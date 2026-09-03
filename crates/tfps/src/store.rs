//! Durable storage in SQLite.
//!
//! **One file. No server, no daemon, no credentials, no port.** That is genuine zero
//! configuration — the 2023 TFPS had a plaintext MySQL password in six places of its
//! generated `.cfg`.
//!
//! And the operator **can open it and see what the system learned**:
//!
//! ```sh
//! sqlite3 /var/lib/tfps/tfps.db "select * from block_log order by ts desc limit 20"
//! ```
//!
//! In a product that is silent by design, being able to audit the state is what separates
//! "I trust this" from "I have no idea whether it works".
//!
//! **This is durable storage, not the hot path** (`SPEC.md` §10). The working set lives in
//! memory; only the boot load and the periodic checkpoint happen here. Querying SQL per
//! INVITE would be a write bottleneck at the wholesale target.
//!
//! The split of state matters: **perimeter** state dies with the process and rebuilds in
//! minutes from traffic — consistent with fail-open by not pinning the eBPF program. The
//! **behavioural** state, 45 to 90 days of it, is what has to survive.

// A detached doc comment is invisible to the compiler and to every test: an
// edit spliced between a doc block and its item once left `open_readonly`
// undocumented while its text described a private helper. `missing_docs` is the
// only instrument that sees that, so it is denied here.
#![deny(missing_docs)]

use std::net::Ipv4Addr;
use std::path::Path;

use rusqlite::{params, Connection};
use tfps_core::country;
use tfps_core::disposition::Disposition;
use tfps_core::engine::{Engine, PeerAnomalyRecord};

use crate::drops::DropRow;

/// Where the database lives unless `--db` says otherwise.
pub const DEFAULT_PATH: &str = "/var/lib/tfps/tfps.db";

/// Schema version. An incompatible change recreates the tables rather than corrupting —
/// losing a baseline is recoverable in days; reading a bitmap with the wrong semantics is
/// not.
const SCHEMA: i64 = 2;

/// A source's learned state, as stored — for the control tool.
pub struct SourceRow {
    /// The source address, as text.
    pub peer: String,
    /// The 256-bit country set, as stored: 32 bytes, one bit per country.
    pub seen: Vec<u8>,
    /// How many distinct countries this source has attempted.
    pub n_countries: u32,
    /// The fast arm of the two-rate novelty estimate.
    pub rate_a: f64,
    /// When this source was last heard, as a Unix timestamp.
    pub last_seen: u32,
}

impl SourceRow {
    /// The countries this source has been seen to call, as labels.
    pub fn countries(&self) -> Vec<&'static str> {
        match blob_to_words(&self.seen) {
            Some(bits) => country::decode_bitmap(bits, [0; 4]),
            None => Vec::new(),
        }
    }
}

/// One audit row.
pub struct BlockRow {
    /// When the decision was reached, as a Unix timestamp.
    pub ts: u32,
    /// The condemned source, as text.
    pub ip: String,
    /// The rule that fired: `scanner`, `injection`, `auth-failed` and friends.
    pub reason: String,
    /// What the rule matched — the signature, pattern or outcome.
    pub detail: String,
}

/// One exported label: a judged source, and what became of the judgement.
///
/// The shape sipnab reads. Field meanings are pinned in the R1 design so a
/// consumer in another repository does not have to guess.
pub struct LabelRow {
    /// When this decision was reached, Unix seconds. Not the address's first
    /// ever sighting — this event's own timestamp.
    pub first_seen: u32,
    /// The judged source.
    pub ip: String,
    /// The rule that fired, or the exemption source.
    pub rule: String,
    /// What the rule matched.
    pub detail: String,
    /// `blocked`, `would-block` or `exempt`, derived from how it was recorded.
    pub verdict: &'static str,
    /// Whether enforcement actually applied. False for every exemption.
    pub enforced: bool,
    /// Absolute lapse time; `Some(0)` is never, `None` is "no block, no TTL".
    pub expires: Option<i64>,
    /// When an operator lifted it, if one did.
    pub unbanned_at: Option<u32>,
}

/// One lifted block — a human overruling the machine.
pub struct UnbanRow {
    /// When the lift happened, as a Unix timestamp.
    pub ts: u32,
    /// The address that was unblocked.
    pub ip: String,
    /// Who lifted it. Only `operator` counts as a human judgement.
    pub actor: String,
}

/// How an operator narrows a source search.
pub struct SourceFilter<'a> {
    /// Exactly this peer, when the operator named one.
    pub peer: Option<&'a str>,
    /// Only sources that have called this country (ISO label, case-insensitive).
    pub country: Option<&'a str>,
    /// Stop after this many rows.
    pub limit: usize,
}

impl Default for SourceFilter<'_> {
    fn default() -> Self {
        Self {
            peer: None,
            country: None,
            limit: 50,
        }
    }
}

impl SourceFilter<'_> {
    fn matches(&self, r: &SourceRow) -> bool {
        if self.peer.is_some_and(|p| r.peer != p) {
            return false;
        }
        if let Some(c) = self.country {
            if !r.countries().iter().any(|x| x.eq_ignore_ascii_case(c)) {
                return false;
            }
        }
        true
    }
}

/// The durable half of TFPS: learned state, the audit log and the feed cursor.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Opens the database read-write, creating and migrating it as needed.
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
        }
        let conn =
            Connection::open(path).map_err(|e| format!("opening {}: {e}", path.display()))?;

        // WAL: concurrent reads while the checkpoint writes, and fewer fsyncs.
        // `synchronous=NORMAL` is WAL's usual companion — losing the last few seconds to a
        // power cut costs seconds of learning, not the database.
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| format!("WAL: {e}"))?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(|e| format!("synchronous: {e}"))?;

        let me = Self { conn };
        me.migrate()?;
        Ok(me)
    }

    fn migrate(&self) -> Result<(), String> {
        let found: i64 = self
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap_or(0);
        if found != 0 && found != SCHEMA {
            // Incompatible schema: start over. See the note on `SCHEMA`.
            // `block_log` is deliberately NOT here. The rationale on `SCHEMA` —
            // losing a baseline is recoverable in days — is true of learned state
            // and false of an audit log: it cannot be relearned from traffic, and
            // under R1 it IS the labeled corpus, which is weeks of collection.
            // Dropping it to add a column to it would destroy the thing the column
            // exists to describe. Its columns are migrated below instead.
            for t in ["peer_anomaly", "known_peer", "pair", "peer_country", "meta"] {
                let _ = self.conn.execute(&format!("DROP TABLE IF EXISTS {t}"), []);
            }
        }
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS meta (
                     k TEXT PRIMARY KEY,
                     v TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS peer_anomaly (
                     peer        TEXT    PRIMARY KEY,
                     seen        BLOB    NOT NULL,   -- 32 bytes: the 256-bit country set
                     n_countries INTEGER NOT NULL,
                     rate_a      REAL    NOT NULL,
                     rate_b      REAL    NOT NULL,
                     last_seen   INTEGER NOT NULL DEFAULT 0
                 );
                 -- Audit: every block records why, in human-readable form.
                 -- `SPEC.md` §12 requires the operator to be able to reconstruct it.
                 CREATE TABLE IF NOT EXISTS block_log (
                     ts     INTEGER NOT NULL,
                     ip     TEXT    NOT NULL,
                     reason TEXT    NOT NULL,
                     detail TEXT    NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS block_log_ts ON block_log (ts);
                 -- The APIBAN feed, kept because it cannot rebuild itself from traffic.
                 -- Perimeter state normally dies with the process and is relearned in
                 -- minutes (`SPEC.md` 10); this is the exception, since the feed is
                 -- consumed through a forward-only cursor. Losing it would mean the
                 -- integration silently protects nothing after a restart.
                 -- Registered peers that authenticated — known-good, never banned even by
                 -- the APIBAN feed re-applied at boot. This is what protects a customer on a
                 -- dynamic IP; it must persist so a restart does not knock them off.
                 CREATE TABLE IF NOT EXISTS known_peer (
                     ip        TEXT    PRIMARY KEY,
                     last_auth INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS apiban_ip (
                     ip TEXT PRIMARY KEY,
                     ts INTEGER NOT NULL
                 );
                 -- Hard negatives: a source that tripped a rule and was trusted anyway.
                 -- The most valuable label there is, because it looked hostile and was not.
                 CREATE TABLE IF NOT EXISTS exempt_log (
                     ts     INTEGER NOT NULL,
                     ip     TEXT    NOT NULL,
                     reason TEXT    NOT NULL,
                     detail TEXT    NOT NULL,
                     rule   TEXT    NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS exempt_log_ts ON exempt_log (ts);
                 -- Gold negatives: a human saying the machine was wrong. SPEC 12 makes
                 -- manual unblocking the precision proxy; until now it was never recorded.
                 CREATE TABLE IF NOT EXISTS unban_log (
                     ts    INTEGER NOT NULL,
                     ip    TEXT    NOT NULL,
                     actor TEXT    NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS unban_log_ip ON unban_log (ip);
                 -- What a blocked source kept sending after its block, per source: the
                 -- XDP program reports its drops on a ring buffer and the daemon flushes
                 -- this at checkpoint. `drops` is the kernel's exact count; `events` is
                 -- the sample it reported. Kept off the drop list like block_log: it is
                 -- evidence about blocks, and the kernel discards the traffic it would
                 -- be relearned from.
                 CREATE TABLE IF NOT EXISTS drop_log (
                     ip         TEXT    PRIMARY KEY,
                     first_ts   INTEGER NOT NULL,
                     last_ts    INTEGER NOT NULL,
                     drops      INTEGER NOT NULL,
                     events     INTEGER NOT NULL,
                     last_port  INTEGER NOT NULL,
                     last_len   INTEGER NOT NULL,
                     last_proto INTEGER NOT NULL,
                     last_line  TEXT    NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS drop_log_last ON drop_log (last_ts);",
            )
            .map_err(|e| format!("creating schema: {e}"))?;
        // Columns added to a table that survives the version change. SQLite has no
        // ADD COLUMN IF NOT EXISTS, and a second open would fail on an ALTER that
        // already ran, so the presence check is the idempotence.
        self.add_column_if_missing("block_log", "enforced", "INTEGER NOT NULL DEFAULT 1")?;
        self.add_column_if_missing("block_log", "expires", "INTEGER")?;

        self.conn
            .pragma_update(None, "user_version", SCHEMA)
            .map_err(|e| format!("user_version: {e}"))
    }

    /// The instant learning began, written on the first run.
    ///
    /// **This is what makes learning mode mean anything.** Without persisting it, every
    /// restart would reset the 30 days and the countdown would promise something a
    /// `systemctl restart` erases.
    pub fn learning_started(&self, default_now: u32) -> u32 {
        if let Ok(v) =
            self.conn
                .query_row("SELECT v FROM meta WHERE k = 'learning_started'", [], |r| {
                    r.get::<_, String>(0)
                })
        {
            if let Ok(t) = v.parse() {
                return t;
            }
        }
        if let Err(e) = self.conn.execute(
            "INSERT OR REPLACE INTO meta (k, v) VALUES ('learning_started', ?1)",
            params![default_now.to_string()],
        ) {
            // Not fatal: learning proceeds from `default_now` either way. Not
            // silent either, because the next boot would restart the clock and
            // the operator would see the learning window reset for no reason.
            eprintln!("WARNING: could not persist the learning start: {e}");
        }
        default_now
    }

    /// Records addresses from the feed, so they can be re-applied after a restart.
    pub fn apiban_add(&mut self, ips: &[Ipv4Addr], ts: u32) -> Result<(), String> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| format!("transaction: {e}"))?;
        {
            let mut ins = tx
                .prepare_cached("INSERT OR REPLACE INTO apiban_ip (ip, ts) VALUES (?1, ?2)")
                .map_err(|e| format!("preparing apiban_ip: {e}"))?;
            for ip in ips {
                ins.execute(params![ip.to_string(), ts])
                    .map_err(|e| format!("writing apiban_ip: {e}"))?;
            }
        }
        tx.commit().map_err(|e| format!("commit: {e}"))
    }

    /// The feed addresses still worth applying. `since` bounds how stale an entry may be —
    /// APIBAN is a rolling list of hotspots, not a permanent verdict on an address.
    pub fn apiban_since(&self, since: u32) -> Result<Vec<Ipv4Addr>, String> {
        let mut st = self
            .conn
            .prepare("SELECT ip FROM apiban_ip WHERE ts >= ?1")
            .map_err(|e| format!("reading apiban_ip: {e}"))?;
        let rows = st
            .query_map(params![since], |r| r.get::<_, String>(0))
            .map_err(|e| format!("iterating apiban_ip: {e}"))?;
        Ok(rows.flatten().filter_map(|s| s.parse().ok()).collect())
    }

    /// Persists the known-good registered peers.
    pub fn save_known_peers(
        &mut self,
        peers: impl Iterator<Item = (std::net::Ipv4Addr, u32)>,
    ) -> Result<(), String> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| format!("transaction: {e}"))?;
        {
            let mut ins = tx
                .prepare_cached("INSERT OR REPLACE INTO known_peer (ip, last_auth) VALUES (?1, ?2)")
                .map_err(|e| format!("preparing known_peer: {e}"))?;
            for (ip, ts) in peers {
                ins.execute(params![ip.to_string(), ts])
                    .map_err(|e| format!("writing known_peer: {e}"))?;
            }
        }
        tx.commit().map_err(|e| format!("commit: {e}"))
    }

    /// Loads the known-good peers newer than `since`, as (ip, last_auth).
    pub fn known_peers_since(&self, since: u32) -> Result<Vec<(std::net::Ipv4Addr, u32)>, String> {
        let mut st = self
            .conn
            .prepare("SELECT ip, last_auth FROM known_peer WHERE last_auth >= ?1")
            .map_err(|e| format!("reading known_peer: {e}"))?;
        let rows = st
            .query_map(params![since], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, u32>(1)?))
            })
            .map_err(|e| format!("iterating known_peer: {e}"))?;
        Ok(rows
            .flatten()
            .filter_map(|(ip, ts)| ip.parse().ok().map(|ip| (ip, ts)))
            .collect())
    }

    /// Drops known peers that have not authenticated within the retention window.
    pub fn known_peers_prune(&self, older_than: u32) -> usize {
        self.conn
            .execute(
                "DELETE FROM known_peer WHERE last_auth < ?1",
                params![older_than],
            )
            .unwrap_or(0)
    }

    /// Every address currently on the APIBAN feed, for attributing a block to it.
    pub fn apiban_all(&self) -> Result<std::collections::HashSet<String>, String> {
        let mut st = self
            .conn
            .prepare("SELECT ip FROM apiban_ip")
            .map_err(|e| format!("reading apiban_ip: {e}"))?;
        let rows = st
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|e| format!("iterating apiban_ip: {e}"))?;
        Ok(rows.flatten().collect())
    }

    /// Drops feed entries older than the retention window.
    pub fn apiban_prune(&self, older_than: u32) -> usize {
        self.conn
            .execute("DELETE FROM apiban_ip WHERE ts < ?1", params![older_than])
            .unwrap_or(0)
    }

    /// Reads a small named value. Used for anything that has to survive a restart but is
    /// not learning state — the APIBAN resume point, for instance.
    pub fn meta_get(&self, key: &str) -> Option<String> {
        self.conn
            .query_row("SELECT v FROM meta WHERE k = ?1", params![key], |r| {
                r.get(0)
            })
            .ok()
    }

    /// Writes one. Failure is not fatal: the worst case is refetching a feed from the
    /// start, which costs bandwidth, not correctness.
    pub fn meta_set(&self, key: &str, value: &str) {
        if let Err(e) = self.conn.execute(
            "INSERT OR REPLACE INTO meta (k, v) VALUES (?1, ?2)",
            params![key, value],
        ) {
            // `meta` carries the APIBAN cursor, and the schema comment says what
            // losing it costs: the integration "silently protects nothing after
            // a restart". A dropped write here has to be audible.
            eprintln!("WARNING: could not persist meta {key}: {e}");
        }
    }

    /// Records what the perimeter decided, wherever that decision belongs.
    ///
    /// Takes the [`Disposition`] rather than loose fields so a caller cannot
    /// record a verdict and a reason that disagree: they were decided together
    /// and they are written together. The verdict *name* is deliberately not
    /// stored — it is a function of `enforced`, and a column would be the same
    /// fact written twice, free to drift.
    ///
    /// Returns an error rather than swallowing one. A failed audit write must
    /// not stop the block it describes, and the caller enforces that by not
    /// treating this as fatal — but silence here would lose the corpus a row at
    /// a time, which is exactly the failure nobody notices.
    pub fn log_decision(
        &self,
        ts: u32,
        ip: Ipv4Addr,
        d: &Disposition<'_>,
        ttl: u64,
    ) -> Result<(), String> {
        match d {
            Disposition::Ignore => Ok(()),
            Disposition::Block { kind, detail } => {
                // 0 is "never" throughout this codebase, including the APIBAN
                // path. Storing ts+0 would claim the block lapsed as it was made.
                let expires: i64 = if ttl == 0 {
                    0
                } else {
                    // Saturating: a TTL large enough to overflow is a
                    // configuration error, and clamping is better than wrapping
                    // to a lapse time in the past.
                    i64::from(ts).saturating_add(i64::try_from(ttl).unwrap_or(i64::MAX))
                };
                self.conn
                    .execute(
                        "INSERT INTO block_log (ts, ip, reason, detail, enforced, expires)
                         VALUES (?1, ?2, ?3, ?4, 1, ?5)",
                        params![ts, ip.to_string(), kind, detail, expires],
                    )
                    .map(|_| ())
                    .map_err(|e| format!("recording a block for {ip}: {e}"))
            }
            Disposition::WouldBlock { kind, detail } => self
                .conn
                .execute(
                    // No expiry: nothing was blocked, so there is no TTL to record.
                    // A number here would be a lapse time for a block that never was.
                    "INSERT INTO block_log (ts, ip, reason, detail, enforced, expires)
                     VALUES (?1, ?2, ?3, ?4, 0, NULL)",
                    params![ts, ip.to_string(), kind, detail],
                )
                .map(|_| ())
                .map_err(|e| format!("recording a would-block for {ip}: {e}")),
            Disposition::ExemptIgnoreIp { kind, detail, rule } => {
                self.log_exempt(ts, ip, kind, detail, rule)
            }
            Disposition::ExemptKnownPeer { kind, detail } => {
                // Named rather than left blank: a learned registration and a
                // curated list are different strengths of evidence, and the
                // corpus has to be able to tell them apart.
                self.log_exempt(ts, ip, kind, detail, "registered-peer")
            }
        }
    }

    fn log_exempt(
        &self,
        ts: u32,
        ip: Ipv4Addr,
        reason: &str,
        detail: &str,
        rule: &str,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO exempt_log (ts, ip, reason, detail, rule) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![ts, ip.to_string(), reason, detail, rule],
            )
            .map(|_| ())
            .map_err(|e| format!("recording an exemption for {ip}: {e}"))
    }

    /// Records a lifted block — the gold negative, a human saying this was wrong.
    ///
    /// `actor` exists so that a TTL lapsing can never be counted as an operator
    /// judgement. Only `operator` rows are negatives.
    pub fn log_unban(&self, ts: u32, ip: Ipv4Addr, actor: &str) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO unban_log (ts, ip, actor) VALUES (?1, ?2, ?3)",
                params![ts, ip.to_string(), actor],
            )
            .map(|_| ())
            .map_err(|e| format!("recording an unban for {ip}: {e}"))
    }

    /// The lifted blocks, newest first.
    pub fn unbans(&self, limit: usize) -> Result<Vec<UnbanRow>, String> {
        let mut st = self
            .conn
            .prepare("SELECT ts, ip, actor FROM unban_log ORDER BY ts DESC LIMIT ?1")
            .map_err(|e| format!("reading unban_log: {e}"))?;
        let rows = st
            .query_map(params![i64::try_from(limit).unwrap_or(i64::MAX)], |r| {
                Ok(UnbanRow {
                    ts: r.get(0)?,
                    ip: r.get(1)?,
                    actor: r.get(2)?,
                })
            })
            .map_err(|e| format!("reading unban_log: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("iterating unban_log: {e}"))
    }

    /// Every label, newest first — the R1 export.
    ///
    /// Three tables, one stream. The verdict is derived from `enforced` rather
    /// than stored: a column would be the same fact written twice and free to
    /// disagree with the row it describes.
    ///
    /// The unban join is deliberately by address and not by row: `unban_log`
    /// records that a source was lifted, not which of its blocks was meant, and
    /// inventing a pairing would be a claim the data does not make.
    pub fn labels(&self, limit: usize) -> Result<Vec<LabelRow>, String> {
        let cap = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut out = Vec::new();

        let mut st = self
            .conn
            .prepare(
                "SELECT b.ts, b.ip, b.reason, b.detail, b.enforced, b.expires,
                        (SELECT MAX(u.ts) FROM unban_log u
                          WHERE u.ip = b.ip AND u.actor = 'operator' AND u.ts >= b.ts)
                 FROM block_log b ORDER BY b.ts DESC LIMIT ?1",
            )
            .map_err(|e| format!("reading labels: {e}"))?;
        let rows = st
            .query_map(params![cap], |r| {
                let enforced: i64 = r.get(4)?;
                Ok(LabelRow {
                    first_seen: r.get(0)?,
                    ip: r.get(1)?,
                    rule: r.get(2)?,
                    detail: r.get(3)?,
                    verdict: if enforced != 0 {
                        "blocked"
                    } else {
                        "would-block"
                    },
                    enforced: enforced != 0,
                    expires: r.get(5)?,
                    unbanned_at: r.get(6)?,
                })
            })
            .map_err(|e| format!("reading labels: {e}"))?;
        for r in rows {
            out.push(r.map_err(|e| format!("iterating labels: {e}"))?);
        }

        let mut st = self
            .conn
            .prepare(
                "SELECT ts, ip, reason, detail, rule FROM exempt_log ORDER BY ts DESC LIMIT ?1",
            )
            .map_err(|e| format!("reading exemptions: {e}"))?;
        let rows = st
            .query_map(params![cap], |r| {
                Ok(LabelRow {
                    first_seen: r.get(0)?,
                    ip: r.get(1)?,
                    // The exemption SOURCE is the rule for an exempt row: which
                    // list spared it is the evidence, and the signature that
                    // fired is carried in `detail` alongside what it matched.
                    rule: r.get(4)?,
                    detail: format!("{}: {}", r.get::<_, String>(2)?, r.get::<_, String>(3)?),
                    verdict: "exempt",
                    enforced: false,
                    expires: None,
                    unbanned_at: None,
                })
            })
            .map_err(|e| format!("reading exemptions: {e}"))?;
        for r in rows {
            out.push(r.map_err(|e| format!("iterating exemptions: {e}"))?);
        }

        // Newest first, matching every other reader in this tool.
        out.sort_by_key(|l| std::cmp::Reverse(l.first_seen));
        out.truncate(limit);
        Ok(out)
    }

    /// Deletes old audit rows. Without this the file grows forever — which is what
    /// produced the 477 MB `/var/log/opensips.log` that `fail2ban` scans line by line.
    pub fn prune_log(&self, older_than: u32) -> usize {
        self.conn
            .execute("DELETE FROM block_log WHERE ts < ?1", params![older_than])
            .unwrap_or(0)
    }

    /// Adds what the daemon saw dropped since its last checkpoint, per source.
    ///
    /// The rows are deltas and the table adds them, so a source seen across two
    /// checkpoints — or two daemon lifetimes, since the kernel's count restarts with the
    /// process — counts every packet once. The first sighting is kept; everything
    /// "last" is replaced.
    ///
    /// Returns an error rather than swallowing one: a lost row here is a blocked
    /// source whose behaviour reads as "nothing happened", which is the blindness the
    /// ring buffer exists to remove.
    pub fn record_drops(&self, rows: &[DropRow]) -> Result<(), String> {
        let clamp = |n: u64| i64::try_from(n).unwrap_or(i64::MAX);
        for r in rows {
            self.conn
                .execute(
                    "INSERT INTO drop_log
                         (ip, first_ts, last_ts, drops, events, last_port, last_len,
                          last_proto, last_line)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                     ON CONFLICT(ip) DO UPDATE SET
                         drops      = drops + excluded.drops,
                         events     = events + excluded.events,
                         last_ts    = excluded.last_ts,
                         last_port  = excluded.last_port,
                         last_len   = excluded.last_len,
                         last_proto = excluded.last_proto,
                         last_line  = excluded.last_line",
                    params![
                        r.ip,
                        r.first_ts,
                        r.last_ts,
                        clamp(r.drops),
                        clamp(r.events),
                        r.last_port,
                        r.last_len,
                        r.last_proto,
                        r.last_line
                    ],
                )
                .map(|_| ())
                .map_err(|e| format!("recording drops from {}: {e}", r.ip))?;
        }
        Ok(())
    }

    /// The dropped sources, most dropped first — what `tfps_ctl dropped` shows.
    pub fn dropped(&self, limit: usize, ip: Option<&str>) -> Result<Vec<DropRow>, String> {
        let (sql, args): (&str, Vec<String>) = match ip {
            Some(v) => (
                "SELECT ip, first_ts, last_ts, drops, events, last_port, last_len,
                        last_proto, last_line
                 FROM drop_log WHERE ip = ?1 ORDER BY drops DESC, ip LIMIT ?2",
                vec![v.to_string(), limit.to_string()],
            ),
            None => (
                "SELECT ip, first_ts, last_ts, drops, events, last_port, last_len,
                        last_proto, last_line
                 FROM drop_log ORDER BY drops DESC, ip LIMIT ?1",
                vec![limit.to_string()],
            ),
        };
        let mut st = self
            .conn
            .prepare(sql)
            .map_err(|e| format!("reading drop_log: {e}"))?;
        let rows = st
            .query_map(rusqlite::params_from_iter(args), |r| {
                let drops: i64 = r.get(3)?;
                let events: i64 = r.get(4)?;
                Ok(DropRow {
                    ip: r.get(0)?,
                    first_ts: r.get(1)?,
                    last_ts: r.get(2)?,
                    drops: u64::try_from(drops).unwrap_or(0),
                    events: u64::try_from(events).unwrap_or(0),
                    last_port: r.get(5)?,
                    last_len: r.get(6)?,
                    last_proto: r.get(7)?,
                    last_line: r.get(8)?,
                })
            })
            .map_err(|e| format!("iterating drop_log: {e}"))?;
        Ok(rows.flatten().collect())
    }

    /// Forgets sources not seen dropping since `older_than`. Same window as the block
    /// log, since the two are read together.
    pub fn drops_prune(&self, older_than: u32) -> usize {
        self.conn
            .execute(
                "DELETE FROM drop_log WHERE last_ts < ?1",
                params![older_than],
            )
            .unwrap_or(0)
    }

    /// Add a column unless it is already there.
    ///
    /// The default matters and is not arbitrary: every row written before
    /// `enforced` existed came from the enforcing arm, because that was the only
    /// arm that wrote anything. Defaulting them to 1 records what actually
    /// happened rather than guessing.
    fn add_column_if_missing(&self, table: &str, column: &str, decl: &str) -> Result<(), String> {
        let present: i64 = self
            .conn
            .query_row(
                "SELECT count(*) FROM pragma_table_info(?1) WHERE name = ?2",
                params![table, column],
                |r| r.get(0),
            )
            .map_err(|e| format!("inspecting {table}: {e}"))?;
        if present > 0 {
            return Ok(());
        }
        self.conn
            .execute(
                &format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"),
                [],
            )
            .map(|_| ())
            .map_err(|e| format!("adding {table}.{column}: {e}"))
    }

    /// Opens the database **read-only**, for the control tool.
    ///
    /// Read-only on purpose: `tfps_ctl` inspecting state must not be able to corrupt what
    /// the daemon is writing, and WAL lets it read while a checkpoint is in flight.
    pub fn open_readonly(path: &Path) -> Result<Self, String> {
        use rusqlite::OpenFlags;
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(|e| format!("opening {} read-only: {e}", path.display()))?;
        Ok(Self { conn })
    }

    /// Learned pairs, filtered the way an operator searches: by peer, by A-number
    /// substring, or by a country the pair has called.
    pub fn find_sources(&self, f: &SourceFilter<'_>) -> Result<Vec<SourceRow>, String> {
        let mut st = self
            .conn
            .prepare(
                "SELECT peer, seen, n_countries, rate_a, last_seen FROM peer_anomaly
                 ORDER BY last_seen DESC",
            )
            .map_err(|e| format!("reading peer_anomaly: {e}"))?;
        let rows = st
            .query_map([], |r| {
                Ok(SourceRow {
                    peer: r.get(0)?,
                    seen: r.get::<_, Vec<u8>>(1)?,
                    n_countries: r.get(2)?,
                    rate_a: r.get(3)?,
                    last_seen: r.get(4)?,
                })
            })
            .map_err(|e| format!("iterating peer_anomaly: {e}"))?;
        Ok(rows
            .flatten()
            .filter(|r| f.matches(r))
            .take(f.limit)
            .collect())
    }

    /// Sources by distinct-country breadth, and when last heard from.
    pub fn peers(&self) -> Result<Vec<(String, u32, u32)>, String> {
        let mut st = self
            .conn
            .prepare(
                "SELECT peer, n_countries, last_seen FROM peer_anomaly
                 ORDER BY n_countries DESC",
            )
            .map_err(|e| format!("reading peers: {e}"))?;
        let rows = st
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .map_err(|e| format!("iterating peers: {e}"))?;
        Ok(rows.flatten().collect())
    }

    /// The countries a source has been seen to call. The new model tracks membership, not
    /// per-country counts, so this lists the set rather than frequencies.
    pub fn peer_countries(&self, peer: &str) -> Result<Vec<&'static str>, String> {
        let row = self
            .conn
            .query_row(
                "SELECT seen FROM peer_anomaly WHERE peer = ?1",
                params![peer],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .map_err(|e| format!("reading peer_anomaly: {e}"))?;
        Ok(match blob_to_words(&row) {
            Some(bits) => country::decode_bitmap(bits, [0; 4]),
            None => Vec::new(),
        })
    }

    /// The block audit log, newest first.
    pub fn blocks(&self, limit: usize, ip: Option<&str>) -> Result<Vec<BlockRow>, String> {
        let (sql, args): (&str, Vec<String>) = match ip {
            Some(v) => (
                "SELECT ts, ip, reason, detail FROM block_log WHERE ip = ?1
                 ORDER BY ts DESC LIMIT ?2",
                vec![v.to_string(), limit.to_string()],
            ),
            None => (
                "SELECT ts, ip, reason, detail FROM block_log ORDER BY ts DESC LIMIT ?1",
                vec![limit.to_string()],
            ),
        };
        let mut st = self
            .conn
            .prepare(sql)
            .map_err(|e| format!("reading block_log: {e}"))?;
        let rows = st
            .query_map(rusqlite::params_from_iter(args), |r| {
                Ok(BlockRow {
                    ts: r.get(0)?,
                    ip: r.get(1)?,
                    reason: r.get(2)?,
                    detail: r.get(3)?,
                })
            })
            .map_err(|e| format!("iterating block_log: {e}"))?;
        Ok(rows.flatten().collect())
    }

    /// How many blocks happened since `ts`, grouped by reason. The shape of what the
    /// perimeter is actually catching, which one line of the periodic report cannot show.
    pub fn blocks_by_reason(&self, since: u32) -> Result<Vec<(String, u32)>, String> {
        let mut st = self
            .conn
            .prepare(
                "SELECT reason, COUNT(*) FROM block_log WHERE ts >= ?1
                 GROUP BY reason ORDER BY COUNT(*) DESC",
            )
            .map_err(|e| format!("reading block_log: {e}"))?;
        let rows = st
            .query_map(params![since], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(|e| format!("iterating block_log: {e}"))?;
        Ok(rows.flatten().collect())
    }

    /// Breadth of the baseline: the widest single-source country count, and the total
    /// across sources. (The per-country call frequencies of the old model are gone.)
    pub fn country_spread(&self) -> Result<(u32, u32), String> {
        self.conn
            .query_row(
                "SELECT COALESCE(MAX(n_countries), 0), COALESCE(SUM(n_countries), 0) \
                 FROM peer_anomaly",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|e| format!("reading peer_anomaly: {e}"))
    }

    /// Totals for the status line: pairs, peers, and the newest thing the file knows about
    /// — which is how stale the snapshot is.
    pub fn totals(&self) -> Result<(u32, u32, u32), String> {
        self.conn
            .query_row(
                "SELECT COUNT(*), COUNT(*), COALESCE(MAX(last_seen), 0) FROM peer_anomaly",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(|e| format!("reading totals: {e}"))
    }

    /// Forgets learned state for a peer, or for one pair of it.
    ///
    /// **Only meaningful with the daemon stopped.** A running process holds the working set
    /// in memory and would write it straight back at the next checkpoint, so the caller has
    /// to establish that before offering this.
    pub fn forget(&self, peer: &str, _a_number: Option<&str>) -> Result<usize, String> {
        self.conn
            .execute("DELETE FROM peer_anomaly WHERE peer = ?1", params![peer])
            .map_err(|e| format!("deleting: {e}"))
    }

    /// Writes the learning state. Called at checkpoint time, never per packet.
    pub fn checkpoint(&mut self, engine: &Engine) -> Result<(usize, usize), String> {
        let now = self.now_stamp();
        let tx = self
            .conn
            .transaction()
            .map_err(|e| format!("transaction: {e}"))?;
        let mut sources = 0usize;
        {
            let mut ins = tx
                .prepare_cached(
                    "INSERT OR REPLACE INTO peer_anomaly
                     (peer, seen, n_countries, rate_a, rate_b, last_seen)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )
                .map_err(|e| format!("preparing peer_anomaly: {e}"))?;
            for r in engine.export_anomaly() {
                ins.execute(params![
                    r.peer.to_string(),
                    words_to_blob(&r.seen_countries),
                    r.n_countries,
                    r.rate_a,
                    r.rate_b,
                    now
                ])
                .map_err(|e| format!("writing peer_anomaly: {e}"))?;
                sources += 1;
            }
        }
        tx.commit().map_err(|e| format!("commit: {e}"))?;
        Ok((sources, 0))
    }

    /// A wall-clock stamp for `last_seen`. The core is clockless, so reading the clock here
    /// at checkpoint time (never on the packet path) is harmless.
    fn now_stamp(&self) -> u32 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0)
    }

    /// Loads the state at boot. An error here is **not fatal** — the system restarts
    /// learning, which is bad but recoverable; refusing to start would be worse.
    pub fn load_into(&self, engine: &mut Engine) -> Result<(usize, usize), String> {
        let mut sources = 0usize;
        let mut st = self
            .conn
            .prepare("SELECT peer, seen, n_countries, rate_a, rate_b FROM peer_anomaly")
            .map_err(|e| format!("reading peer_anomaly: {e}"))?;
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, u32>(2)?,
                    r.get::<_, f64>(3)?,
                    r.get::<_, f64>(4)?,
                ))
            })
            .map_err(|e| format!("iterating peer_anomaly: {e}"))?;
        for row in rows.flatten() {
            let (peer, seen, n_countries, rate_a, rate_b) = row;
            let (Ok(peer), Some(seen_countries)) = (peer.parse::<Ipv4Addr>(), blob_to_words(&seen))
            else {
                continue; // corrupt row: skip one, do not lose the whole database
            };
            engine.import_anomaly(PeerAnomalyRecord {
                peer,
                seen_countries,
                n_countries,
                rate_a,
                rate_b,
            });
            sources += 1;
        }
        Ok((sources, 0))
    }
}

/// The bitmap as 32 little-endian bytes. An explicit format so the file is readable by
/// other tools and does not depend on the byte order of the machine that wrote it.
fn words_to_blob(w: &[u64; 4]) -> Vec<u8> {
    w.iter().flat_map(|x| x.to_le_bytes()).collect()
}

fn blob_to_words(b: &[u8]) -> Option<[u64; 4]> {
    if b.len() != 32 {
        return None;
    }
    let mut out = [0u64; 4];
    for (i, chunk) in b.as_chunks::<8>().0.iter().enumerate() {
        out[i] = u64::from_le_bytes(*chunk);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tfps_core::dialplan::DialPlan;
    use tfps_core::engine::Mode;
    use tfps_core::novelty::Timestamp;

    fn tmp() -> std::path::PathBuf {
        let n: u32 = std::process::id();
        std::env::temp_dir().join(format!(
            "tfps-test-{n}-{:?}.db",
            std::thread::current().id()
        ))
    }

    fn invite(from: &str, dialed: &str) -> Vec<u8> {
        format!("INVITE sip:{dialed}@pbx SIP/2.0\r\nFrom: <sip:{from}@pbx>;tag=t\r\n\r\n")
            .into_bytes()
    }

    // ---- R1: the audit log is the corpus, and must survive a schema change ----

    /// Build a database as the previous schema version left it, then reopen it
    /// with the current code. `user_version` is forced rather than faked so the
    /// migration takes the same path a real upgrade takes.
    fn v1_database_with_a_block(path: &std::path::Path) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS block_log (
                 ts INTEGER NOT NULL, ip TEXT NOT NULL,
                 reason TEXT NOT NULL, detail TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS peer_anomaly (
                 peer TEXT PRIMARY KEY, seen BLOB NOT NULL, n_countries INTEGER NOT NULL,
                 rate_a REAL NOT NULL, rate_b REAL NOT NULL,
                 last_seen INTEGER NOT NULL DEFAULT 0);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO block_log (ts, ip, reason, detail) VALUES (10, '198.51.100.7', 'scanner', 'sipvicious')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO peer_anomaly VALUES ('198.51.100.9', X'00', 1, 0.0, 0.0, 5)",
            [],
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 1i64).unwrap();
    }

    fn fresh(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "tfps-r1-{}-{}-{name}",
            std::process::id(),
            std::thread::current()
                .name()
                .unwrap_or("t")
                .replace("::", "-")
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("tfps.db")
    }

    // THE SCENARIO. Learned state is relearned in minutes, which is why the
    // migration drops it. An audit log cannot be relearned at all, and under R1
    // it is the labeled corpus -- weeks of collection. Dropping it on a version
    // bump would destroy the product to add a column to it.
    #[test]
    fn the_audit_log_survives_a_schema_upgrade() {
        let path = fresh("survive");
        v1_database_with_a_block(&path);
        let s = Store::open(&path).unwrap();
        let n: i64 = s
            .conn
            .query_row("SELECT count(*) FROM block_log", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            n, 1,
            "the audit log was dropped by the upgrade — that is the corpus"
        );
        let (ip, reason): (String, String) = s
            .conn
            .query_row("SELECT ip, reason FROM block_log", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!((ip.as_str(), reason.as_str()), ("198.51.100.7", "scanner"));
    }

    // Rows written before the column existed were all written by the enforcing
    // arm, because it was the only arm that wrote. Defaulting them to enforced
    // is therefore true, not merely convenient.
    #[test]
    fn rows_predating_the_column_read_as_enforced() {
        let path = fresh("default");
        v1_database_with_a_block(&path);
        let s = Store::open(&path).unwrap();
        let enforced: i64 = s
            .conn
            .query_row("SELECT enforced FROM block_log", [], |r| r.get(0))
            .unwrap();
        assert_eq!(enforced, 1, "a pre-upgrade row must read as enforced");
    }

    // NEGATIVE CONTROL. Preserving the audit log must not accidentally preserve
    // the learned bitmaps, whose semantics are exactly what a version change
    // means has changed. Reading those with the wrong meaning is the corruption
    // the drop exists to prevent.
    #[test]
    fn learned_state_is_still_discarded_on_a_schema_change() {
        let path = fresh("drop-learned");
        v1_database_with_a_block(&path);
        let s = Store::open(&path).unwrap();
        let n: i64 = s
            .conn
            .query_row("SELECT count(*) FROM peer_anomaly", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            n, 0,
            "learned state must still be recreated, not carried across"
        );
    }

    #[test]
    fn the_label_tables_exist_after_migration() {
        let path = fresh("tables");
        let s = Store::open(&path).unwrap();
        for table in ["exempt_log", "unban_log", "block_log"] {
            let n: i64 = s
                .conn
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    params![table],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n, 1, "{table} must exist");
        }
    }

    // Opening twice must not fail. Adding a column is not idempotent in SQLite,
    // so the second open is where a naive ALTER blows up.
    #[test]
    fn opening_an_already_migrated_database_is_a_no_op() {
        let path = fresh("idempotent");
        v1_database_with_a_block(&path);
        Store::open(&path).unwrap();
        let s = Store::open(&path).expect("a second open must succeed");
        let n: i64 = s
            .conn
            .query_row("SELECT count(*) FROM block_log", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1, "the row must survive the second open too");
    }

    // ---- Owed: three failures from this session, paid in related tests ----

    // Debt 6 (a doc comment detached from its item: a claim and its code
    // drifting apart). The migration carries a comment asserting block_log is
    // deliberately absent from the drop list. A comment cannot enforce itself,
    // and this is the pair that matters -- so both halves are read.
    /// The drop list, read from the migration and nowhere else.
    ///
    /// Anchored on `fn migrate` on purpose. The naive form searched the whole
    /// file for the first `for t in [`, and that search string itself appears
    /// in this test file -- a pattern that matches the matcher, correct only
    /// because `migrate` happens to sit above the tests. Move the tests, or add
    /// another such loop earlier, and the gate reads the wrong array and still
    /// passes. Same shape as a `pkill -f` pattern broad enough to match the
    /// shell running it.
    fn drop_list(src: &str) -> &str {
        let body = src
            .split_once("fn migrate")
            .expect("the migration must still be called `migrate`")
            .1;
        body.split_once("for t in [")
            .expect("the drop list must still be a literal array inside `migrate`")
            .1
            .split_once(']')
            .expect("the drop list must be closed")
            .0
    }

    #[test]
    fn the_migration_does_not_drop_the_audit_log() {
        let list = drop_list(include_str!("store.rs"));
        assert!(
            !list.contains("block_log"),
            "block_log is back on the drop list; the corpus would not survive a version bump"
        );
    }

    // Debt 6, the other half. Checking only that block_log is absent would pass
    // over an empty list -- which would preserve the learned bitmaps a version
    // change means have changed meaning. A fact written twice needs both copies
    // read.
    #[test]
    fn the_migration_still_drops_the_learned_state() {
        let list = drop_list(include_str!("store.rs"));
        for table in ["peer_anomaly", "known_peer", "meta"] {
            assert!(
                list.contains(table),
                "{table} must still be recreated on a schema change"
            );
        }
    }

    // ---- R2: what a blocked source kept doing outlives the process ----
    //
    // The ring buffer cannot be driven from here (CAP_BPF, an attached program, a
    // packet from a blocked source). What the daemon does with the events once it
    // has them CAN be: it flushes per-source deltas at checkpoint, and `tfps_ctl
    // dropped` reads the rows back in another process.

    fn drop_row(ip: &str, ts: u32, drops: u64, events: u64, line: &str) -> DropRow {
        DropRow {
            ip: ip.into(),
            first_ts: ts,
            last_ts: ts,
            drops,
            events,
            last_port: 5060,
            last_len: 300,
            last_proto: 17,
            last_line: line.into(),
        }
    }

    #[test]
    fn drops_accumulate_across_checkpoints() {
        let s = Store::open(&fresh("drops-accumulate")).unwrap();
        s.record_drops(&[drop_row("198.51.100.7", 100, 7, 1, "OPTIONS sip:a SIP/2.0")])
            .unwrap();
        s.record_drops(&[drop_row(
            "198.51.100.7",
            160,
            5,
            1,
            "REGISTER sip:b SIP/2.0",
        )])
        .unwrap();
        let rows = s.dropped(10, None).unwrap();
        assert_eq!(rows.len(), 1, "one row per source");
        let r = &rows[0];
        assert_eq!(
            (r.drops, r.events),
            (12, 2),
            "checkpoints write deltas; the row is their sum"
        );
        assert_eq!(r.first_ts, 100, "the first sighting is kept");
        assert_eq!(r.last_ts, 160, "the latest sighting wins");
        assert_eq!(r.last_line, "REGISTER sip:b SIP/2.0");
        assert_eq!((r.last_port, r.last_len, r.last_proto), (5060, 300, 17));
    }

    #[test]
    fn the_drop_log_survives_a_reopen() {
        let path = fresh("drops-reopen");
        {
            let s = Store::open(&path).unwrap();
            s.record_drops(&[drop_row("198.51.100.8", 1, 4, 1, "a")])
                .unwrap();
        }
        let s = Store::open(&path).unwrap();
        let rows = s.dropped(10, None).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].drops, 4);
    }

    #[test]
    fn dropped_sources_read_back_most_active_first() {
        let s = Store::open(&fresh("drops-order")).unwrap();
        s.record_drops(&[
            drop_row("198.51.100.1", 1, 3, 1, "a"),
            drop_row("198.51.100.2", 1, 10, 1, "b"),
            drop_row("198.51.100.3", 1, 5, 1, "c"),
        ])
        .unwrap();
        let ips: Vec<String> = s
            .dropped(10, None)
            .unwrap()
            .into_iter()
            .map(|r| r.ip)
            .collect();
        assert_eq!(ips, ["198.51.100.2", "198.51.100.3", "198.51.100.1"]);
        assert_eq!(s.dropped(1, None).unwrap().len(), 1, "the limit applies");
    }

    #[test]
    fn dropped_can_be_narrowed_to_one_source() {
        let s = Store::open(&fresh("drops-one")).unwrap();
        s.record_drops(&[
            drop_row("198.51.100.1", 1, 3, 1, "a"),
            drop_row("198.51.100.2", 1, 10, 1, "b"),
        ])
        .unwrap();
        let rows = s.dropped(10, Some("198.51.100.1")).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].ip, "198.51.100.1");
    }

    #[test]
    fn an_empty_drop_log_reads_as_empty_and_not_as_an_error() {
        let s = Store::open(&fresh("drops-empty")).unwrap();
        assert!(s.dropped(10, None).unwrap().is_empty());
    }

    #[test]
    fn a_failed_drop_write_is_reported_rather_than_swallowed() {
        let s = Store::open(&fresh("drops-broken")).unwrap();
        s.conn.execute_batch("DROP TABLE drop_log;").unwrap();
        assert!(
            s.record_drops(&[drop_row("198.51.100.1", 1, 1, 1, "a")])
                .is_err(),
            "a lost row is a blocked source whose behaviour reads as nothing happened"
        );
        assert!(
            s.dropped(10, None).is_err(),
            "a broken read is an error, not an empty result"
        );
    }

    #[test]
    fn drop_rows_prune_by_last_sighting() {
        let s = Store::open(&fresh("drops-prune")).unwrap();
        s.record_drops(&[
            drop_row("198.51.100.1", 100, 1, 1, "a"),
            drop_row("198.51.100.2", 500, 1, 1, "b"),
        ])
        .unwrap();
        assert_eq!(s.drops_prune(200), 1);
        let ips: Vec<String> = s
            .dropped(10, None)
            .unwrap()
            .into_iter()
            .map(|r| r.ip)
            .collect();
        assert_eq!(ips, ["198.51.100.2"]);
    }

    // The same rule as block_log: this is evidence about blocks, not learned state,
    // and it cannot be relearned from traffic the kernel discards.
    #[test]
    fn the_migration_does_not_drop_the_drop_log() {
        let list = drop_list(include_str!("store.rs"));
        assert!(
            !list.contains("drop_log"),
            "drop_log is on the drop list; what blocked sources did would not survive a version bump"
        );
    }

    // Debt 1 (I ran a push from the wrong repository directory and it targeted
    // the wrong object). The same class here is writing to a database other
    // than the one named.
    #[test]
    fn a_store_writes_to_the_path_it_was_given() {
        let path = fresh("named-path");
        let s = Store::open(&path).unwrap();
        s.log_decision(1, "198.51.100.1".parse().unwrap(), &dispo_block(), 3600)
            .unwrap();
        assert!(
            path.exists(),
            "the named path must be the file that was created"
        );
        assert!(
            !std::path::Path::new(DEFAULT_PATH).starts_with(path.parent().unwrap()),
            "the test must not be silently exercising the default path"
        );
        let n: i64 = Store::open(&path)
            .unwrap()
            .conn
            .query_row("SELECT count(*) FROM block_log", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1, "the row must be in the database that was named");
    }

    // Debt 1, second half: two stores must not see each other. If they did, a
    // count read from one would describe the other -- which is exactly what
    // acting on the wrong target looks like from the outside.
    #[test]
    fn two_stores_at_different_paths_are_isolated() {
        let a = fresh("iso-a");
        let b = fresh("iso-b");
        Store::open(&a)
            .unwrap()
            .log_decision(1, "198.51.100.1".parse().unwrap(), &dispo_block(), 3600)
            .unwrap();
        let sb = Store::open(&b).unwrap();
        assert_eq!(
            sb.blocks(10, None).unwrap().len(),
            0,
            "a second database must not see the first's rows"
        );
    }

    // Debt 2 (a broken instrument returned nothing and I reported the nothing as
    // fact). Empty must be a real answer...
    #[test]
    fn an_empty_audit_log_reads_as_empty_and_not_as_an_error() {
        let path = fresh("empty-ok");
        let s = Store::open(&path).unwrap();
        let rows = s
            .blocks(10, None)
            .expect("an empty log is a legitimate answer, not a failure");
        assert!(rows.is_empty());
    }

    // ...and a failed read must NOT look like empty. This is the exact shape of
    // the failure being paid for: had the query been broken, "no rows" and
    // "could not read" would have been the same value, and the caller would
    // have reported an empty corpus as a measured one.
    #[test]
    fn a_broken_read_is_an_error_not_an_empty_result() {
        let path = fresh("broken-read");
        let s = Store::open(&path).unwrap();
        s.conn.execute_batch("DROP TABLE block_log;").unwrap();
        let r = s.blocks(10, None);
        assert!(
            r.is_err(),
            "reading a missing table returned {:?} — an unreadable log must never \
             be indistinguishable from an empty one",
            r.map(|v| v.len())
        );
    }

    // ---- R1: recording what was decided ----

    fn dispo_block() -> tfps_core::disposition::Disposition<'static> {
        tfps_core::disposition::Disposition::Block {
            kind: "scanner",
            detail: "sipvicious",
        }
    }

    #[test]
    fn a_block_records_its_verdict_and_when_it_lapses() {
        let path = fresh("rec-block");
        let s = Store::open(&path).unwrap();
        s.log_decision(100, "198.51.100.1".parse().unwrap(), &dispo_block(), 3600)
            .unwrap();
        let (enforced, expires): (i64, Option<i64>) = s
            .conn
            .query_row("SELECT enforced, expires FROM block_log", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(enforced, 1);
        assert_eq!(expires, Some(3700), "expires is ts + ttl, absolute");
    }

    // A TTL of 0 means forever, and the APIBAN path already uses it that way.
    // Storing ts+0 would claim the block lapsed the instant it was made.
    #[test]
    fn a_ttl_of_zero_records_never_rather_than_now() {
        let path = fresh("rec-forever");
        let s = Store::open(&path).unwrap();
        s.log_decision(100, "198.51.100.1".parse().unwrap(), &dispo_block(), 0)
            .unwrap();
        let expires: Option<i64> = s
            .conn
            .query_row("SELECT expires FROM block_log", [], |r| r.get(0))
            .unwrap();
        assert_eq!(expires, Some(0), "0 means never, not 'expired at ts'");
    }

    // The observe-only label. No TTL exists because nothing was blocked, so
    // `expires` must be null rather than a number nobody can act on.
    #[test]
    fn a_would_block_records_no_expiry_because_nothing_was_blocked() {
        let path = fresh("rec-would");
        let s = Store::open(&path).unwrap();
        let d = tfps_core::disposition::Disposition::WouldBlock {
            kind: "injection",
            detail: "'",
        };
        s.log_decision(100, "198.51.100.2".parse().unwrap(), &d, 3600)
            .unwrap();
        let (enforced, expires): (i64, Option<i64>) = s
            .conn
            .query_row("SELECT enforced, expires FROM block_log", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(enforced, 0);
        assert_eq!(
            expires, None,
            "a TTL that was never applied must not be recorded"
        );
    }

    // The hard negative, and the rule that spared it -- an operator's curated
    // list and a learned registration are different strengths of evidence.
    #[test]
    fn an_exemption_records_which_rule_spared_it() {
        let path = fresh("rec-exempt");
        let s = Store::open(&path).unwrap();
        let d = tfps_core::disposition::Disposition::ExemptIgnoreIp {
            kind: "scanner",
            detail: "sipvicious",
            rule: "10.0.0.0/8",
        };
        s.log_decision(100, "198.51.100.3".parse().unwrap(), &d, 3600)
            .unwrap();
        let (ip, rule): (String, String) = s
            .conn
            .query_row("SELECT ip, rule FROM exempt_log", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!((ip.as_str(), rule.as_str()), ("198.51.100.3", "10.0.0.0/8"));
        let n: i64 = s
            .conn
            .query_row("SELECT count(*) FROM block_log", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            n, 0,
            "an exemption is not a block and must not enter the block log"
        );
    }

    #[test]
    fn a_registered_peer_exemption_names_itself_as_the_rule() {
        let path = fresh("rec-known");
        let s = Store::open(&path).unwrap();
        let d = tfps_core::disposition::Disposition::ExemptKnownPeer {
            kind: "auth-failed",
            detail: "rejected",
        };
        s.log_decision(100, "198.51.100.4".parse().unwrap(), &d, 3600)
            .unwrap();
        let rule: String = s
            .conn
            .query_row("SELECT rule FROM exempt_log", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rule, "registered-peer");
    }

    // NEGATIVE CONTROL: silence writes nothing at all. If `Ignore` produced a
    // row, every benign packet would enter the corpus as a label.
    #[test]
    fn silence_records_nothing() {
        let path = fresh("rec-silence");
        let s = Store::open(&path).unwrap();
        s.log_decision(
            100,
            "198.51.100.5".parse().unwrap(),
            &tfps_core::disposition::Disposition::Ignore,
            3600,
        )
        .unwrap();
        for table in ["block_log", "exempt_log"] {
            let n: i64 = s
                .conn
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                .unwrap();
            assert_eq!(n, 0, "{table} must be empty");
        }
    }

    // The gold negative. `actor` exists so a TTL lapse can never be counted as a
    // human saying the machine was wrong.
    #[test]
    fn an_unban_records_who_lifted_it() {
        let path = fresh("rec-unban");
        let s = Store::open(&path).unwrap();
        s.log_unban(200, "198.51.100.6".parse().unwrap(), "operator")
            .unwrap();
        let (ip, actor): (String, String) = s
            .conn
            .query_row("SELECT ip, actor FROM unban_log", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!((ip.as_str(), actor.as_str()), ("198.51.100.6", "operator"));
    }

    // A failed audit write must not stop the block -- but it must not be silent
    // either. The old signature returned nothing at all, so a corpus could lose
    // every row and read as a quiet success.
    #[test]
    fn a_failed_audit_write_is_reported_rather_than_swallowed() {
        let path = fresh("rec-fail");
        let s = Store::open(&path).unwrap();
        s.conn.execute_batch("DROP TABLE block_log;").unwrap();
        let r = s.log_decision(100, "198.51.100.7".parse().unwrap(), &dispo_block(), 3600);
        assert!(
            r.is_err(),
            "a lost label must be reported; silence here loses the corpus a row at a time"
        );
    }

    // ---- R1: the export, which another repository parses ----

    #[test]
    fn the_export_carries_all_three_verdicts() {
        let path = fresh("export-all");
        let s = Store::open(&path).unwrap();
        s.log_decision(10, "198.51.100.1".parse().unwrap(), &dispo_block(), 60)
            .unwrap();
        s.log_decision(
            20,
            "198.51.100.2".parse().unwrap(),
            &tfps_core::disposition::Disposition::WouldBlock {
                kind: "injection",
                detail: "'",
            },
            60,
        )
        .unwrap();
        s.log_decision(
            30,
            "198.51.100.3".parse().unwrap(),
            &tfps_core::disposition::Disposition::ExemptIgnoreIp {
                kind: "scanner",
                detail: "sipvicious",
                rule: "10.0.0.0/8",
            },
            60,
        )
        .unwrap();
        let v: Vec<&str> = s.labels(50).unwrap().iter().map(|l| l.verdict).collect();
        assert_eq!(v, vec!["exempt", "would-block", "blocked"], "newest first");
    }

    // The verdict is derived, so it cannot disagree with the row it describes.
    #[test]
    fn the_verdict_follows_enforcement_rather_than_a_stored_column() {
        let path = fresh("export-derive");
        let s = Store::open(&path).unwrap();
        s.log_decision(10, "198.51.100.1".parse().unwrap(), &dispo_block(), 60)
            .unwrap();
        let l = &s.labels(50).unwrap()[0];
        assert!(l.enforced);
        assert_eq!(l.verdict, "blocked");
        assert_eq!(l.expires, Some(70));
    }

    // An operator lift attaches to the block it followed. A lift recorded
    // BEFORE a block must not attach to it: that would read as a human
    // overruling a decision that had not been made yet.
    #[test]
    fn an_operator_lift_attaches_only_to_a_block_that_preceded_it() {
        let path = fresh("export-unban");
        let s = Store::open(&path).unwrap();
        s.log_decision(100, "198.51.100.1".parse().unwrap(), &dispo_block(), 60)
            .unwrap();
        s.log_unban(50, "198.51.100.1".parse().unwrap(), "operator")
            .unwrap();
        assert_eq!(
            s.labels(50).unwrap()[0].unbanned_at,
            None,
            "a lift before the block must not be read as overruling it"
        );
        s.log_unban(150, "198.51.100.1".parse().unwrap(), "operator")
            .unwrap();
        assert_eq!(s.labels(50).unwrap()[0].unbanned_at, Some(150));
    }

    // Only a human counts. A TTL lapse is not somebody saying the machine was
    // wrong, and counting it would inflate the false-positive rate R1 measures.
    #[test]
    fn a_non_operator_lift_is_not_a_negative_label() {
        let path = fresh("export-ttl");
        let s = Store::open(&path).unwrap();
        s.log_decision(100, "198.51.100.1".parse().unwrap(), &dispo_block(), 60)
            .unwrap();
        s.log_unban(150, "198.51.100.1".parse().unwrap(), "ttl")
            .unwrap();
        assert_eq!(
            s.labels(50).unwrap()[0].unbanned_at,
            None,
            "only an operator lift is a human judgement"
        );
    }

    // NEGATIVE CONTROL: an empty database exports nothing and does not error.
    // "No labels yet" and "the export is broken" must never be one value.
    #[test]
    fn an_empty_database_exports_no_labels_without_failing() {
        let path = fresh("export-empty");
        let s = Store::open(&path).unwrap();
        assert!(s.labels(50).expect("empty is an answer").is_empty());
    }

    // ---- Owed: a `pkill -f` pattern that matched the shell running it ----
    //
    // Cleaning up a throwaway process, I used a pattern broad enough to match
    // my own command line, so the kill took out the shell and the `rm` after it
    // never ran. The bracket trick that avoids it is in my notes; I used the
    // naive form anyway.
    //
    // Nothing in this product matches processes, so the debt is paid against
    // the same CLASS where it does appear here: a text matcher that can select
    // the wrong thing -- itself included -- and still pass.

    /// The anchor must reach the migration's array and not the first textual
    /// match in the file. That is the property the naive extractor had only by
    /// luck of ordering.
    #[test]
    fn the_drop_list_extractor_reads_the_migration_and_not_a_decoy() {
        let decoyed = concat!(
            "fn something_else() {\n",
            "    for t in [\"block_log\", \"definitely_wrong\"] {}\n",
            "}\n",
            "fn migrate() {\n",
            "    for t in [\"peer_anomaly\", \"known_peer\"] {}\n",
            "}\n"
        );
        let list = drop_list(decoyed);
        assert!(
            list.contains("peer_anomaly"),
            "the extractor read a decoy above the migration: {list:?}"
        );
        assert!(
            !list.contains("block_log"),
            "the extractor selected the wrong array and would report a failure \
             that is not there: {list:?}"
        );
    }

    /// POSITIVE CONTROL. The decoy test shows the anchor skips what precedes
    /// the migration; this shows the anchoring is what does it, by proving the
    /// unanchored search picks the decoy. Without it the test above could pass
    /// for the wrong reason.
    #[test]
    fn the_unanchored_search_really_would_have_picked_the_decoy() {
        let decoyed = concat!(
            "fn something_else() {\n",
            "    for t in [\"block_log\", \"definitely_wrong\"] {}\n",
            "}\n",
            "fn migrate() {\n",
            "    for t in [\"peer_anomaly\"] {}\n",
            "}\n"
        );
        let naive = decoyed
            .split_once("for t in [")
            .unwrap()
            .1
            .split_once(']')
            .unwrap()
            .0;
        assert!(
            naive.contains("block_log"),
            "the unanchored form must demonstrably pick the decoy, or the \
             anchoring above guards nothing"
        );
    }

    #[test]
    fn the_apiban_list_survives_a_restart_and_ages_out() {
        // The feed is consumed through a forward-only cursor, so what it already gave us
        // cannot be fetched again. Losing it on restart would leave the integration
        // looking healthy while protecting nothing.
        let dir = std::env::temp_dir().join(format!("tfps-apiban-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("t.db");
        let day = 86_400u32;
        let now = 100 * day;
        {
            let mut s = Store::open(&path).unwrap();
            s.apiban_add(&[Ipv4Addr::new(45, 134, 144, 130)], now - 2 * day)
                .unwrap();
            s.apiban_add(&[Ipv4Addr::new(185, 243, 5, 75)], now - 30 * day)
                .unwrap();
        }
        let s = Store::open(&path).unwrap();
        let fresh = s.apiban_since(now - 7 * day).unwrap();
        assert_eq!(
            fresh,
            vec![Ipv4Addr::new(45, 134, 144, 130)],
            "stale entries stay out"
        );
        assert_eq!(
            s.apiban_since(0).unwrap().len(),
            2,
            "but they are still on file"
        );
        assert_eq!(s.apiban_prune(now - 7 * day), 1);
        assert_eq!(
            s.apiban_since(0).unwrap().len(),
            1,
            "pruning removed the old one"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn meta_survives_a_reopen() {
        // The APIBAN resume point lives here. Losing it means refetching the whole feed on
        // every restart, which is what this replaced.
        let dir = std::env::temp_dir().join(format!("tfps-meta-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("t.db");
        {
            let s = Store::open(&path).unwrap();
            assert_eq!(s.meta_get("apiban_id"), None, "absent before it is written");
            s.meta_set("apiban_id", "1698425647");
        }
        let s = Store::open(&path).unwrap();
        assert_eq!(s.meta_get("apiban_id").as_deref(), Some("1698425647"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_learned_state_survives_a_restart() {
        // The property that makes learning mode meaningful: without it a
        // `systemctl restart` would silently erase 30 days of baseline.
        let path = tmp();
        let _ = std::fs::remove_file(&path);
        let peer = Ipv4Addr::new(10, 0, 0, 5);
        let t = Timestamp(1_800_000_000);

        let mut e1 = Engine::new(DialPlan::new(["00"]), Mode::Active).with_behavioural();
        e1.observe(peer, &invite("200", "00551199998888"), t);
        e1.observe(peer, &invite("200", "00351912345678"), t);

        let mut s = Store::open(&path).unwrap();
        let (sources, _) = s.checkpoint(&e1).unwrap();
        assert_eq!(sources, 1, "one source persisted");

        // A fresh process, memory wiped.
        let mut e2 = Engine::new(DialPlan::new(["00"]), Mode::Active).with_behavioural();
        let s2 = Store::open(&path).unwrap();
        s2.load_into(&mut e2).unwrap();

        // What was already known stays known — it does not become novel again.
        let dec = e2.observe(peer, &invite("200", "00551199998888"), t);
        assert_eq!(
            dec,
            tfps_core::engine::Decision::Pass {
                country: "BR",
                novel: false
            },
            "Brazil was already known before the restart"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_learning_start_does_not_reset_on_every_boot() {
        let path = tmp().with_extension("learn.db");
        let _ = std::fs::remove_file(&path);
        let s = Store::open(&path).unwrap();
        let first = s.learning_started(1000);
        assert_eq!(first, 1000);
        // A "restart" later, with the clock much further along.
        let s2 = Store::open(&path).unwrap();
        assert_eq!(
            s2.learning_started(9_999_999),
            1000,
            "restarting must not push the end of learning further out"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_audit_log_writes_and_prunes() {
        let path = tmp().with_extension("log.db");
        let _ = std::fs::remove_file(&path);
        let s = Store::open(&path).unwrap();
        s.log_decision(100, Ipv4Addr::new(1, 2, 3, 4), &dispo_block(), 3600)
            .unwrap();
        s.log_decision(200, Ipv4Addr::new(5, 6, 7, 8), &dispo_block(), 3600)
            .unwrap();
        assert_eq!(s.prune_log(150), 1, "only the oldest one goes");
        let remaining: i64 = s
            .conn
            .query_row("SELECT count(*) FROM block_log", [], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining, 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_corrupt_blob_does_not_break_loading() {
        assert!(blob_to_words(&[0u8; 31]).is_none());
        assert!(blob_to_words(&[]).is_none());
        assert!(blob_to_words(&[0u8; 32]).is_some());
        // Round-trip preserves the value.
        let w = [1u64, 2, 3, 4];
        assert_eq!(blob_to_words(&words_to_blob(&w)), Some(w));
    }
}
