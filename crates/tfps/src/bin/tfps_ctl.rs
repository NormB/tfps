//! `tfps_ctl` — inspect what TFPS has learned, and lift or place blocks.
//!
//! The counterpart to `fail2ban-client`, and it exists for the same reason that tool does:
//! a defence nobody can inspect is a defence nobody trusts. `SPEC.md` §12 makes manual
//! unblocking the **precision proxy** — with no labelled data it is the only measure of how
//! often the system is wrong, so the act has to be one command, not a database session.
//!
//! Two sources of truth, and the difference matters to anyone reading the output:
//!
//! - **Blocks live in the kernel.** They are read and written straight into the eBPF map,
//!   so an unban takes effect on the next packet.
//! - **Learning lives in SQLite**, written at checkpoint (every 300 s by default). What is
//!   shown is therefore a snapshot, and `status` says how old it is rather than letting
//!   somebody draw conclusions from stale rows.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use tfps::drops::proto_name;
use tfps::say;
use tfps::store::{BlockRow, SourceFilter, Store};
use tfps::xdp::{monotonic_ns, Blocklist};

fn usage() -> String {
    format!(
        "tfps_ctl — inspect and control a running TFPS

USAGE: tfps_ctl <command> [options]

  status                       what is running, what is blocked, how fresh the state is
  stats                        every counter: kernel drops, traffic mix, what got blocked
  banned [--why]               list condemned sources, with time left
  dropped [--limit N] [--ip IP] what blocked sources kept sending, and why they were blocked
  unban <ip>... | --all        lift a block. The precision measure of this product
  ban <ip> [--ttl N]           condemn a source by hand (default ttl: 3600s, 0 = forever)
  sources [filters]            list learned sources and the countries they call
  source <peer>                everything known about one source
  peers                        sources by country breadth, when last heard
  countries <peer>             the countries a source has been seen to call
  log [--limit N] [--ip IP]    the block audit log, newest first
  log --json                   every label as JSON Lines, for an external analyzer
  forget <peer> [--a NUMBER]   erase learned state (requires tfps stopped)

SOURCE FILTERS:
  --peer IP                    exactly this peer
  --country ISO                sources that have called this country, e.g. --country GB
  --limit N                    stop after N rows (default 50)

GLOBAL:
  --db PATH                    database (default: {db})
  --map PATH                   an explicitly pinned block map
  -h, --help                   this help

Reading blocks needs CAP_BPF (run as root). Reading learned state only needs the database.
",
        db = tfps::store::DEFAULT_PATH
    )
}

struct Args {
    command: String,
    positional: Vec<String>,
    db: PathBuf,
    json: bool,
    map: Option<PathBuf>,
    peer: Option<String>,
    a_number: Option<String>,
    country: Option<String>,
    ip: Option<String>,
    limit: usize,
    ttl: u64,
    all: bool,
    why: bool,
}

fn parse(argv: &[String]) -> Result<Args, String> {
    let mut a = Args {
        command: String::new(),
        positional: Vec::new(),
        db: PathBuf::from(tfps::store::DEFAULT_PATH),
        json: false,
        map: None,
        peer: None,
        a_number: None,
        country: None,
        ip: None,
        limit: 50,
        ttl: 3600,
        all: false,
        why: false,
    };
    let mut it = argv.iter();
    let value = |name: &str, it: &mut std::slice::Iter<'_, String>| -> Result<String, String> {
        it.next()
            .cloned()
            .ok_or_else(|| format!("{name} requires a value"))
    };
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--db" => a.db = PathBuf::from(value("--db", &mut it)?),
            "--map" => a.map = Some(PathBuf::from(value("--map", &mut it)?)),
            "--peer" => a.peer = Some(value("--peer", &mut it)?),
            "--a" => a.a_number = Some(value("--a", &mut it)?),
            "--country" => a.country = Some(value("--country", &mut it)?),
            "--ip" => a.ip = Some(value("--ip", &mut it)?),
            "--json" => a.json = true,
            "--limit" => {
                a.limit = value("--limit", &mut it)?
                    .parse()
                    .map_err(|e| format!("invalid --limit: {e}"))?
            }
            "--ttl" => {
                a.ttl = value("--ttl", &mut it)?
                    .parse()
                    .map_err(|e| format!("invalid --ttl: {e}"))?
            }
            "--all" => a.all = true,
            "--why" => a.why = true,
            "-h" | "--help" => return Err(String::new()),
            other if other.starts_with('-') => return Err(format!("unknown option: {other}")),
            other if a.command.is_empty() => a.command = other.to_string(),
            other => a.positional.push(other.to_string()),
        }
    }
    if a.command.is_empty() {
        return Err(String::new());
    }
    Ok(a)
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse(&argv) {
        Ok(a) => a,
        Err(e) if e.is_empty() => {
            say!("{}", usage().trim_end());
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("error: {e}\n\n{}", usage());
            return ExitCode::from(2);
        }
    };

    let r = match args.command.as_str() {
        "status" => status(&args),
        "stats" => stats(&args),
        "banned" => banned(&args),
        "dropped" => dropped(&args),
        "unban" => unban(&args),
        "ban" => ban(&args),
        "sources" => sources(&args),
        "source" => source(&args),
        "peers" => peers(&args),
        "countries" => countries(&args),
        "log" => log(&args),
        "forget" => forget(&args),
        other => Err(format!("unknown command: {other}")),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------- commands

fn status(args: &Args) -> Result<(), String> {
    say!("database          : {}", args.db.display());
    match Store::open_readonly(&args.db).and_then(|s| s.totals()) {
        Ok((pairs, peers, newest)) => {
            say!("learned state     : {pairs} pairs across {peers} peers");
            if newest > 0 {
                say!(
                    "last checkpoint   : {} ago (state is a snapshot, not live)",
                    ago(now().saturating_sub(newest))
                );
            }
        }
        Err(e) => say!("learned state     : unavailable — {e}"),
    }
    match Blocklist::open(args.map.as_deref()) {
        Ok(b) => {
            let e = b.entries();
            let permanent = e.iter().filter(|(_, until)| *until == 0).count();
            say!("enforcement       : {}", b.source);
            say!(
                "blocked now       : {} ({permanent} without expiry)",
                e.len()
            );
        }
        Err(e) => {
            say!("enforcement       : unreachable — {e}");
            say!("                    (learned state above is still readable)");
        }
    }
    Ok(())
}

/// The whole picture, from the two places it lives.
///
/// **The kernel half is live; the userspace half is a snapshot.** They are printed apart,
/// with the snapshot's age stated, because presenting a five-minute-old packet count beside
/// a current drop count as if both were now would be the kind of quiet inaccuracy this
/// project exists to avoid.
fn stats(args: &Args) -> Result<(), String> {
    match tfps::xdp::live_counters() {
        Ok(c) => {
            let share = if c.seen > 0 {
                100.0 * c.dropped as f64 / c.seen as f64
            } else {
                0.0
            };
            say!("KERNEL  (live)");
            say!("  seen on SIP ports : {}", c.seen);
            say!(
                "  dropped by XDP    : {} ({share:.1}% — gone before sngrep)",
                c.dropped
            );
            say!("  blocks expired    : {}", c.expired);
            // The sample the daemon saw of those drops. A non-zero `lost` means the
            // ring buffer overflowed and the sample is thinner than the policy says.
            say!(
                "  drops reported    : {} events to userspace, {} lost{}",
                c.reported,
                c.lost,
                if c.lost > 0 {
                    " — the daemon is not draining fast enough"
                } else {
                    ""
                }
            );
        }
        Err(e) => say!("KERNEL  (live)\n  unavailable — {e}"),
    }
    let s = Store::open_readonly(&args.db)?;
    let apiban = s.apiban_all().unwrap_or_default();
    // A perimeter block often lands on an IP that is also on the feed; attribute it to the
    // reason we condemned it (the audit log), not to the feed it happens to appear on.
    let audit: std::collections::HashSet<String> = s
        .blocks(1_000_000, None)
        .unwrap_or_default()
        .into_iter()
        .map(|r| r.ip)
        .collect();
    if let Ok(b) = Blocklist::open(args.map.as_deref()) {
        let e = b.entries();
        let perimeter = e
            .iter()
            .filter(|(ip, _)| audit.contains(&ip.to_string()))
            .count();
        let feed = e
            .iter()
            .filter(|(ip, _)| !audit.contains(&ip.to_string()) && apiban.contains(&ip.to_string()))
            .count();
        say!("  condemned now     : {}", e.len());
        say!("    perimeter/manual : {perimeter}");
        say!("    APIBAN feed only : {feed}");
    }

    let now = now();
    match (s.meta_get("stats"), s.meta_get("stats_ts")) {
        (Some(line), ts) => {
            let age = ts
                .and_then(|t| t.parse::<u32>().ok())
                .map(|t| ago(now.saturating_sub(t)))
                .unwrap_or_else(|| "unknown".into());
            say!("\nTRAFFIC  (as of the last checkpoint, {age} ago)");
            // Two columns, so twenty counters stay readable in a terminal.
            let pairs: Vec<(&str, &str)> = line
                .split_whitespace()
                .filter_map(|kv| kv.split_once('='))
                .collect();
            for row in pairs.chunks(2) {
                let cell = |(k, v): &(&str, &str)| format!("{k:<16} {v:>10}");
                say!(
                    "  {}   {}",
                    cell(&row[0]),
                    row.get(1).map(cell).unwrap_or_default()
                );
            }
        }
        _ => say!("\nTRAFFIC\n  no checkpoint yet — the daemon writes these every 5 minutes"),
    }
    if let Some(t) = s.meta_get("started_at").and_then(|v| v.parse::<u32>().ok()) {
        say!("  {:<16} {:>10}", "running for", ago(now.saturating_sub(t)));
    }

    if let Some(line) = s.meta_get("ignoreip").filter(|l| !l.is_empty()) {
        say!("\nIGNOREIP  (exempt from enforcement, still judged and reported)");
        for entry in line.split_whitespace() {
            if let Some((label, hits)) = entry.rsplit_once('=') {
                let note = if hits == "0" { "  never matched" } else { "" };
                say!("  {label:<22} {hits:>8}{note}");
            }
        }
    }

    if let Some(cal) = s.meta_get("calibration").filter(|c| !c.is_empty()) {
        say!("\nCALIBRATION  (benign hypotheses learned from this deployment)");
        for kv in cal.split_whitespace() {
            if let Some((k, v)) = kv.split_once('=') {
                say!("  {k:<16} {v:>10}");
            }
        }
    }

    let (pairs, peers, _) = s.totals()?;
    let (countries, calls) = s.country_spread()?;
    say!("\nLEARNED");
    say!("  {:<16} {:>10}", "pairs", pairs);
    say!("  {:<16} {:>10}", "peers", peers);
    say!("  {:<16} {:>10}", "countries", countries);
    say!("  {:<16} {:>10}", "intl calls", calls);

    say!("\nBLOCKS BY REASON  (perimeter/manual — the APIBAN feed is a separate list)");
    say!(
        "  {:<16} {:>10}  {}",
        "apiban (feed)",
        apiban.len(),
        "permanent, not audit-logged"
    );
    for (label, since) in [
        ("last hour", 3600u32),
        ("last day", 86400),
        ("last week", 604_800),
    ] {
        let rows = s.blocks_by_reason(now.saturating_sub(since))?;
        let total: u32 = rows.iter().map(|(_, n)| n).sum();
        let detail: Vec<String> = rows.iter().map(|(r, n)| format!("{r}:{n}")).collect();
        say!("  {label:<16} {total:>10}  {}", detail.join(" "));
    }

    // What the blocked sources did next. Five here; `dropped` has the rest.
    let dropped = s.dropped(5, None)?;
    if !dropped.is_empty() {
        say!("\nSTILL SENDING  (blocked sources seen dropping, as of the last checkpoint)");
        for r in &dropped {
            say!(
                "  {:<16} {:>10}  {} ago  {}",
                r.ip,
                r.drops,
                ago(now.saturating_sub(r.last_ts)),
                r.last_line
            );
        }
    }
    Ok(())
}

/// Where a block's explanation came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Attribution {
    /// The audit log has a row: the perimeter, or an operator's `ban`.
    Perimeter,
    /// Only the APIBAN feed lists it.
    Feed,
    /// Nothing here explains it.
    Unknown,
}

/// Why an address is blocked, as far as this database knows.
///
/// One rule for `banned` and `dropped`, because two copies would drift and the same
/// address would be a scanner in one listing and unattributed in the other. The audit
/// log wins over the feed: a scanner is often on both — APIBAN's honeypots catch the
/// same tools — and the reason WE condemned it is the perimeter one.
fn attribute(
    audit: &HashMap<String, (String, String)>,
    apiban: &HashSet<String>,
    ip: &str,
) -> (Attribution, String) {
    if let Some((reason, detail)) = audit.get(ip) {
        (Attribution::Perimeter, format!("{reason} ({detail})"))
    } else if apiban.contains(ip) {
        (Attribution::Feed, "apiban (feed)".to_string())
    } else {
        (Attribution::Unknown, "not in this audit log".to_string())
    }
}

/// ip -> (reason, detail): the most recent block of each address in the audit log.
fn latest_reasons(store: Option<&Store>) -> HashMap<String, (String, String)> {
    let mut audit = HashMap::new();
    if let Some(s) = store {
        // Rows come newest-first, so the first seen per address is the latest.
        if let Ok(rows) = s.blocks(1_000_000, None) {
            for r in rows {
                audit.entry(r.ip).or_insert((r.reason, r.detail));
            }
        }
    }
    audit
}

fn banned(args: &Args) -> Result<(), String> {
    let b = Blocklist::open(args.map.as_deref())?;
    let entries = b.entries();
    if entries.is_empty() {
        say!("nothing is blocked");
        return Ok(());
    }
    // Load both sets once, then attribute each block through the one shared rule.
    let store = Store::open_readonly(&args.db).ok();
    let apiban = store
        .as_ref()
        .and_then(|s| s.apiban_all().ok())
        .unwrap_or_default();
    let audit = latest_reasons(store.as_ref());

    let now_ns = monotonic_ns();
    let (mut n_perimeter, mut n_apiban, mut n_unknown) = (0usize, 0usize, 0usize);
    say!("{:<16} {:>10}  REASON", "SOURCE", "EXPIRES IN");
    for (ip, until) in &entries {
        let left = if *until == 0 {
            "never".to_string()
        } else {
            ago(((*until).saturating_sub(now_ns) / 1_000_000_000) as u32)
        };
        let ip_s = ip.to_string();
        let (origin, why) = attribute(&audit, &apiban, &ip_s);
        match origin {
            Attribution::Perimeter => n_perimeter += 1,
            Attribution::Feed => n_apiban += 1,
            Attribution::Unknown => n_unknown += 1,
        }
        if args.why {
            say!("{ip_s:<16} {left:>10}  {why}");
        } else {
            say!("{ip_s:<16} {left:>10}");
        }
    }
    say!(
        "\n{} blocked — {n_perimeter} perimeter/manual, {n_apiban} APIBAN feed{}",
        entries.len(),
        if n_unknown > 0 {
            format!(", {n_unknown} unattributed")
        } else {
            String::new()
        }
    );
    Ok(())
}

/// What blocked sources kept sending, from the table the daemon flushes at checkpoint.
///
/// The counts are the kernel's and exact; the request line is from the latest sampled
/// event. The "why" is the same attribution `banned` gives, so the two commands never
/// disagree about an address.
fn dropped(args: &Args) -> Result<(), String> {
    let s = Store::open_readonly(&args.db)?;
    let rows = s.dropped(args.limit, args.ip.as_deref())?;
    if rows.is_empty() {
        say!(
            "no dropped traffic recorded — the daemon writes this at checkpoint (every 5 \
             minutes), and only its own XDP program reports drops"
        );
        return Ok(());
    }
    let apiban = s.apiban_all().unwrap_or_default();
    let audit = latest_reasons(Some(&s));
    let now = now();
    say!(
        "{:<16} {:>9} {:>7} {:>7}  {:<24} LAST REQUEST",
        "SOURCE",
        "DROPPED",
        "EVENTS",
        "LAST",
        "WHY BLOCKED"
    );
    for r in &rows {
        let (_, why) = attribute(&audit, &apiban, &r.ip);
        say!(
            "{:<16} {:>9} {:>7} {:>7}  {:<24} {}:{} {}",
            r.ip,
            r.drops,
            r.events,
            ago(now.saturating_sub(r.last_ts)),
            why,
            proto_name(r.last_proto),
            r.last_port,
            r.last_line
        );
    }
    say!(
        "\n{} sources. DROPPED is the kernel's exact count; EVENTS is the sample it reported \
         (the first few drops per source per second).",
        rows.len()
    );
    Ok(())
}

/// Records a lift, but only one that actually happened.
///
/// Split out because the kernel map needs `CAP_BPF` and cannot be driven from a
/// test, while the rule that matters here can be: **an address that was not
/// blocked must leave no trace.** A row for a lift that did not happen is a
/// negative label against a source nothing was ever alleged about, and R1 reads
/// these rows as an operator saying the machine was wrong.
///
/// Never fatal. The kernel removal is the operator's actual intent and has
/// already happened by the time this runs; failing the command afterwards would
/// tell them the unban did not work when it did. Never silent either — this is
/// the highest-quality label in the corpus and losing one quietly is how the
/// precision measure rots.
fn record_lift(store: Option<&Store>, ts: u32, ip: Ipv4Addr, removed: bool) {
    if !removed {
        return;
    }
    let Some(s) = store else {
        return;
    };
    if let Err(e) = s.log_unban(ts, ip, "operator") {
        eprintln!("WARNING: {ip} was unbanned but the lift was not recorded: {e}");
    }
}

fn unban(args: &Args) -> Result<(), String> {
    let mut b = Blocklist::open(args.map.as_deref())?;
    // Read-write here, unlike every other command in this tool: an unban is the
    // one thing `tfps_ctl` does that the corpus needs to know about. Opened
    // best-effort so a database that cannot be written still lets the operator
    // lift a block — protection outranks bookkeeping.
    let store = Store::open(&args.db)
        .map_err(|e| eprintln!("WARNING: lifts will not be recorded: {e}"))
        .ok();
    let ts = now();
    if args.all {
        let all = b.entries();
        for (ip, _) in &all {
            b.remove(*ip)?;
            record_lift(store.as_ref(), ts, *ip, true);
        }
        say!("unbanned {} sources", all.len());
        return Ok(());
    }
    if args.positional.is_empty() {
        return Err("give at least one address, or --all".into());
    }
    for raw in &args.positional {
        let ip: Ipv4Addr = raw.parse().map_err(|e| format!("{raw}: {e}"))?;
        // Saying "unbanned" for an address that was never there would be a small lie the
        // operator acts on: they would stop looking for the real block.
        let removed = b.remove(ip)?;
        if removed {
            say!("unbanned {ip}");
        } else {
            say!("{ip} was not blocked");
        }
        record_lift(store.as_ref(), ts, ip, removed);
    }
    Ok(())
}

fn ban(args: &Args) -> Result<(), String> {
    let mut b = Blocklist::open(args.map.as_deref())?;
    if args.positional.is_empty() {
        return Err("give at least one address".into());
    }
    for raw in &args.positional {
        let ip: Ipv4Addr = raw.parse().map_err(|e| format!("{raw}: {e}"))?;
        b.insert(ip, args.ttl)?;
        let how = if args.ttl == 0 {
            "with no expiry".to_string()
        } else {
            format!("for {}", ago(args.ttl as u32))
        };
        say!("blocked {ip} {how}");
    }
    Ok(())
}

fn sources(args: &Args) -> Result<(), String> {
    let s = Store::open_readonly(&args.db)?;
    let f = SourceFilter {
        peer: args.peer.as_deref(),
        country: args.country.as_deref(),
        limit: args.limit,
    };
    let rows = s.find_sources(&f)?;
    if rows.is_empty() {
        say!("no source matches");
        return Ok(());
    }
    say!("{:<16} {:>8} {:>9}  COUNTRIES", "PEER", "COUNTRIES", "LAST");
    let now = now();
    for r in &rows {
        let c = r.countries();
        let shown: Vec<&str> = c.iter().take(10).copied().collect();
        let tail = if c.len() > shown.len() {
            format!(" +{}", c.len() - shown.len())
        } else {
            String::new()
        };
        say!(
            "{:<16} {:>8} {:>9}  {}{}",
            r.peer,
            r.n_countries,
            ago(now.saturating_sub(r.last_seen)),
            shown.join(","),
            tail
        );
    }
    say!("\n{} sources", rows.len());
    Ok(())
}

fn source(args: &Args) -> Result<(), String> {
    let [peer] = args.positional.as_slice() else {
        return Err("usage: tfps_ctl source <peer>".into());
    };
    let s = Store::open_readonly(&args.db)?;
    let rows = s.find_sources(&SourceFilter {
        peer: Some(peer),
        limit: usize::MAX,
        ..Default::default()
    })?;
    let Some(r) = rows.first() else {
        return Err(format!("no source {peer} in the database"));
    };
    let c = r.countries();
    say!("peer              : {}", r.peer);
    say!(
        "last seen         : {} ago",
        ago(now().saturating_sub(r.last_seen))
    );
    say!("learned rate      : {:.2} intl calls / window", r.rate_a);
    say!("countries known   : {}", c.len());
    for chunk in c.chunks(12) {
        say!("                    {}", chunk.join(" "));
    }
    say!(
        "\nThe detector fires when a source's evidence — a burst of novel countries, \
         several prefixes, or a volume spike against this baseline — crosses the bound."
    );
    Ok(())
}

fn peers(args: &Args) -> Result<(), String> {
    let s = Store::open_readonly(&args.db)?;
    let rows = s.peers()?;
    if rows.is_empty() {
        say!("no peer learned yet");
        return Ok(());
    }
    say!("{:<16} {:>9} {:>9}  COUNTRIES", "PEER", "COUNTRIES", "LAST");
    let now = now();
    for (peer, ncoun, last) in rows.iter().take(args.limit) {
        let seen: Vec<&str> = s.peer_countries(peer).unwrap_or_default();
        say!(
            "{:<16} {:>9} {:>9}  {}",
            peer,
            ncoun,
            ago(now.saturating_sub(*last)),
            seen.iter().take(6).copied().collect::<Vec<_>>().join(" ")
        );
    }
    say!("\n{} sources", rows.len());
    Ok(())
}

fn countries(args: &Args) -> Result<(), String> {
    let [peer] = args.positional.as_slice() else {
        return Err("usage: tfps_ctl countries <peer>".into());
    };
    let s = Store::open_readonly(&args.db)?;
    let names = s.peer_countries(peer)?;
    if names.is_empty() {
        return Err(format!("nothing learned for source {peer}"));
    }
    say!("{peer} has been seen to call {} countries:", names.len());
    for chunk in names.chunks(16) {
        say!("  {}", chunk.join(" "));
    }
    Ok(())
}

/// One exported label, as the wire sees it.
///
/// A struct rather than a hand-built string: this is a contract another
/// repository parses, and hand-rolled escaping is how a detail containing a
/// quote — an injection pattern, for instance — silently produces a line the
/// consumer cannot read. `null` is emitted rather than the field being omitted,
/// so a reader can tell "no unban" from "field missing".
#[derive(serde::Serialize)]
struct JsonLabel<'a> {
    ip: &'a str,
    rule: &'a str,
    detail: &'a str,
    first_seen: u32,
    expires: Option<i64>,
    unbanned_at: Option<u32>,
    enforced: bool,
    verdict: &'a str,
}

fn log_json(args: &Args) -> Result<(), String> {
    let s = Store::open_readonly(&args.db)?;
    for l in s.labels(args.limit)? {
        let row = JsonLabel {
            ip: &l.ip,
            rule: &l.rule,
            detail: &l.detail,
            first_seen: l.first_seen,
            expires: l.expires,
            unbanned_at: l.unbanned_at,
            enforced: l.enforced,
            verdict: l.verdict,
        };
        // JSON Lines: one object per line, so a consumer can stream it and a
        // truncated file still yields every complete record before the cut.
        say!(
            "{}",
            serde_json::to_string(&row).map_err(|e| format!("serialising a label: {e}"))?
        );
    }
    Ok(())
}

fn log(args: &Args) -> Result<(), String> {
    if args.json {
        return log_json(args);
    }
    let s = Store::open_readonly(&args.db)?;
    let rows: Vec<BlockRow> = s.blocks(args.limit, args.ip.as_deref())?;
    if rows.is_empty() {
        say!("the audit log is empty");
        return Ok(());
    }
    say!("{:<9} {:<16} {:<14} DETAIL", "AGE", "SOURCE", "REASON");
    let now = now();
    for r in &rows {
        say!(
            "{:<9} {:<16} {:<14} {}",
            ago(now.saturating_sub(r.ts)),
            r.ip,
            r.reason,
            r.detail
        );
    }
    Ok(())
}

fn forget(args: &Args) -> Result<(), String> {
    let Some(peer) = args.positional.first() else {
        return Err("usage: tfps_ctl forget <peer> [--a NUMBER]".into());
    };
    // A running daemon holds the working set in memory and would write it straight back at
    // the next checkpoint. Deleting rows underneath it would look like it worked and then
    // quietly undo itself — the exact class of silent failure this project exists to avoid.
    if Blocklist::open(args.map.as_deref()).is_ok() {
        return Err(
            "tfps appears to be running: its in-memory state would be written back at the \
             next checkpoint, undoing this. Stop the service first (systemctl stop tfps)."
                .into(),
        );
    }
    let s = Store::open(Path::new(&args.db))?;
    let n = s.forget(peer, args.a_number.as_deref())?;
    say!("forgot {n} pairs for {peer}");
    Ok(())
}

// ---------------------------------------------------------------- helpers

fn now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

/// A compact duration. Operators read these in a column, so the widest case has to stay
/// short: `3d4h` rather than `3 days, 4 hours`.
fn ago(secs: u32) -> String {
    match secs {
        0 => "now".to_string(),
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86400 => format!("{}h{}m", s / 3600, (s % 3600) / 60),
        s => format!("{}d{}h", s / 86400, (s % 86400) / 3600),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- R1: the gold negative ----

    fn ctl_db(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("tfps-ctl-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("tfps.db")
    }

    fn lifts(s: &Store) -> Vec<tfps::store::UnbanRow> {
        s.unbans(100).unwrap()
    }

    #[test]
    fn a_real_lift_is_recorded_as_an_operator_judgement() {
        let path = ctl_db("lift");
        let s = Store::open(&path).unwrap();
        record_lift(Some(&s), 500, "198.51.100.1".parse().unwrap(), true);
        let rows = lifts(&s);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].ip, "198.51.100.1");
        assert_eq!(
            rows[0].actor, "operator",
            "the actor must distinguish a human lift from a TTL lapsing"
        );
    }

    // THE RULE. `unban` on an address that was never blocked prints "was not
    // blocked" and must write nothing: a row here would be a negative label
    // against a source nothing was ever alleged about, and R1 counts these as
    // an operator saying the machine was wrong.
    #[test]
    fn lifting_an_address_that_was_not_blocked_records_nothing() {
        let path = ctl_db("no-lift");
        let s = Store::open(&path).unwrap();
        record_lift(Some(&s), 500, "198.51.100.2".parse().unwrap(), false);
        assert!(
            lifts(&s).is_empty(),
            "a lift that did not happen must leave no trace"
        );
    }

    // Bookkeeping must never be able to stop the operator lifting a block, so a
    // missing store is not an error here -- but it must also not panic, which is
    // what an unwrap on the open would have done on a read-only filesystem.
    #[test]
    fn a_lift_without_a_database_still_completes() {
        record_lift(None, 500, "198.51.100.3".parse().unwrap(), true);
    }

    // NEGATIVE CONTROL for the pair above: with a store present and `removed`
    // true, exactly one row appears -- so "records nothing" is not passing
    // because nothing is ever recorded.
    #[test]
    fn recording_is_reachable_so_the_silence_tests_are_not_vacuous() {
        let path = ctl_db("reachable");
        let s = Store::open(&path).unwrap();
        record_lift(Some(&s), 1, "198.51.100.4".parse().unwrap(), true);
        record_lift(Some(&s), 2, "198.51.100.5".parse().unwrap(), false);
        assert_eq!(lifts(&s).len(), 1, "exactly the real lift, and only it");
    }

    fn args(v: &[&str]) -> Result<Args, String> {
        parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn the_command_comes_first_and_addresses_follow() {
        let a = args(&["unban", "1.2.3.4", "5.6.7.8"]).unwrap();
        assert_eq!(a.command, "unban");
        assert_eq!(a.positional, ["1.2.3.4", "5.6.7.8"]);
    }

    #[test]
    fn filters_parse() {
        let a = args(&[
            "pairs",
            "--peer",
            "10.0.0.5",
            "--country",
            "gb",
            "--limit",
            "5",
        ])
        .unwrap();
        assert_eq!(a.peer.as_deref(), Some("10.0.0.5"));
        assert_eq!(a.country.as_deref(), Some("gb"));
        assert_eq!(a.limit, 5);
    }

    #[test]
    fn an_option_with_no_value_is_an_error_not_a_default() {
        // Silently defaulting would make `--limit` at the end of a line mean something the
        // operator did not ask for.
        assert!(args(&["sources", "--limit"]).is_err());
        assert!(args(&["banned", "--bogus"]).is_err());
    }

    // ---- R2: one attribution rule, shared by `banned` and `dropped` ----
    //
    // `banned` already decided how a blocked address is explained: the audit log
    // wins over the feed, and an address in neither says so. `dropped` needs the
    // same answer for the same address, and two copies of that rule would drift
    // — one command would call a source a scanner and the other would call it
    // unattributed. So it is one function, and it is pinned here.

    fn audit_of(entries: &[(&str, &str, &str)]) -> HashMap<String, (String, String)> {
        entries
            .iter()
            .map(|(ip, r, d)| (ip.to_string(), (r.to_string(), d.to_string())))
            .collect()
    }

    #[test]
    fn the_audit_log_outranks_the_feed() {
        // A scanner is often on both: APIBAN's honeypots catch the same tools. The
        // reason WE condemned it is the perimeter one, not the list it also sits on.
        let audit = audit_of(&[("198.51.100.1", "scanner", "sipvicious")]);
        let feed = HashSet::from(["198.51.100.1".to_string()]);
        assert_eq!(
            attribute(&audit, &feed, "198.51.100.1"),
            (Attribution::Perimeter, "scanner (sipvicious)".to_string())
        );
    }

    #[test]
    fn the_feed_is_named_when_the_audit_log_has_nothing() {
        let audit = audit_of(&[]);
        let feed = HashSet::from(["198.51.100.2".to_string()]);
        assert_eq!(
            attribute(&audit, &feed, "198.51.100.2"),
            (Attribution::Feed, "apiban (feed)".to_string())
        );
    }

    #[test]
    fn an_unattributed_source_says_so() {
        // A block placed by hand, or by a daemon whose audit log is gone: the
        // operator must be told nothing explains it, not handed a guess.
        let audit = audit_of(&[("198.51.100.1", "scanner", "sipvicious")]);
        let feed = HashSet::new();
        assert_eq!(
            attribute(&audit, &feed, "198.51.100.9"),
            (Attribution::Unknown, "not in this audit log".to_string())
        );
    }

    #[test]
    fn durations_stay_narrow_enough_for_a_column() {
        assert_eq!(ago(0), "now");
        assert_eq!(ago(45), "45s");
        assert_eq!(ago(600), "10m");
        assert_eq!(ago(3700), "1h1m");
        assert_eq!(ago(200_000), "2d7h");
        assert!(ago(u32::MAX).len() <= 9);
    }

    #[test]
    fn output_goes_through_the_pipe_safe_macro() {
        // `tfps_ctl pairs | head` closes the pipe early. Rust ignores SIGPIPE, so a plain
        // `println!` panics there — this file must not contain one.
        // The needle is assembled at runtime, otherwise this test's own source would
        // contain the very thing it forbids and fail against itself.
        let needle = concat!("print", "ln!(");
        let src = include_str!("tfps_ctl.rs");
        // `eprintln!` ends in the same characters and is fine: stderr is not the piped
        // stream, and a diagnostic that cannot be written is not worth surviving for.
        let hits = src
            .match_indices(needle)
            .filter(|(i, _)| !src[..*i].ends_with(char::is_alphabetic))
            .count();
        assert_eq!(
            hits, 0,
            "use say!() instead of {needle}) so a closed pipe ends the run instead of panicking"
        );
    }
}
