//! Condemning a source from outside the daemon: `tfps_ctl ban`, `unban`, and
//! the evidence `ingest` -- one rule, in one place.
//!
//! The daemon decides for itself what it will not act against: the machine it
//! is defending, and the operator's `ignoreip`. A block placed by hand used
//! to skip both, so the one command meant for a human to reach for in a hurry
//! was the one that could condemn the host. Every block placed from here now
//! goes through the same refusals, gets the same TTL semantics, and leaves the
//! same audit row the perimeter leaves -- with its provenance in the `rule`,
//! so a label exported later says who asked.
//!
//! The kernel map needs `CAP_BPF` and cannot be opened from a test, so it is
//! behind [`BanSink`], a trait the map implements and a test fakes with a map
//! in memory. Everything else here is pure over its arguments.

#![deny(missing_docs)]

use std::io::BufRead;
use std::net::Ipv4Addr;
use std::path::Path;

use serde::{Deserialize, Serialize};

use tfps_core::disposition::Disposition;
use tfps_core::ignore::IgnoreList;

use crate::config::{self, Loaded};
use crate::contract::{rfc3339, Action};
use crate::store::Store;
use crate::xdp::Blocklist;

/// Where blocks go. The kernel map in the binary; a `BTreeMap` in a test.
pub trait BanSink {
    /// Condemns `ip` for `ttl` seconds, `0` meaning forever.
    fn insert(&mut self, ip: Ipv4Addr, ttl: u64) -> Result<(), String>;
    /// Lifts a block; `Ok(false)` when there was none to lift.
    fn remove(&mut self, ip: Ipv4Addr) -> Result<bool, String>;
}

impl BanSink for Blocklist {
    fn insert(&mut self, ip: Ipv4Addr, ttl: u64) -> Result<(), String> {
        Blocklist::insert(self, ip, ttl)
    }
    fn remove(&mut self, ip: Ipv4Addr) -> Result<bool, String> {
        Blocklist::remove(self, ip)
    }
}

/// Why a block was not placed, or a lift did not happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// An address of the machine being defended. Not configurable.
    SelfAddress,
    /// Matched an `ignoreip` entry; carries the entry, for the operator.
    IgnoreIp(String),
    /// An unban of something that was not blocked.
    NotBlocked,
    /// The input did not name an address at all.
    Invalid,
}

impl Refusal {
    /// The contract's word for it.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Refusal::SelfAddress => "self",
            Refusal::IgnoreIp(_) => "ignoreip",
            Refusal::NotBlocked => "not-blocked",
            Refusal::Invalid => "invalid",
        }
    }

    /// The sentence for a person.
    #[must_use]
    pub fn explain(&self) -> String {
        match self {
            Refusal::SelfAddress => "this host's own address".to_string(),
            Refusal::IgnoreIp(rule) => format!("exempt by ignoreip {rule}"),
            Refusal::NotBlocked => "was not blocked".to_string(),
            Refusal::Invalid => "not an IPv4 address".to_string(),
        }
    }
}

/// What the daemon will not act against, reconstructed for a second process.
pub struct Judge {
    local: Vec<Ipv4Addr>,
    ignore: IgnoreList,
}

impl Judge {
    /// From an explicit list of the host's addresses and an ignore list.
    #[must_use]
    pub fn new(local: Vec<Ipv4Addr>, ignore: IgnoreList) -> Self {
        Self { local, ignore }
    }

    /// The daemon's own exemptions, as far as another process can know them.
    ///
    /// Three sources, because no single one is complete from outside: the
    /// host's addresses as `local` (the caller reads them the way the daemon
    /// does); the configuration file's `ignoreip`; and the `ignoreip` line the
    /// daemon writes to meta at checkpoint, which is the only place a
    /// `--ignoreip` given on its command line can be seen from here. An entry
    /// that fails to parse is announced, never dropped quietly, for the same
    /// reason the daemon announces it.
    #[must_use]
    pub fn load(local: Vec<Ipv4Addr>, store: Option<&Store>, config: &Path) -> Self {
        let mut ignore = IgnoreList::new();
        let mut seen = std::collections::HashSet::new();
        let mut add = |entry: &str, from: &str| {
            if !seen.insert(entry.to_string()) {
                return;
            }
            if let Err(e) = ignore.add(entry) {
                eprintln!("WARNING: ignoreip entry from {from} rejected — {e}");
            }
        };
        match config::load(config) {
            Loaded::File(c, path) => {
                for entry in &c.ignoreip {
                    add(entry, &path.display().to_string());
                }
            }
            Loaded::Absent => {}
            // A broken file is not "no exemptions": say so, the daemon says so too.
            Loaded::Broken(e) => eprintln!("WARNING: {e}"),
        }
        if let Some(line) = store.and_then(|s| s.meta_get("ignoreip")) {
            for entry in line.split_whitespace() {
                if let Some((label, _hits)) = entry.rsplit_once('=') {
                    add(label, "the daemon's checkpoint");
                }
            }
        }
        Self::new(local, ignore)
    }

    /// The refusal for placing a block on `ip`, if there is one.
    ///
    /// The host first: it is not configuration and cannot be removed by an
    /// entry, whereas an `ignoreip` match names the entry so the operator can
    /// find it.
    pub fn refusal(&mut self, ip: Ipv4Addr) -> Option<Refusal> {
        if self.local.contains(&ip) {
            return Some(Refusal::SelfAddress);
        }
        self.ignore
            .exempt(ip)
            .map(|rule| Refusal::IgnoreIp(rule.to_string()))
    }
}

/// One block to place.
pub struct Request<'a> {
    /// The source to condemn.
    pub ip: Ipv4Addr,
    /// Seconds until the block lapses; `0` is forever.
    pub ttl: u64,
    /// The audit `rule`: `manual` for an operator, `sipnab:<rule>` for evidence.
    pub rule: &'a str,
    /// The audit `detail`.
    pub detail: &'a str,
    /// The contract's `source`: who asked.
    pub source: &'a str,
}

/// What `place` and `lift` did, for both readers: the contract object for a
/// program, and the refusal in full for the sentence a person reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The contract's line.
    pub action: Action,
    /// The refusal, with what it matched, when there was one.
    pub refusal: Option<Refusal>,
}

impl Outcome {
    /// The sentence for a person.
    #[must_use]
    pub fn describe(&self) -> String {
        let ip = self.action.ip.as_deref().unwrap_or("?");
        if let Some(r) = &self.refusal {
            return format!("refused {ip}: {}", r.explain());
        }
        let verb = match (self.action.action.as_str(), self.action.applied) {
            ("unban", _) => return format!("unbanned {ip}"),
            (_, true) => "blocked",
            (_, false) => "would block",
        };
        match &self.action.expires {
            Some(until) => format!("{verb} {ip} until {until}"),
            None => format!("{verb} {ip} with no expiry"),
        }
    }
}

/// Places one block, or refuses it, and says which.
///
/// In order: the refusals, then the kernel map, then the audit row. A refused
/// address touches nothing. Under `dry_run` nothing is written either, and the
/// action still says what would have happened -- `applied` false with
/// `refused` null is the one shape only a dry run produces.
///
/// The map write failing is an error, not an action: the operator's intent
/// was the block, and reporting "applied: false" for a map that refused
/// would file a kernel failure under the same word as a policy decision.
/// The audit write failing is warned about and never fatal, for the reason
/// `log_block` gives: the block it describes has already happened.
pub fn place(
    sink: &mut dyn BanSink,
    store: Option<&Store>,
    judge: &mut Judge,
    req: &Request<'_>,
    now: u32,
    dry_run: bool,
) -> Result<Outcome, String> {
    let mut action = Action {
        ip: Some(req.ip.to_string()),
        action: "ban".to_string(),
        applied: false,
        refused: None,
        expires: None,
        source: req.source.to_string(),
    };
    if let Some(r) = judge.refusal(req.ip) {
        action.refused = Some(r.as_str().to_string());
        return Ok(Outcome {
            action,
            refusal: Some(r),
        });
    }
    // 0 is "never" throughout this codebase; the contract says null.
    action.expires = (req.ttl != 0).then(|| {
        rfc3339(i64::from(now).saturating_add(i64::try_from(req.ttl).unwrap_or(i64::MAX)))
    });
    if dry_run {
        return Ok(Outcome {
            action,
            refusal: None,
        });
    }
    sink.insert(req.ip, req.ttl)?;
    action.applied = true;
    if let Some(s) = store {
        let d = Disposition::Block {
            kind: req.rule,
            detail: req.detail,
        };
        if let Err(e) = s.log_decision(now, req.ip, &d, req.ttl) {
            eprintln!(
                "WARNING: {} was blocked but the block was not recorded: {e}",
                req.ip
            );
        }
    }
    Ok(Outcome {
        action,
        refusal: None,
    })
}

/// Lifts one block, records the lift if it happened, and says which.
///
/// Remove from the kernel first -- the operator's actual intent and the
/// authoritative half -- then write `unban_log`. An address that was not
/// blocked records **nothing**: a row there is a negative label against a
/// source nothing was ever alleged about, and the corpus reads these rows as
/// an operator saying the machine was wrong. The write failing is warned
/// about, never fatal and never silent: this is the highest-quality label in
/// the corpus, and losing one quietly is how the precision measure rots.
pub fn lift(
    sink: &mut dyn BanSink,
    store: Option<&Store>,
    ip: Ipv4Addr,
    now: u32,
) -> Result<Outcome, String> {
    let removed = sink.remove(ip)?;
    if removed {
        if let Some(s) = store {
            if let Err(e) = s.log_unban(now, ip, "operator") {
                eprintln!("WARNING: {ip} was unbanned but the lift was not recorded: {e}");
            }
        }
    }
    let refusal = (!removed).then_some(Refusal::NotBlocked);
    Ok(Outcome {
        action: Action {
            ip: Some(ip.to_string()),
            action: "unban".to_string(),
            applied: removed,
            refused: refusal.as_ref().map(|r| r.as_str().to_string()),
            expires: None,
            source: "operator".to_string(),
        },
        refusal,
    })
}

/// The outcome for an input that named no address.
#[must_use]
pub fn invalid(action: &str, source: &str) -> Outcome {
    Outcome {
        action: Action {
            ip: None,
            action: action.to_string(),
            applied: false,
            refused: Some(Refusal::Invalid.as_str().to_string()),
            expires: None,
            source: source.to_string(),
        },
        refusal: Some(Refusal::Invalid),
    }
}

// ---------------------------------------------------------------- R4: evidence in

/// One finding, as sipnab publishes it: the same `{src_ip, rule, evidence}`
/// that `--alert-exec` already hands a shell command, one JSON object per line.
///
/// `ts` is when sipnab saw it and is carried for the operator's eyes. The
/// audit row is stamped with the ingest time, because that is when THIS
/// system reached its decision (R1, `first_seen`). Fields this version does
/// not know are ignored, so a newer sipnab can say more without breaking an
/// older TFPS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// The source sipnab is presenting evidence against.
    pub src_ip: String,
    /// sipnab's rule name; becomes `sipnab:<rule>` in the audit log.
    pub rule: String,
    /// What sipnab saw; becomes the audit `detail`, verbatim.
    pub evidence: String,
    /// When sipnab saw it, RFC 3339, if it said. (serde reads an absent
    /// `Option` as `None` on its own; the attribute only keeps it absent on
    /// the way back out, so the fixture round-trips.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ts: Option<String>,
}

/// The audit `rule` for a finding: the provenance, then sipnab's own name.
#[must_use]
pub fn provenance(rule: &str) -> String {
    format!("sipnab:{rule}")
}

/// Everything a stream of evidence needs, held once for every line of it.
pub struct Intake<'a> {
    /// The kernel map, or a test's fake.
    pub sink: &'a mut dyn BanSink,
    /// The audit log, when one could be opened.
    pub store: Option<&'a Store>,
    /// The daemon's exemptions.
    pub judge: &'a mut Judge,
    /// Seconds a block lasts; `0` is forever.
    pub ttl: u64,
    /// Report every decision, write nothing.
    pub dry_run: bool,
}

impl Intake<'_> {
    /// Applies one line of evidence exactly as `ban` would apply the address.
    ///
    /// A line that is not a finding -- torn JSON, no `src_ip`, an address
    /// that is not IPv4 -- is an `invalid` outcome for THAT line, with the
    /// reason on stderr, and never an error: a stream is a stream, and one
    /// torn record must not stop the ones after it.
    pub fn line(&mut self, line: &str, now: u32) -> Result<Outcome, String> {
        let finding: Finding = match serde_json::from_str(line) {
            Ok(f) => f,
            Err(e) => {
                // The error, not the line: a torn record can be anything, and
                // stderr is the operator's, not the stream's.
                eprintln!(
                    "WARNING: a line of evidence is not a finding ({e}); reported as invalid"
                );
                return Ok(invalid("ban", "sipnab"));
            }
        };
        let Ok(ip) = finding.src_ip.parse::<Ipv4Addr>() else {
            eprintln!(
                "WARNING: a finding names no IPv4 address ({:?}); reported as invalid",
                finding.src_ip
            );
            return Ok(invalid("ban", "sipnab"));
        };
        let rule = provenance(&finding.rule);
        place(
            self.sink,
            self.store,
            self.judge,
            &Request {
                ip,
                ttl: self.ttl,
                rule: &rule,
                detail: &finding.evidence,
                source: "sipnab",
            },
            now,
            self.dry_run,
        )
    }

    /// Reads findings until the input ends, handing each outcome to `emit` as
    /// it is decided, so a long-lived pipe from sipnab acts on every finding
    /// when it arrives rather than when the pipe closes. Blank lines are not
    /// records and produce nothing. Returns how many findings were read.
    ///
    /// Only a failed read of the input or a refused kernel write ends it
    /// early; both are about this side, not about a line.
    pub fn stream<R: BufRead>(
        &mut self,
        input: R,
        now: &dyn Fn() -> u32,
        emit: &mut dyn FnMut(&Outcome) -> Result<(), String>,
    ) -> Result<usize, String> {
        let mut n = 0usize;
        for line in input.lines() {
            let line = line.map_err(|e| format!("reading evidence: {e}"))?;
            if line.trim().is_empty() {
                continue;
            }
            n += 1;
            let o = self.line(&line, now())?;
            emit(&o)?;
        }
        Ok(n)
    }
}

/// A fake for the kernel map, for tests here and in the contract test.
#[derive(Debug, Default)]
pub struct MemoryMap {
    /// What is blocked, and for how long it was asked.
    pub blocked: std::collections::BTreeMap<Ipv4Addr, u64>,
}

impl BanSink for MemoryMap {
    fn insert(&mut self, ip: Ipv4Addr, ttl: u64) -> Result<(), String> {
        self.blocked.insert(ip, ttl);
        Ok(())
    }
    fn remove(&mut self, ip: Ipv4Addr) -> Result<bool, String> {
        Ok(self.blocked.remove(&ip).is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("tfps-condemn-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn store(name: &str) -> Store {
        Store::open(&dir(name).join("t.db")).unwrap()
    }

    fn judge() -> Judge {
        let mut ignore = IgnoreList::new();
        ignore.add("192.0.2.64/26").unwrap();
        Judge::new(vec![ip("192.0.2.1")], ignore)
    }

    fn request(addr: &str, ttl: u64) -> Request<'static> {
        Request {
            ip: ip(addr),
            ttl,
            rule: "manual",
            detail: "operator",
            source: "operator",
        }
    }

    fn block_rows(s: &Store) -> Vec<crate::store::BlockRow> {
        s.blocks(100, None).unwrap()
    }

    // THE RULE. A defence that can condemn the host it defends will eventually
    // do so; it happened here during development, from the host itself.
    #[test]
    fn the_host_is_never_condemned() {
        let s = store("self");
        let mut map = MemoryMap::default();
        let a = place(
            &mut map,
            Some(&s),
            &mut judge(),
            &request("192.0.2.1", 60),
            1,
            false,
        )
        .unwrap()
        .action;
        assert_eq!(a.refused.as_deref(), Some("self"));
        assert!(!a.applied);
        assert_eq!(a.expires, None, "nothing refused can lapse");
        assert!(map.blocked.is_empty(), "the map must be untouched");
        assert!(block_rows(&s).is_empty(), "a refusal leaves no audit row");
    }

    #[test]
    fn an_ignoreip_address_is_refused_and_the_entry_is_named() {
        let s = store("ignoreip");
        let mut map = MemoryMap::default();
        let mut j = judge();
        let a = place(
            &mut map,
            Some(&s),
            &mut j,
            &request("192.0.2.77", 60),
            1,
            false,
        )
        .unwrap()
        .action;
        assert_eq!(a.refused.as_deref(), Some("ignoreip"));
        assert!(map.blocked.is_empty());
        assert_eq!(
            j.refusal(ip("192.0.2.77")),
            Some(Refusal::IgnoreIp("192.0.2.64/26".into())),
            "the human form names the entry that matched"
        );
        // The neighbour outside the /26 is not exempt.
        assert_eq!(j.refusal(ip("192.0.2.128")), None);
    }

    #[test]
    fn a_placed_block_is_in_the_map_and_audited_with_its_provenance() {
        let s = store("placed");
        let mut map = MemoryMap::default();
        let req = Request {
            ip: ip("198.51.100.20"),
            ttl: 3600,
            rule: "sipnab:scanner_detected",
            detail: "ua=\"pplsip\" detection=ua_pattern",
            source: "sipnab",
        };
        let a = place(&mut map, Some(&s), &mut judge(), &req, 1_788_453_610, false)
            .unwrap()
            .action;
        assert!(a.applied);
        assert_eq!(a.refused, None);
        assert_eq!(a.expires.as_deref(), Some("2026-09-03T17:40:10Z"));
        assert_eq!(a.source, "sipnab");
        assert_eq!(map.blocked.get(&ip("198.51.100.20")), Some(&3600));
        let rows = block_rows(&s);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].reason, "sipnab:scanner_detected");
        assert_eq!(rows[0].detail, "ua=\"pplsip\" detection=ua_pattern");
        assert_eq!(rows[0].ts, 1_788_453_610);
        // The label export sees it as an enforced block with the right lapse.
        let labels = s.labels(10).unwrap();
        assert_eq!(labels[0].verdict, "blocked");
        assert_eq!(labels[0].expires, Some(1_788_453_610 + 3600));
    }

    // 0 is "never" everywhere in this codebase; the contract says null.
    #[test]
    fn a_ttl_of_zero_is_forever_and_reads_as_null() {
        let s = store("forever");
        let mut map = MemoryMap::default();
        let a = place(
            &mut map,
            Some(&s),
            &mut judge(),
            &request("198.51.100.23", 0),
            5,
            false,
        )
        .unwrap()
        .action;
        assert!(a.applied);
        assert_eq!(a.expires, None);
        assert_eq!(s.labels(10).unwrap()[0].expires, Some(0));
    }

    // Proved by counting, not by trusting a flag: the store has the same number
    // of rows after as before, and the map is empty.
    #[test]
    fn a_dry_run_reports_what_it_would_do_and_writes_nothing() {
        let s = store("dry");
        let before = block_rows(&s).len();
        let mut map = MemoryMap::default();
        let a = place(
            &mut map,
            Some(&s),
            &mut judge(),
            &request("198.51.100.20", 3600),
            100,
            true,
        )
        .unwrap()
        .action;
        assert!(!a.applied, "a dry run applies nothing");
        assert_eq!(a.refused, None, "and refuses nothing it would have placed");
        assert_eq!(
            a.expires.as_deref(),
            Some("1970-01-01T01:01:40Z"),
            "it still says when the block would have lapsed"
        );
        assert!(map.blocked.is_empty(), "the map must be untouched");
        assert_eq!(
            block_rows(&s).len(),
            before,
            "the audit log must be untouched"
        );
        // A refusal under dry run is still a refusal.
        let a = place(
            &mut map,
            Some(&s),
            &mut judge(),
            &request("192.0.2.1", 60),
            100,
            true,
        )
        .unwrap()
        .action;
        assert_eq!(a.refused.as_deref(), Some("self"));
    }

    // NEGATIVE CONTROL for the dry run: the same call without the flag writes,
    // so "writes nothing" is not passing because nothing ever writes.
    #[test]
    fn the_real_run_is_reachable_so_the_dry_run_test_is_not_vacuous() {
        let s = store("wet");
        let mut map = MemoryMap::default();
        place(
            &mut map,
            Some(&s),
            &mut judge(),
            &request("198.51.100.20", 3600),
            100,
            false,
        )
        .unwrap();
        assert_eq!(map.blocked.len(), 1);
        assert_eq!(block_rows(&s).len(), 1);
    }

    // The map refusing is a failure of the enforcement plane, not an action.
    #[test]
    fn a_map_that_refuses_is_an_error_not_a_refusal() {
        struct Broken;
        impl BanSink for Broken {
            fn insert(&mut self, _: Ipv4Addr, _: u64) -> Result<(), String> {
                Err("no map".into())
            }
            fn remove(&mut self, _: Ipv4Addr) -> Result<bool, String> {
                Err("no map".into())
            }
        }
        let s = store("broken");
        let r = place(
            &mut Broken,
            Some(&s),
            &mut judge(),
            &request("198.51.100.20", 60),
            1,
            false,
        );
        assert!(r.is_err());
        assert!(
            block_rows(&s).is_empty(),
            "no row for a block that did not happen"
        );
    }

    // ---- the daemon's exemptions, seen from another process ----

    #[test]
    fn the_judge_reads_the_config_file_and_the_daemons_meta_line() {
        let d = dir("load");
        let cfg = d.join("config.json");
        std::fs::write(&cfg, r#"{"ignoreip": ["203.0.113.0/24"]}"#).unwrap();
        let s = Store::open(&d.join("t.db")).unwrap();
        // What the daemon writes at checkpoint: its whole list, local entries
        // included, with hit counts.
        s.meta_set("ignoreip", "192.0.2.1=0 198.51.100.0/25=12");
        let mut j = Judge::load(vec![ip("192.0.2.9")], Some(&s), &cfg);
        assert_eq!(j.refusal(ip("192.0.2.9")), Some(Refusal::SelfAddress));
        assert_eq!(
            j.refusal(ip("203.0.113.7")),
            Some(Refusal::IgnoreIp("203.0.113.0/24".into())),
            "from the file"
        );
        assert_eq!(
            j.refusal(ip("198.51.100.100")),
            Some(Refusal::IgnoreIp("198.51.100.0/25".into())),
            "from the daemon's meta line: a --ignoreip flag is visible only there"
        );
        assert_eq!(
            j.refusal(ip("192.0.2.1")),
            Some(Refusal::IgnoreIp("192.0.2.1".into())),
            "the daemon's own local entry, when this process is not on that host"
        );
        assert_eq!(j.refusal(ip("198.51.100.200")), None, "outside every entry");
    }

    #[test]
    fn a_missing_config_and_an_absent_store_leave_only_the_host() {
        let mut j = Judge::load(
            vec![ip("192.0.2.9")],
            None,
            Path::new("/nonexistent/tfps/config.json"),
        );
        assert_eq!(j.refusal(ip("192.0.2.9")), Some(Refusal::SelfAddress));
        assert_eq!(j.refusal(ip("198.51.100.1")), None);
    }

    // ---- R1: the gold negative, now behind the same seam ----

    fn lifts(s: &Store) -> Vec<crate::store::UnbanRow> {
        s.unbans(100).unwrap()
    }

    #[test]
    fn a_real_lift_is_recorded_as_an_operator_judgement() {
        let s = store("lift");
        let mut map = MemoryMap::default();
        map.insert(ip("198.51.100.1"), 60).unwrap();
        let a = lift(&mut map, Some(&s), ip("198.51.100.1"), 500)
            .unwrap()
            .action;
        assert!(a.applied);
        assert_eq!(a.refused, None);
        assert!(map.blocked.is_empty(), "removed from the map first");
        let rows = lifts(&s);
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].ip.as_str(), rows[0].ts), ("198.51.100.1", 500));
        assert_eq!(
            rows[0].actor, "operator",
            "the actor must distinguish a human lift from a TTL lapsing"
        );
    }

    // THE RULE. `unban` on an address that was never blocked says so and must
    // write nothing: a row here would be a negative label against a source
    // nothing was ever alleged about.
    #[test]
    fn lifting_an_address_that_was_not_blocked_records_nothing() {
        let s = store("no-lift");
        let mut map = MemoryMap::default();
        let a = lift(&mut map, Some(&s), ip("198.51.100.2"), 500)
            .unwrap()
            .action;
        assert!(!a.applied);
        assert_eq!(a.refused.as_deref(), Some("not-blocked"));
        assert!(
            lifts(&s).is_empty(),
            "a lift that did not happen must leave no trace"
        );
    }

    // Bookkeeping must never be able to stop the operator lifting a block, so a
    // missing store is not an error here -- but it must also not panic.
    #[test]
    fn a_lift_without_a_database_still_completes() {
        let mut map = MemoryMap::default();
        map.insert(ip("198.51.100.3"), 60).unwrap();
        let a = lift(&mut map, None, ip("198.51.100.3"), 500)
            .unwrap()
            .action;
        assert!(a.applied);
    }

    // NEGATIVE CONTROL for the pair above: with a store present and a real
    // block, exactly one row appears.
    #[test]
    fn recording_is_reachable_so_the_silence_tests_are_not_vacuous() {
        let s = store("reachable");
        let mut map = MemoryMap::default();
        map.insert(ip("198.51.100.4"), 60).unwrap();
        lift(&mut map, Some(&s), ip("198.51.100.4"), 1).unwrap();
        lift(&mut map, Some(&s), ip("198.51.100.5"), 2).unwrap();
        assert_eq!(lifts(&s).len(), 1, "exactly the real lift, and only it");
    }

    #[test]
    fn the_sentences_say_what_happened() {
        let s = store("describe");
        let mut map = MemoryMap::default();
        let mut j = judge();
        let o = place(
            &mut map,
            Some(&s),
            &mut j,
            &request("198.51.100.20", 3600),
            1_788_453_610,
            false,
        )
        .unwrap();
        assert_eq!(
            o.describe(),
            "blocked 198.51.100.20 until 2026-09-03T17:40:10Z"
        );
        let o = place(
            &mut map,
            Some(&s),
            &mut j,
            &request("198.51.100.23", 0),
            1,
            true,
        )
        .unwrap();
        assert_eq!(o.describe(), "would block 198.51.100.23 with no expiry");
        let o = place(
            &mut map,
            Some(&s),
            &mut j,
            &request("192.0.2.77", 60),
            1,
            false,
        )
        .unwrap();
        assert_eq!(
            o.describe(),
            "refused 192.0.2.77: exempt by ignoreip 192.0.2.64/26"
        );
        let o = place(
            &mut map,
            Some(&s),
            &mut j,
            &request("192.0.2.1", 60),
            1,
            false,
        )
        .unwrap();
        assert_eq!(o.describe(), "refused 192.0.2.1: this host's own address");
        assert_eq!(
            lift(&mut map, Some(&s), ip("198.51.100.20"), 2)
                .unwrap()
                .describe(),
            "unbanned 198.51.100.20"
        );
        assert_eq!(
            lift(&mut map, Some(&s), ip("198.51.100.20"), 2)
                .unwrap()
                .describe(),
            "refused 198.51.100.20: was not blocked"
        );
        assert_eq!(
            invalid("ban", "operator").describe(),
            "refused ?: not an IPv4 address"
        );
    }

    #[test]
    fn an_invalid_input_is_an_action_with_no_address() {
        let a = invalid("ban", "sipnab").action;
        assert_eq!(a.ip, None);
        assert_eq!(a.refused.as_deref(), Some("invalid"));
        assert!(!a.applied);
        assert_eq!((a.action.as_str(), a.source.as_str()), ("ban", "sipnab"));
    }

    // ---- R4: evidence from sipnab, applied as a ban is applied ----
    //
    // sipnab never bans anything; it publishes evidence, and a system whose
    // entire job is condemning sources decides what to do with it. So a
    // finding goes through the same refusals as `ban`, gets the same TTL, and
    // leaves an audit row that says where it came from.

    const T_INGEST: u32 = 1_788_453_610;

    fn ingest_one(line: &str, s: &Store, map: &mut MemoryMap, dry: bool) -> Outcome {
        Intake {
            sink: map,
            store: Some(s),
            judge: &mut judge(),
            ttl: 3600,
            dry_run: dry,
        }
        .line(line, T_INGEST)
        .unwrap()
    }

    #[test]
    fn a_finding_is_applied_and_audited_with_its_provenance() {
        let s = store("ingest-applied");
        let mut map = MemoryMap::default();
        let o = ingest_one(
            r#"{"src_ip":"198.51.100.20","rule":"scanner_detected","evidence":"ua=\"pplsip\" detection=ua_pattern","ts":"2026-09-03T16:40:00Z"}"#,
            &s,
            &mut map,
            false,
        );
        assert!(o.action.applied);
        assert_eq!(o.action.source, "sipnab");
        assert_eq!(o.action.expires.as_deref(), Some("2026-09-03T17:40:10Z"));
        assert_eq!(map.blocked.get(&ip("198.51.100.20")), Some(&3600));
        let rows = block_rows(&s);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].reason, "sipnab:scanner_detected");
        assert_eq!(rows[0].detail, "ua=\"pplsip\" detection=ua_pattern");
        assert_eq!(
            rows[0].ts, T_INGEST,
            "stamped when THIS system decided, not when sipnab saw it"
        );
        assert_eq!(s.labels(10).unwrap()[0].rule, "sipnab:scanner_detected");
    }

    #[test]
    fn a_finding_naming_the_host_is_refused_with_self() {
        let s = store("ingest-self");
        let mut map = MemoryMap::default();
        let o = ingest_one(
            r#"{"src_ip":"192.0.2.1","rule":"scanner_detected","evidence":"x"}"#,
            &s,
            &mut map,
            false,
        );
        assert_eq!(o.action.refused.as_deref(), Some("self"));
        assert!(map.blocked.is_empty());
        assert!(block_rows(&s).is_empty());
    }

    #[test]
    fn a_finding_in_ignoreip_is_refused_with_ignoreip() {
        let s = store("ingest-ignoreip");
        let mut map = MemoryMap::default();
        let o = ingest_one(
            r#"{"src_ip":"192.0.2.77","rule":"register_scan","evidence":"registers=40 success=0"}"#,
            &s,
            &mut map,
            false,
        );
        assert_eq!(o.action.refused.as_deref(), Some("ignoreip"));
        assert_eq!(o.refusal, Some(Refusal::IgnoreIp("192.0.2.64/26".into())));
        assert!(map.blocked.is_empty());
    }

    // Proved with a count before and after, and an empty map.
    #[test]
    fn a_dry_run_ingest_writes_nothing_and_still_reports() {
        let s = store("ingest-dry");
        let before = block_rows(&s).len();
        let mut map = MemoryMap::default();
        let o = ingest_one(
            r#"{"src_ip":"198.51.100.22","rule":"options_flood","evidence":"rate=120/s"}"#,
            &s,
            &mut map,
            true,
        );
        assert!(!o.action.applied);
        assert_eq!(o.action.refused, None);
        assert_eq!(o.action.expires.as_deref(), Some("2026-09-03T17:40:10Z"));
        assert!(map.blocked.is_empty(), "the map must be untouched");
        assert_eq!(
            block_rows(&s).len(),
            before,
            "the audit log must be untouched"
        );
    }

    // The binary drives the STREAM, not the line, so the dry run has to be
    // proved there too: a stream that forgot to pass the flag along would
    // pass every line-level test and write on a real pipe. Found by mutation.
    #[test]
    fn a_dry_run_stream_writes_nothing_and_reports_every_line() {
        let s = store("ingest-dry-stream");
        let before = block_rows(&s).len();
        let mut map = MemoryMap::default();
        let input = "{\"src_ip\":\"198.51.100.20\",\"rule\":\"a\",\"evidence\":\"1\"}\n\
                     {\"src_ip\":\"192.0.2.1\",\"rule\":\"a\",\"evidence\":\"2\"}\n";
        let mut seen = Vec::new();
        let n = Intake {
            sink: &mut map,
            store: Some(&s),
            judge: &mut judge(),
            ttl: 60,
            dry_run: true,
        }
        .stream(input.as_bytes(), &|| T_INGEST, &mut |o| {
            seen.push(o.action.clone());
            Ok(())
        })
        .unwrap();
        assert_eq!(n, 2);
        assert!(!seen[0].applied);
        assert_eq!(seen[0].refused, None, "would have been applied");
        assert_eq!(seen[0].expires.as_deref(), Some("2026-09-03T16:41:10Z"));
        assert_eq!(
            seen[1].refused.as_deref(),
            Some("self"),
            "a refusal is still a refusal"
        );
        assert!(map.blocked.is_empty(), "the map must be untouched");
        assert_eq!(
            block_rows(&s).len(),
            before,
            "the audit log must be untouched"
        );
    }

    #[test]
    fn a_line_that_is_not_a_finding_is_invalid_and_not_an_error() {
        let s = store("ingest-invalid");
        let mut map = MemoryMap::default();
        for bad in [
            r#"{"src_ip":"198.51.100.21","rule":"reg"#,
            r#"{"rule":"x","evidence":"y"}"#,
            r#"{"src_ip":"not-an-ip","rule":"x","evidence":"y"}"#,
            r#"{"src_ip":"2001:db8::1","rule":"x","evidence":"y"}"#,
            r#"{"src_ip":"198.51.100.1","rule":"x"}"#,
            "[1,2,3]",
            "garbage",
        ] {
            let o = ingest_one(bad, &s, &mut map, false);
            assert_eq!(o.action.refused.as_deref(), Some("invalid"), "{bad}");
            assert_eq!(o.action.ip, None, "{bad}");
            assert_eq!(o.action.source, "sipnab");
        }
        assert!(map.blocked.is_empty());
        assert!(block_rows(&s).is_empty());
    }

    #[test]
    fn a_newer_sipnab_may_say_more_and_ts_is_optional() {
        let s = store("ingest-lenient");
        let mut map = MemoryMap::default();
        let o = ingest_one(
            r#"{"src_ip":"198.51.100.30","rule":"x","evidence":"y","confidence":0.9,"call_id":"abc"}"#,
            &s,
            &mut map,
            false,
        );
        assert!(
            o.action.applied,
            "unknown fields are not a reason to refuse"
        );
    }

    // THE STREAM PROPERTY: a torn line in the middle is reported on its own
    // line and the lines after it are still applied.
    #[test]
    fn a_torn_line_does_not_stop_the_lines_after_it() {
        let s = store("ingest-torn");
        let mut map = MemoryMap::default();
        let input = concat!(
            "{\"src_ip\":\"198.51.100.20\",\"rule\":\"a\",\"evidence\":\"1\"}\n",
            "\n",
            "{\"src_ip\":\"198.51.100.21\",\"rule\":\"b",
            "\n",
            "{\"src_ip\":\"198.51.100.22\",\"rule\":\"c\",\"evidence\":\"3\"}\n",
        );
        let mut seen = Vec::new();
        let n = Intake {
            sink: &mut map,
            store: Some(&s),
            judge: &mut judge(),
            ttl: 60,
            dry_run: false,
        }
        .stream(input.as_bytes(), &|| T_INGEST, &mut |o| {
            seen.push(o.action.clone());
            Ok(())
        })
        .unwrap();
        assert_eq!(n, 3, "three records; the blank line is not one");
        assert_eq!(seen.len(), 3);
        assert!(seen[0].applied);
        assert_eq!(seen[1].refused.as_deref(), Some("invalid"));
        assert!(seen[2].applied, "the line after the torn one");
        assert_eq!(map.blocked.len(), 2);
        assert_eq!(block_rows(&s).len(), 2);
    }

    // Each outcome is emitted as it is decided, not when the input ends.
    #[test]
    fn outcomes_are_emitted_as_they_are_decided() {
        let s = store("ingest-order");
        let mut map = MemoryMap::default();
        let input = "{\"src_ip\":\"198.51.100.20\",\"rule\":\"a\",\"evidence\":\"1\"}\n\
                     {\"src_ip\":\"198.51.100.21\",\"rule\":\"a\",\"evidence\":\"2\"}\n";
        let mut blocked_when_emitted = Vec::new();
        Intake {
            sink: &mut map,
            store: Some(&s),
            judge: &mut judge(),
            ttl: 60,
            dry_run: false,
        }
        .stream(input.as_bytes(), &|| T_INGEST, &mut |o| {
            blocked_when_emitted.push((o.action.ip.clone(), block_rows(&s).len()));
            Ok(())
        })
        .unwrap();
        assert_eq!(
            blocked_when_emitted,
            [
                (Some("198.51.100.20".to_string()), 1),
                (Some("198.51.100.21".to_string()), 2)
            ],
            "the first outcome is emitted before the second line is read"
        );
    }

    #[test]
    fn a_finding_round_trips_and_the_provenance_is_prefixed() {
        let line = r#"{"src_ip":"198.51.100.20","rule":"scanner_detected","evidence":"ua=\"pplsip\"","ts":"2026-09-03T16:40:00Z"}"#;
        let f: Finding = serde_json::from_str(line).unwrap();
        assert_eq!(serde_json::to_string(&f).unwrap(), line);
        let no_ts = r#"{"src_ip":"198.51.100.20","rule":"r","evidence":"e"}"#;
        let f: Finding = serde_json::from_str(no_ts).unwrap();
        assert_eq!(
            serde_json::to_string(&f).unwrap(),
            no_ts,
            "an absent ts stays absent"
        );
        assert_eq!(provenance("scanner_detected"), "sipnab:scanner_detected");
    }
}
