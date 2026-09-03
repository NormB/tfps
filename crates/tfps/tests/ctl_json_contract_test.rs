// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every JSON surface of `tfps_ctl` is a contract another repository parses.
//!
//! sipnab holds byte-identical copies of the fixtures under `fixtures/` and
//! gates its reader on them; this side gates its emitter. Two claims are made
//! per surface, and both are needed:
//!
//! 1. **The bytes round-trip.** Each fixture line parses into the contract
//!    struct and serialises back to exactly the same bytes. That pins the key
//!    order, the `null`s, and the absence of any extra key -- the things a
//!    hand-written fixture drifts on.
//! 2. **The emitter produces them.** The real conversion is driven over real
//!    store rows chosen to reproduce the fixture, and its output is compared
//!    to the fixture byte for byte. Without this the fixture would be
//!    self-consistent and worth nothing.
//!
//! Addresses are from the RFC 5737 documentation ranges so the files carry no
//! PII and both repositories can commit them.

use std::net::Ipv4Addr;
use std::path::Path;

use serde::{de::DeserializeOwned, Serialize};
use tfps::condemn::{invalid, lift, place, Finding, Intake, Judge, MemoryMap, Request};
use tfps::contract::{Action, Banned, Dropped, Label, Status};
use tfps::ctl::{attribute, latest_reasons, status_of, to_banned, to_dropped};
use tfps::drops::DropRow;
use tfps::store::Store;
use tfps_core::disposition::Disposition;
use tfps_core::ignore::IgnoreList;

const STATUS: &str = include_str!("fixtures/tfps-status-golden.json");
const BANNED: &str = include_str!("fixtures/tfps-banned-golden.jsonl");
const DROPPED: &str = include_str!("fixtures/tfps-dropped-golden.jsonl");
const BAN: &str = include_str!("fixtures/tfps-ban-golden.jsonl");
const UNBAN: &str = include_str!("fixtures/tfps-unban-golden.jsonl");
const LABELS: &str = include_str!("fixtures/tfps-labels-golden.jsonl");
const EVIDENCE: &str = include_str!("fixtures/sipnab-evidence-golden.jsonl");
const EVIDENCE_RESULT: &str = include_str!("fixtures/sipnab-evidence-result-golden.jsonl");

/// 2026-09-03T16:40:00Z, the instant every fixture is written around.
const T0: u32 = 1_788_453_600;

fn lines(fixture: &str) -> Vec<&str> {
    let out: Vec<&str> = fixture.lines().collect();
    assert!(!out.is_empty(), "an empty fixture pins nothing");
    for l in &out {
        assert!(!l.is_empty(), "a blank line is not a record");
        assert_eq!(
            l.trim_end(),
            *l,
            "no trailing whitespace: the bytes are the contract"
        );
    }
    out
}

/// Parse a line into `T` and serialise it again; the result must be the same bytes.
fn round_trip<T: Serialize + DeserializeOwned>(line: &str) -> T {
    let v: T = serde_json::from_str(line)
        .unwrap_or_else(|e| panic!("fixture line does not parse as the contract: {line}: {e}"));
    let back = serde_json::to_string(&v).unwrap();
    assert_eq!(
        back, line,
        "the struct does not reproduce the fixture bytes"
    );
    v
}

fn emit<T: Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap()
}

fn fresh(name: &str) -> Store {
    let dir = std::env::temp_dir().join(format!("tfps-ctl-json-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Store::open(&dir.join("t.db")).unwrap()
}

fn ip(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

// ---- 1. the bytes round-trip ----

#[test]
fn every_fixture_line_round_trips_through_its_struct() {
    assert_eq!(lines(STATUS).len(), 1, "status is one object, not a stream");
    round_trip::<Status>(lines(STATUS)[0]);
    for l in lines(BANNED) {
        round_trip::<Banned>(l);
    }
    for l in lines(DROPPED) {
        round_trip::<Dropped>(l);
    }
    for l in lines(BAN) {
        round_trip::<Action>(l);
    }
    for l in lines(UNBAN) {
        round_trip::<Action>(l);
    }
    for l in lines(LABELS) {
        round_trip::<Label>(l);
    }
}

/// NEGATIVE CONTROL on the round trip: a stray key must be refused, or a
/// fixture that grew a field nobody emits would still pass.
#[test]
fn a_fixture_with_an_extra_key_is_refused() {
    let with_extra = STATUS.trim_end().replacen('}', ",\"extra\":1}", 1);
    assert!(serde_json::from_str::<Status>(&with_extra).is_err());
    // A missing field is caught by the round trip, not by the parse: serde
    // reads an absent `Option` as `None`, and it comes back out as `null`, so
    // the bytes differ. This is the positive control on that mechanism.
    let missing = STATUS.trim_end().replacen("\"mode\":\"native\",", "", 1);
    let v: Status = serde_json::from_str(&missing).unwrap();
    assert_ne!(
        serde_json::to_string(&v).unwrap(),
        missing,
        "a fixture missing a field must not survive the round trip"
    );
}

/// The refusal vocabulary, exactly. sipnab matches on these strings.
#[test]
fn the_refusals_are_exactly_the_four_agreed_plus_none() {
    let seen: std::collections::BTreeSet<Option<String>> = lines(BAN)
        .into_iter()
        .chain(lines(UNBAN))
        .map(|l| round_trip::<Action>(l).refused)
        .collect();
    let want: std::collections::BTreeSet<Option<String>> = [
        None,
        Some("self".into()),
        Some("ignoreip".into()),
        Some("not-blocked".into()),
        Some("invalid".into()),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        seen, want,
        "every refusal must appear in a fixture, and no other"
    );
}

/// `applied` and `refused` are two views of one fact for a real run: a
/// refused action was not applied. (A dry run is the one case where both are
/// false and null, and it is not in these fixtures.)
#[test]
fn applied_and_refused_never_both_hold() {
    for l in lines(BAN).into_iter().chain(lines(UNBAN)) {
        let a = round_trip::<Action>(l);
        assert!(
            a.applied != a.refused.is_some(),
            "{l}: applied={} refused={:?}",
            a.applied,
            a.refused
        );
        if a.refused.is_some() {
            assert!(a.expires.is_none(), "{l}: nothing refused can lapse");
        }
    }
}

// ---- 2. the emitter produces them ----

#[test]
fn status_is_produced_from_what_the_tool_can_see() {
    let want = lines(STATUS)[0];
    let got = status_of(
        Some(3),
        Some("native"),
        Some("eth0"),
        Path::new("/var/lib/tfps/tfps.db"),
        "0.1.0",
    );
    assert_eq!(emit(&got), want);
}

/// Mode and interface come from the daemon's last start and are reported only
/// while enforcement is live: a stale pair from a previous run described as
/// current would be exactly the quiet inaccuracy this tool exists to avoid.
#[test]
fn status_reports_no_mode_or_interface_when_nothing_is_enforcing() {
    let got = status_of(
        None,
        Some("native"),
        Some("eth0"),
        Path::new("/var/lib/tfps/tfps.db"),
        "0.1.0",
    );
    assert_eq!(got.enforcement, "inactive");
    assert_eq!(got.blocked_now, 0);
    assert_eq!(got.mode, None);
    assert_eq!(got.interface, None);
    // An empty meta value is "unknown", not a mode called "".
    let got = status_of(Some(1), Some(""), Some(""), Path::new("/x"), "0.1.0");
    assert_eq!((got.mode, got.interface), (None, None));
}

#[test]
fn banned_is_produced_from_the_kernel_map_and_the_audit_log() {
    let s = fresh("banned");
    s.log_decision(
        T0,
        ip("198.51.100.10"),
        &Disposition::Block {
            kind: "user-agent",
            detail: "pplsip",
        },
        3600,
    )
    .unwrap();
    let mut s = s;
    s.apiban_add(&[ip("198.51.100.11")], T0).unwrap();
    let apiban = s.apiban_all().unwrap();
    let audit = latest_reasons(Some(&s));

    // The kernel stores a monotonic lapse instant; the contract speaks wall
    // clock. Here the daemon has been up 1000 s and it is T0 now.
    let now_mono: u64 = 1_000_000_000_000;
    let entries: [(Ipv4Addr, u64); 3] = [
        (ip("198.51.100.10"), now_mono + 3600 * 1_000_000_000),
        (ip("198.51.100.11"), 0),
        (ip("198.51.100.12"), 0),
    ];
    let got: Vec<String> = entries
        .iter()
        .map(|(ip, until)| {
            let ip_s = ip.to_string();
            emit(&to_banned(
                *ip,
                *until,
                now_mono,
                T0,
                &attribute(&audit, &apiban, &ip_s),
            ))
        })
        .collect();
    assert_eq!(got, lines(BANNED));
}

#[test]
fn dropped_is_produced_from_the_drop_log_and_the_audit_log() {
    let s = fresh("dropped");
    s.log_decision(
        T0,
        ip("198.51.100.10"),
        &Disposition::Block {
            kind: "user-agent",
            detail: "pplsip",
        },
        3600,
    )
    .unwrap();
    s.record_drops(&[
        DropRow {
            ip: "198.51.100.10".into(),
            first_ts: T0 + 30,
            last_ts: T0 + 60,
            drops: 30,
            events: 4,
            last_port: 5060,
            last_len: 412,
            last_proto: 17,
            last_line: "OPTIONS sip:100@198.51.100.1 SIP/2.0".into(),
        },
        DropRow {
            ip: "198.51.100.13".into(),
            first_ts: T0 + 120,
            last_ts: T0 + 120,
            drops: 1,
            events: 1,
            last_port: 5060,
            last_len: 0,
            last_proto: 17,
            last_line: String::new(),
        },
    ])
    .unwrap();
    let apiban = s.apiban_all().unwrap();
    let audit = latest_reasons(Some(&s));
    let got: Vec<String> = s
        .dropped(50, None)
        .unwrap()
        .iter()
        .map(|r| emit(&to_dropped(r, &attribute(&audit, &apiban, &r.ip))))
        .collect();
    assert_eq!(got, lines(DROPPED));
}

/// The host is 192.0.2.1 and 192.0.2.64/26 is exempt: the two refusals the
/// fixture shows are refusals of exactly these.
fn judge() -> Judge {
    let mut ignore = IgnoreList::new();
    ignore.add("192.0.2.64/26").unwrap();
    Judge::new(vec![ip("192.0.2.1")], ignore)
}

/// 2026-09-03T16:40:10Z: when the operator ran the command.
const T_BAN: u32 = T0 + 10;

#[test]
fn ban_is_produced_from_the_one_placement_rule() {
    let s = fresh("ban");
    let mut map = MemoryMap::default();
    let mut j = judge();
    let req = |addr: &str, ttl: u64| Request {
        ip: ip(addr),
        ttl,
        rule: "manual",
        detail: "operator",
        source: "operator",
    };
    let got = vec![
        emit(
            &place(
                &mut map,
                Some(&s),
                &mut j,
                &req("198.51.100.20", 3600),
                T_BAN,
                false,
            )
            .unwrap()
            .action,
        ),
        emit(
            &place(
                &mut map,
                Some(&s),
                &mut j,
                &req("198.51.100.23", 0),
                T_BAN,
                false,
            )
            .unwrap()
            .action,
        ),
        emit(
            &place(
                &mut map,
                Some(&s),
                &mut j,
                &req("192.0.2.1", 3600),
                T_BAN,
                false,
            )
            .unwrap()
            .action,
        ),
        emit(
            &place(
                &mut map,
                Some(&s),
                &mut j,
                &req("192.0.2.77", 3600),
                T_BAN,
                false,
            )
            .unwrap()
            .action,
        ),
        emit(&invalid("ban", "operator").action),
    ];
    assert_eq!(got, lines(BAN));
    // What the fixture cannot show: the two applied blocks are in the map and
    // the audit log, and nothing else is.
    assert_eq!(
        map.blocked
            .keys()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["198.51.100.20", "198.51.100.23"]
    );
    let rows = s.blocks(10, None).unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows
        .iter()
        .all(|r| r.reason == "manual" && r.detail == "operator"));
}

#[test]
fn unban_is_produced_from_the_one_lifting_rule() {
    let s = fresh("unban");
    let mut map = MemoryMap::default();
    place(
        &mut map,
        Some(&s),
        &mut judge(),
        &Request {
            ip: ip("198.51.100.20"),
            ttl: 3600,
            rule: "manual",
            detail: "operator",
            source: "operator",
        },
        T0,
        false,
    )
    .unwrap();
    let got = vec![
        emit(
            &lift(&mut map, Some(&s), ip("198.51.100.20"), T_BAN)
                .unwrap()
                .action,
        ),
        emit(
            &lift(&mut map, Some(&s), ip("198.51.100.21"), T_BAN)
                .unwrap()
                .action,
        ),
        emit(&invalid("unban", "operator").action),
    ];
    assert_eq!(got, lines(UNBAN));
    assert!(map.blocked.is_empty());
    let lifts = s.unbans(10).unwrap();
    assert_eq!(lifts.len(), 1, "only the lift that happened is recorded");
    assert_eq!(lifts[0].ip, "198.51.100.20");
}

// ---- R4: the evidence channel ----
//
// sipnab holds both files: it asserts its emitter writes the first and its
// reader accepts the second. This side asserts the opposite pair.

/// Every well-formed evidence line round-trips through `Finding`, and exactly
/// one line is torn -- the fixture must carry the case the stream property is
/// about, or a reader that aborts on the first bad line would pass.
#[test]
fn the_evidence_fixture_round_trips_and_carries_one_torn_line() {
    let mut torn = 0;
    for l in lines(EVIDENCE) {
        match serde_json::from_str::<Finding>(l) {
            Ok(f) => assert_eq!(serde_json::to_string(&f).unwrap(), l),
            Err(_) => torn += 1,
        }
    }
    assert_eq!(
        torn, 1,
        "exactly one torn line, in the middle of the stream"
    );
    for l in lines(EVIDENCE_RESULT) {
        round_trip::<Action>(l);
    }
    assert_eq!(
        lines(EVIDENCE).len(),
        lines(EVIDENCE_RESULT).len(),
        "one result per input line"
    );
}

#[test]
fn ingest_produces_the_result_fixture_from_the_evidence_fixture() {
    let s = fresh("ingest");
    let mut map = MemoryMap::default();
    let mut got = Vec::new();
    let n = Intake {
        sink: &mut map,
        store: Some(&s),
        judge: &mut judge(),
        ttl: 3600,
        dry_run: false,
    }
    .stream(EVIDENCE.as_bytes(), &|| T_BAN, &mut |o| {
        got.push(emit(&o.action));
        Ok(())
    })
    .unwrap();
    assert_eq!(n, 5);
    assert_eq!(got, lines(EVIDENCE_RESULT));
    // What the fixture cannot show: exactly the two applied findings reached
    // the map and the audit log, with their provenance.
    assert_eq!(
        map.blocked
            .keys()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["198.51.100.20", "198.51.100.22"]
    );
    let mut rules: Vec<(String, String)> = s
        .blocks(10, None)
        .unwrap()
        .into_iter()
        .map(|r| (r.reason, r.detail))
        .collect();
    rules.sort();
    assert_eq!(
        rules,
        [
            ("sipnab:options_flood".to_string(), "rate=120/s".to_string()),
            (
                "sipnab:scanner_detected".to_string(),
                "ua=\"pplsip\" detection=ua_pattern".to_string()
            ),
        ]
    );
}
