// SPDX-License-Identifier: MIT OR Apache-2.0

//! The label format is a contract another repository parses.
//!
//! sipnab reads these lines and has no dependency on this crate — deliberately,
//! because TFPS is optional software an operator may or may not have installed,
//! in the same category as rtpengine, OpenSIPS or Asterisk. A shared Rust type
//! would make one project's release cadence the other's problem.
//!
//! The price of that independence is one format with two implementations, which
//! drift. A gate that reads one copy of a fact written twice certifies half of
//! it. So the contract is pinned by a fixture that is byte-identical in both
//! repositories: this side asserts the exporter *produces* this shape, and
//! sipnab asserts its reader *accepts* it.
//!
//! The addresses are from the documentation ranges of RFC 5737, so the file
//! carries no PII and can be committed on both sides — unlike the real corpus,
//! which never is.

use serde_json::Value;

const GOLDEN: &str = include_str!("fixtures/tfps-labels-golden.jsonl");

fn rows() -> Vec<Value> {
    GOLDEN
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str(l).unwrap_or_else(|e| panic!("golden line is not JSON: {l}: {e}"))
        })
        .collect()
}

/// Every field, on every row. A consumer in another repository cannot ask what
/// a missing key means, so absence is never how a value is expressed.
#[test]
fn every_row_carries_every_field() {
    const FIELDS: &[&str] = &[
        "ip",
        "rule",
        "detail",
        "first_seen",
        "expires",
        "unbanned_at",
        "enforced",
        "verdict",
    ];
    let rows = rows();
    assert!(!rows.is_empty(), "the golden fixture is empty");
    for (i, r) in rows.iter().enumerate() {
        let o = r.as_object().expect("each line is an object");
        for f in FIELDS {
            assert!(
                o.contains_key(*f),
                "row {i} has no {f:?}: null is a value, absence is not"
            );
        }
        assert_eq!(
            o.len(),
            FIELDS.len(),
            "row {i} has extra keys: {:?}",
            o.keys().collect::<Vec<_>>()
        );
    }
}

/// The three verdicts, and nothing else. sipnab matches on these strings.
#[test]
fn the_verdicts_are_exactly_the_three_agreed() {
    let seen: std::collections::BTreeSet<String> = rows()
        .iter()
        .map(|r| r["verdict"].as_str().unwrap().to_string())
        .collect();
    let expected: std::collections::BTreeSet<String> = ["blocked", "exempt", "would-block"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(
        seen, expected,
        "the fixture must exercise every verdict and invent none"
    );
}

/// `expires` carries three distinct meanings and the fixture must contain all
/// three, or a consumer could implement two of them and still pass.
#[test]
fn expires_covers_never_lapsing_and_absent() {
    let rows = rows();
    assert!(
        rows.iter().any(|r| r["expires"] == 0),
        "no row with expires 0 — the 'never' case would go untested"
    );
    assert!(
        rows.iter()
            .any(|r| r["expires"].as_i64().is_some_and(|v| v > 0)),
        "no row with a real lapse time"
    );
    assert!(
        rows.iter().any(|r| r["expires"].is_null()),
        "no row with expires null — the 'nothing was blocked' case would go untested"
    );
}

/// An operator lift must appear on at least one row, and be absent on another.
#[test]
fn the_gold_negative_is_present_and_also_absent() {
    let rows = rows();
    assert!(rows.iter().any(|r| r["unbanned_at"].is_null()));
    assert!(rows.iter().any(|r| !r["unbanned_at"].is_null()));
}

/// A detail containing a quote is the case hand-rolled escaping gets wrong, and
/// `injection` details are literally punctuation. If the fixture never carried
/// one, the consumer's parser would never be tested against it.
#[test]
fn a_detail_containing_punctuation_survives_the_wire() {
    assert!(
        rows().iter().any(|r| r["detail"] == "'"),
        "the fixture must contain a quote-bearing detail; that is the line a \
         hand-built serialiser breaks"
    );
}

/// `enforced` and `verdict` are two views of one fact and must never disagree.
#[test]
fn enforced_and_verdict_never_contradict_each_other() {
    for r in rows() {
        let enforced = r["enforced"].as_bool().unwrap();
        let verdict = r["verdict"].as_str().unwrap();
        assert_eq!(
            enforced,
            verdict == "blocked",
            "enforced={enforced} disagrees with verdict={verdict}"
        );
    }
}

/// The fixture is only a claim until the exporter is held to it.
///
/// Everything above checks the golden file against itself, which would pass
/// happily while the exporter emitted something else entirely. This drives the
/// real `labels()` over decisions chosen to reproduce the fixture, and compares
/// the emitted objects to it field by field.
#[test]
fn the_exporter_produces_the_shape_the_fixture_pins() {
    use tfps::store::Store;
    use tfps_core::disposition::Disposition;

    let dir = std::env::temp_dir().join(format!("tfps-contract-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let s = Store::open(&dir.join("t.db")).unwrap();

    s.log_decision(
        1_756_800_000,
        "198.51.100.10".parse().unwrap(),
        &Disposition::Block {
            kind: "scanner",
            detail: "sipvicious",
        },
        3600,
    )
    .unwrap();
    s.log_decision(
        1_756_800_100,
        "198.51.100.11".parse().unwrap(),
        &Disposition::Block {
            kind: "injection",
            detail: "'",
        },
        0,
    )
    .unwrap();
    s.log_unban(1_756_804_000, "198.51.100.11".parse().unwrap(), "operator")
        .unwrap();
    // A TTL lapse against a DIFFERENT blocked source. It must leave no trace in
    // the export, which is why no fixture row can show it — the absence is the
    // assertion. Without this the `actor = 'operator'` filter could be dropped
    // entirely and every check here would still pass, and sipnab would then
    // count expiries as humans overruling the machine and inflate the
    // false-positive rate R1 exists to measure.
    s.log_unban(1_756_804_100, "198.51.100.10".parse().unwrap(), "ttl")
        .unwrap();
    s.log_decision(
        1_756_800_200,
        "198.51.100.12".parse().unwrap(),
        &Disposition::WouldBlock {
            kind: "reg-scan",
            detail: "no-success",
        },
        3600,
    )
    .unwrap();
    s.log_decision(
        1_756_800_300,
        "192.0.2.5".parse().unwrap(),
        &Disposition::ExemptIgnoreIp {
            kind: "scanner",
            detail: "sipvicious",
            rule: "10.0.0.0/8",
        },
        3600,
    )
    .unwrap();
    s.log_decision(
        1_756_800_400,
        "192.0.2.6".parse().unwrap(),
        &Disposition::ExemptKnownPeer {
            kind: "auth-failed",
            detail: "rejected",
        },
        3600,
    )
    .unwrap();

    let produced: std::collections::BTreeMap<String, Value> = s
        .labels(50)
        .unwrap()
        .into_iter()
        .map(|l| {
            (
                l.ip.clone(),
                serde_json::json!({
                    "ip": l.ip,
                    "rule": l.rule,
                    "detail": l.detail,
                    "first_seen": l.first_seen,
                    "expires": l.expires,
                    "unbanned_at": l.unbanned_at,
                    "enforced": l.enforced,
                    "verdict": l.verdict,
                }),
            )
        })
        .collect();

    let expected: std::collections::BTreeMap<String, Value> = rows()
        .into_iter()
        .map(|r| (r["ip"].as_str().unwrap().to_string(), r))
        .collect();

    assert_eq!(
        produced.keys().collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>(),
        "the exporter emitted a different set of sources than the fixture pins"
    );
    for (ip, want) in &expected {
        assert_eq!(
            produced.get(ip).unwrap(),
            want,
            "the exporter disagrees with the golden fixture for {ip}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
