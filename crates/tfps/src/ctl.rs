//! What `tfps_ctl` shows, kept in the library so a test can reach it.
//!
//! The kernel map needs `CAP_BPF` and cannot be opened from a test, so the
//! binary stays thin: it opens the map and the store and hands what it finds
//! to the functions here, which are pure over their arguments. Everything a
//! contract fixture pins -- how a block is attributed, how a monotonic lapse
//! instant becomes a wall-clock time, which meta values are trusted -- is
//! decided in this file and nowhere else.

#![deny(missing_docs)]

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::Path;

use crate::contract::{rfc3339, Banned, Dropped, Status};
use crate::drops::DropRow;
use crate::store::Store;

/// Where a block's explanation came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attribution {
    /// The audit log has a row: the perimeter, or an operator's `ban`.
    Perimeter {
        /// The rule that fired.
        rule: String,
        /// What it matched.
        detail: String,
        /// When the row was written, Unix seconds.
        ts: u32,
    },
    /// Only the APIBAN feed lists it.
    Feed,
    /// Nothing here explains it.
    Unknown,
}

/// The most recent audit row per address: `ip -> (reason, detail, ts)`.
pub type Audit = HashMap<String, (String, String, u32)>;

/// Why an address is blocked, as far as this database knows.
///
/// One rule for `banned` and `dropped`, because two copies would drift and the
/// same address would be a scanner in one listing and unattributed in the
/// other. The audit log wins over the feed: a scanner is often on both --
/// APIBAN's honeypots catch the same tools -- and the reason WE condemned it
/// is the perimeter one.
#[must_use]
pub fn attribute(audit: &Audit, apiban: &HashSet<String>, ip: &str) -> Attribution {
    if let Some((rule, detail, ts)) = audit.get(ip) {
        Attribution::Perimeter {
            rule: rule.clone(),
            detail: detail.clone(),
            ts: *ts,
        }
    } else if apiban.contains(ip) {
        Attribution::Feed
    } else {
        Attribution::Unknown
    }
}

impl Attribution {
    /// The human form, for the tables.
    #[must_use]
    pub fn why(&self) -> String {
        match self {
            Attribution::Perimeter { rule, detail, .. } => format!("{rule} ({detail})"),
            Attribution::Feed => "apiban (feed)".to_string(),
            Attribution::Unknown => "not in this audit log".to_string(),
        }
    }

    /// The machine form: the rule and what it matched, `None` when unattributed.
    /// The feed reads as rule `apiban`, detail `feed` -- the same words the
    /// daemon uses when it announces a feed block.
    fn rule_and_detail(&self) -> (Option<String>, Option<String>) {
        match self {
            Attribution::Perimeter { rule, detail, .. } => {
                (Some(rule.clone()), Some(detail.clone()))
            }
            Attribution::Feed => (Some("apiban".to_string()), Some("feed".to_string())),
            Attribution::Unknown => (None, None),
        }
    }
}

/// The latest audit row for each address, newest wins.
#[must_use]
pub fn latest_reasons(store: Option<&Store>) -> Audit {
    let mut audit = Audit::new();
    if let Some(s) = store {
        // Rows come newest-first, so the first seen per address is the latest.
        if let Ok(rows) = s.blocks(1_000_000, None) {
            for r in rows {
                audit.entry(r.ip).or_insert((r.reason, r.detail, r.ts));
            }
        }
    }
    audit
}

/// The `status --json` object from what the tool could open.
///
/// `blocked` is `Some(n)` when a block map opened with `n` entries, `None`
/// when none could. `mode` and `iface` are the daemon's meta values as read;
/// they are reported only while enforcement is live, because a pair left by a
/// previous run describes that run, not this one.
#[must_use]
pub fn status_of(
    blocked: Option<usize>,
    mode: Option<&str>,
    iface: Option<&str>,
    db: &Path,
    version: &str,
) -> Status {
    let live = blocked.is_some();
    // Empty is how the daemon clears a value it cannot vouch for; it is not a
    // mode called "".
    let known = |v: Option<&str>| v.filter(|s| live && !s.is_empty()).map(str::to_string);
    Status {
        enforcement: if live { "active" } else { "inactive" }.to_string(),
        mode: known(mode),
        interface: known(iface),
        blocked_now: blocked.unwrap_or(0) as u64,
        db: db.display().to_string(),
        version: version.to_string(),
    }
}

/// One `banned --json` line from a kernel entry and its attribution.
///
/// The map stores the lapse instant in monotonic nanoseconds, `0` for never.
/// The contract speaks wall clock, so the remaining time is measured against
/// `now_mono` and added to `now_wall`.
#[must_use]
pub fn to_banned(
    ip: Ipv4Addr,
    until_mono: u64,
    now_mono: u64,
    now_wall: u32,
    why: &Attribution,
) -> Banned {
    let expires = (until_mono != 0).then(|| {
        let left = until_mono.saturating_sub(now_mono) / 1_000_000_000;
        rfc3339(i64::from(now_wall).saturating_add(i64::try_from(left).unwrap_or(i64::MAX)))
    });
    let (rule, detail) = why.rule_and_detail();
    let first_seen = match why {
        Attribution::Perimeter { ts, .. } => Some(rfc3339(i64::from(*ts))),
        _ => None,
    };
    Banned {
        ip: ip.to_string(),
        rule,
        detail,
        first_seen,
        expires,
        enforced: true,
    }
}

/// One `dropped --json` line from a drop-log row and its attribution.
#[must_use]
pub fn to_dropped(r: &DropRow, why: &Attribution) -> Dropped {
    Dropped {
        ip: r.ip.clone(),
        dropped: r.drops,
        events: r.events,
        last_seen: rfc3339(i64::from(r.last_ts)),
        rule: why.rule_and_detail().0,
        last_request: (!r.last_line.is_empty()).then(|| r.last_line.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- R2: one attribution rule, shared by `banned` and `dropped` ----
    //
    // `banned` already decided how a blocked address is explained: the audit log
    // wins over the feed, and an address in neither says so. `dropped` needs the
    // same answer for the same address, and two copies of that rule would drift
    // -- one command would call a source a scanner and the other would call it
    // unattributed. So it is one function, and it is pinned here.

    fn audit_of(entries: &[(&str, &str, &str, u32)]) -> Audit {
        entries
            .iter()
            .map(|(ip, r, d, ts)| (ip.to_string(), (r.to_string(), d.to_string(), *ts)))
            .collect()
    }

    #[test]
    fn the_audit_log_outranks_the_feed() {
        // A scanner is often on both: APIBAN's honeypots catch the same tools. The
        // reason WE condemned it is the perimeter one, not the list it also sits on.
        let audit = audit_of(&[("198.51.100.1", "scanner", "sipvicious", 7)]);
        let feed = HashSet::from(["198.51.100.1".to_string()]);
        let why = attribute(&audit, &feed, "198.51.100.1");
        assert_eq!(
            why,
            Attribution::Perimeter {
                rule: "scanner".into(),
                detail: "sipvicious".into(),
                ts: 7
            }
        );
        assert_eq!(why.why(), "scanner (sipvicious)");
    }

    #[test]
    fn the_feed_is_named_when_the_audit_log_has_nothing() {
        let audit = audit_of(&[]);
        let feed = HashSet::from(["198.51.100.2".to_string()]);
        let why = attribute(&audit, &feed, "198.51.100.2");
        assert_eq!(why, Attribution::Feed);
        assert_eq!(why.why(), "apiban (feed)");
    }

    // The audit log holds every condemnation of an address, and `banned` must
    // explain the block by the LATEST one: a source first caught as a scanner
    // and later re-blocked for auth failures is answering for the second.
    #[test]
    fn the_latest_audit_row_explains_an_address() {
        use tfps_core::disposition::Disposition;
        let dir = std::env::temp_dir().join(format!("tfps-ctl-latest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let s = Store::open(&dir.join("t.db")).unwrap();
        let ip: Ipv4Addr = "198.51.100.3".parse().unwrap();
        s.log_decision(
            100,
            ip,
            &Disposition::Block {
                kind: "scanner",
                detail: "sipvicious",
            },
            60,
        )
        .unwrap();
        s.log_decision(
            200,
            ip,
            &Disposition::Block {
                kind: "auth-failed",
                detail: "rejected",
            },
            60,
        )
        .unwrap();
        let audit = latest_reasons(Some(&s));
        assert_eq!(
            audit.get("198.51.100.3"),
            Some(&("auth-failed".to_string(), "rejected".to_string(), 200))
        );
        assert!(
            latest_reasons(None).is_empty(),
            "no store, no attribution -- and no panic"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unattributed_source_says_so() {
        // A block placed by hand, or by a daemon whose audit log is gone: the
        // operator must be told nothing explains it, not handed a guess.
        let audit = audit_of(&[("198.51.100.1", "scanner", "sipvicious", 7)]);
        let feed = HashSet::new();
        let why = attribute(&audit, &feed, "198.51.100.9");
        assert_eq!(why, Attribution::Unknown);
        assert_eq!(why.why(), "not in this audit log");
    }
}
