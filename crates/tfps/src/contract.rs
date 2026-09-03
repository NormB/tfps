//! The JSON `tfps_ctl` emits for a program: one contract, pinned by fixtures.
//!
//! Every read and write surface an external tool needs -- `status`, `banned`,
//! `dropped`, `ban`, `unban`, `ingest` and the label export -- speaks one
//! dialect, defined here and nowhere else: JSON Lines where there are several
//! records, `snake_case` keys in the order the struct declares them, timestamps
//! as RFC 3339 UTC strings, and **every field always present**, `null` when
//! unknown, so a reader can tell "no value" from "field missing".
//!
//! The consumer is sipnab, which has no dependency on this crate on purpose:
//! TFPS is optional software an operator may or may not have installed. So the
//! contract is not a shared type; it is a golden fixture per surface under
//! `tests/fixtures/`, byte-identical in both repositories, with each side
//! gating on its own copy. The structs here are what those bytes round-trip
//! through, and `deny_unknown_fields` is what makes a fixture with a stray key
//! fail rather than pass.

#![deny(missing_docs)]

use serde::{Deserialize, Serialize};

/// `tfps_ctl status --json`: one object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    /// `active` when a block map could be opened, `inactive` when none could.
    pub enforcement: String,
    /// How the daemon attached XDP at its last start, `native` or `skb`; `null`
    /// when unknown -- enforcement inactive, a shared map, or a daemon run
    /// without a database to say.
    pub mode: Option<String>,
    /// The interface XDP is attached to; `null` under the same conditions.
    pub interface: Option<String>,
    /// Sources in the block map right now. Zero when enforcement is inactive.
    pub blocked_now: u64,
    /// The database this tool read.
    pub db: String,
    /// The version of `tfps_ctl` that answered.
    pub version: String,
}

/// `tfps_ctl banned --json`: one line per source in the block map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Banned {
    /// The blocked source.
    pub ip: String,
    /// Why, as far as the audit log knows: the rule that fired, `apiban` for a
    /// feed-only block, `null` when nothing here explains it.
    pub rule: Option<String>,
    /// What the rule matched; `feed` for APIBAN; `null` when unattributed.
    pub detail: Option<String>,
    /// When the audit log recorded the block, RFC 3339 UTC; `null` when unattributed.
    pub first_seen: Option<String>,
    /// When the block lapses, RFC 3339 UTC; `null` means never.
    pub expires: Option<String>,
    /// Always true here -- the map is the enforcement plane. Carried so a row
    /// unions cleanly with the label export.
    pub enforced: bool,
}

/// `tfps_ctl dropped --json`: one line per source that kept sending after its block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dropped {
    /// The blocked source.
    pub ip: String,
    /// The kernel's exact count of packets dropped from it.
    pub dropped: u64,
    /// The sampled events userspace saw of those drops.
    pub events: u64,
    /// When it was last seen sending, RFC 3339 UTC.
    pub last_seen: String,
    /// Why it was blocked, the same attribution `banned` gives; `null` when unknown.
    pub rule: Option<String>,
    /// The request line of the latest sampled packet; `null` when none was captured.
    pub last_request: Option<String>,
}

/// `tfps_ctl ban --json`, `unban --json` and every line of `ingest`: what was
/// done about one address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    /// The address, or `null` when the input did not name a valid one.
    pub ip: Option<String>,
    /// `ban` or `unban`.
    pub action: String,
    /// Whether the kernel map was written. False for a refusal and for a dry run.
    pub applied: bool,
    /// Why it was not applied: `self`, `ignoreip`, `not-blocked`, `invalid`; `null`
    /// when it was applied, or would have been under `--dry-run`.
    pub refused: Option<String>,
    /// When the block lapses, RFC 3339 UTC; `null` for never, for an unban, and
    /// for anything refused.
    pub expires: Option<String>,
    /// Who asked: `operator` for the two commands, `sipnab` for `ingest`.
    pub source: String,
}

/// `tfps_ctl log --json`: one exported label, as the R1 design pins it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Label {
    /// The judged source.
    pub ip: String,
    /// The rule that fired, or the exemption source for an `exempt` row.
    pub rule: String,
    /// What the rule matched.
    pub detail: String,
    /// When this decision was reached, Unix seconds (the R1 shape predates the
    /// RFC 3339 convention and is kept as sipnab already reads it).
    pub first_seen: u32,
    /// Absolute lapse time, Unix seconds; `0` is never; `null` is no block.
    pub expires: Option<i64>,
    /// When an operator lifted it, Unix seconds, or `null`.
    pub unbanned_at: Option<u32>,
    /// Whether enforcement applied.
    pub enforced: bool,
    /// `blocked`, `would-block` or `exempt`.
    pub verdict: String,
}

/// Seconds since the Unix epoch as an RFC 3339 UTC timestamp: `2026-09-03T16:40:10Z`.
///
/// Written out rather than pulled in: the workspace carries no date crate, and
/// the whole need is one direction of one format. The civil-date arithmetic is
/// the proleptic-Gregorian algorithm (days from the epoch to year, month, day)
/// and is pinned to dates a human can check by hand, including the two leap
/// rules a naive version gets wrong.
pub fn rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

/// Days since 1970-01-01 to a proleptic-Gregorian (year, month, day).
///
/// Counts in 400-year eras, inside which the leap pattern repeats exactly, so
/// the `% 100` and `% 400` rules fall out of the arithmetic instead of being
/// special cases. Months are numbered from March so the leap day is the last
/// day of the year and never shifts anything after it.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vectors checked against `date -u -d ... +%s`, not against this code.
    #[test]
    fn timestamps_render_as_rfc3339_utc() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_788_453_610), "2026-09-03T16:40:10Z");
        assert_eq!(rfc3339(-1), "1969-12-31T23:59:59Z");
    }

    // 2000 is divisible by 400 and IS a leap year; 2100 is divisible by 100 and
    // is NOT. A formatter that only checks `% 4` passes every ordinary date and
    // fails on exactly these two.
    #[test]
    fn both_leap_rules_hold() {
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(4_107_542_400), "2100-03-01T00:00:00Z");
        assert_eq!(rfc3339(4_107_542_400 - 86_400), "2100-02-28T00:00:00Z");
    }

    // The largest value a HEP timestamp or a u32 store column can hold.
    #[test]
    fn the_u32_ceiling_is_a_real_date() {
        assert_eq!(rfc3339(4_294_967_295), "2106-02-07T06:28:15Z");
    }
}
