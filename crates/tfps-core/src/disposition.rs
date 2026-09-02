// What the perimeter does with a condemnation, as a pure function.
//
// The rule this file exists for: a condemnation must never be computed and then
// silently dropped. `SPEC.md` §12 makes silence an alarm, and the shape that
// broke it was an `if / else if / else if` chain with no `else` — the third arm
// guarded on an enforcer that is `None` under `--no-enforce`. The two exemption
// arms printed, the enforcement arm printed, and the fourth case, "condemned
// while observing", fell off the end of the chain saying nothing.
//
// A chain can silently lack an arm. A total match over an enum cannot: adding a
// state without handling it stops the build. That is the actual repair, and it
// is why this is an enum rather than another `else`.

use core::fmt;

/// What should happen to a source the perimeter has judged.
///
/// Carries the reason with it so the caller cannot report a disposition and a
/// reason that disagree — they are decided together or not at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition<'a> {
    /// Nothing was tripped. The overwhelmingly common case.
    Ignore,
    /// Tripped a rule, but the static ignore list covers it. Reported, never
    /// enforced: staying silent here would hide a compromised trusted peer,
    /// which is exactly when it matters most.
    ExemptIgnoreIp {
        kind: &'a str,
        detail: &'a str,
        rule: &'a str,
    },
    /// Tripped a rule, but this peer registered and authenticated. The dynamic
    /// ignore list, and what protects a customer on a changing address.
    ExemptKnownPeer { kind: &'a str, detail: &'a str },
    /// Condemned, and enforcement is on: block it and record it.
    Block { kind: &'a str, detail: &'a str },
    /// Condemned while observing only. Nothing is blocked, and the judgement is
    /// still recorded — that record is the entire point of an observe-only run.
    WouldBlock { kind: &'a str, detail: &'a str },
}

impl Disposition<'_> {
    /// The rule that fired, for any disposition that has one.
    pub fn kind(&self) -> Option<&str> {
        match self {
            Disposition::Ignore => None,
            Disposition::ExemptIgnoreIp { kind, .. }
            | Disposition::ExemptKnownPeer { kind, .. }
            | Disposition::Block { kind, .. }
            | Disposition::WouldBlock { kind, .. } => Some(kind),
        }
    }

    /// Whether this disposition owes a durable audit row.
    ///
    /// Every judged outcome does. `Ignore` is the only silence, and it is
    /// silence about a source nothing was ever alleged against.
    pub fn is_recordable(&self) -> bool {
        !matches!(self, Disposition::Ignore)
    }
}

impl fmt::Display for Disposition<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Disposition::Ignore => write!(f, "ignore"),
            Disposition::ExemptIgnoreIp { .. } | Disposition::ExemptKnownPeer { .. } => {
                write!(f, "exempt")
            }
            Disposition::Block { .. } => write!(f, "blocked"),
            Disposition::WouldBlock { .. } => write!(f, "would-block"),
        }
    }
}

/// Decide what to do with a judged source.
///
/// Pure: every input that matters is an argument, including the enforcement
/// state, which in the caller comes from whether an XDP program could be
/// attached. That is what makes both sides drivable from a test.
///
/// Precedence is deliberate and matches the order an operator expects: a
/// curated ignore list outranks a learned registration, and both outrank the
/// verdict. Enforcement is consulted last, because whether we *act* must never
/// change whether we *judged*.
pub fn disposition<'a>(
    reason: Option<(&'a str, &'a str)>,
    ignore_rule: Option<&'a str>,
    known_peer: bool,
    enforcing: bool,
) -> Disposition<'a> {
    let Some((kind, detail)) = reason else {
        return Disposition::Ignore;
    };
    if let Some(rule) = ignore_rule {
        return Disposition::ExemptIgnoreIp { kind, detail, rule };
    }
    if known_peer {
        return Disposition::ExemptKnownPeer { kind, detail };
    }
    if enforcing {
        return Disposition::Block { kind, detail };
    }
    // Observing. The judgement stands and is recorded; only the acting stops.
    Disposition::WouldBlock { kind, detail }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INJECTION: Option<(&str, &str)> = Some(("injection", "'"));

    // The defect. Observing is not a reason to forget what was judged: an
    // observe-only run whose whole purpose is collecting labels must produce
    // one for every condemnation, or it collected nothing.
    #[test]
    fn a_condemnation_while_observing_is_recorded_not_discarded() {
        let d = disposition(INJECTION, None, false, false);
        assert_eq!(
            d,
            Disposition::WouldBlock {
                kind: "injection",
                detail: "'"
            },
            "a source condemned under --no-enforce must still be judged aloud"
        );
        assert!(d.is_recordable(), "the judgement owes an audit row");
    }

    // NEGATIVE CONTROL for the fix above. Widening the not-enforcing path is
    // how you silently change the enforcing one; this pins it.
    #[test]
    fn enforcing_still_blocks_and_is_unchanged() {
        assert_eq!(
            disposition(INJECTION, None, false, true),
            Disposition::Block {
                kind: "injection",
                detail: "'"
            }
        );
    }

    // NEGATIVE CONTROL: the fix must not invent a judgement where none was
    // made. An unjudged source stays silent whether or not we are enforcing.
    #[test]
    fn no_reason_is_silent_in_both_enforcement_states() {
        for enforcing in [true, false] {
            let d = disposition(None, None, false, enforcing);
            assert_eq!(d, Disposition::Ignore, "enforcing={enforcing}");
            assert!(
                !d.is_recordable(),
                "silence owes no row (enforcing={enforcing})"
            );
        }
    }

    // Exemption outranks the verdict, and says so. Silence here would hide a
    // compromised trusted peer, which is when it matters most.
    #[test]
    fn the_ignore_list_outranks_the_verdict_and_is_still_reported() {
        let d = disposition(INJECTION, Some("10.0.0.0/8"), false, true);
        assert_eq!(
            d,
            Disposition::ExemptIgnoreIp {
                kind: "injection",
                detail: "'",
                rule: "10.0.0.0/8"
            }
        );
        assert!(d.is_recordable(), "a hard negative is a label, not a shrug");
    }

    // A curated list outranks a learned registration: both exempt, and the
    // operator's own configuration wins the attribution.
    #[test]
    fn the_ignore_list_outranks_a_registered_peer() {
        assert_eq!(
            disposition(INJECTION, Some("10.0.0.0/8"), true, true),
            Disposition::ExemptIgnoreIp {
                kind: "injection",
                detail: "'",
                rule: "10.0.0.0/8"
            }
        );
    }

    // The exemptions must not depend on enforcement. Whether we act cannot
    // change whether we judged -- that conflation is the original defect.
    #[test]
    fn exemptions_do_not_depend_on_enforcement() {
        for enforcing in [true, false] {
            assert_eq!(
                disposition(INJECTION, None, true, enforcing),
                Disposition::ExemptKnownPeer {
                    kind: "injection",
                    detail: "'"
                },
                "enforcing={enforcing}"
            );
        }
    }

    // Every judged outcome owes a row; only true silence does not. This is the
    // property the exporter depends on, so it is pinned here rather than
    // rediscovered there.
    #[test]
    fn every_judged_outcome_is_recordable_and_only_silence_is_not() {
        let judged = [
            disposition(INJECTION, Some("r"), false, true),
            disposition(INJECTION, None, true, true),
            disposition(INJECTION, None, false, true),
            disposition(INJECTION, None, false, false),
        ];
        for d in &judged {
            assert!(d.is_recordable(), "{d:?} owes a row");
            assert!(d.kind().is_some(), "{d:?} must name its rule");
        }
        assert!(!Disposition::Ignore.is_recordable());
        assert!(Disposition::Ignore.kind().is_none());
    }

    // ---- Owed: the invariants that make main.rs's defensive arm dead code. ----
    //
    // `main.rs` matches `Block` and unwraps the enforcer, with an ALARM branch
    // if it is absent. That branch cannot be driven from a test because it is
    // unreachable by construction -- so the construction is what gets tested.
    // Without these, the ALARM is an untested claim about a function nobody
    // pinned.

    #[test]
    fn block_is_returned_only_while_enforcing() {
        // Exhaustive over the inputs that can reach a verdict: no combination
        // with enforcing=false may yield Block.
        for reason in [INJECTION, Some(("scanner", "sipvicious")), None] {
            for rule in [None, Some("10.0.0.0/8")] {
                for known in [true, false] {
                    let d = disposition(reason, rule, known, false);
                    assert!(
                        !matches!(d, Disposition::Block { .. }),
                        "Block while not enforcing: reason={reason:?} rule={rule:?} known={known}"
                    );
                }
            }
        }
    }

    #[test]
    fn would_block_is_returned_only_while_not_enforcing() {
        for reason in [INJECTION, Some(("scanner", "sipvicious")), None] {
            for rule in [None, Some("10.0.0.0/8")] {
                for known in [true, false] {
                    let d = disposition(reason, rule, known, true);
                    assert!(
                        !matches!(d, Disposition::WouldBlock { .. }),
                        "WouldBlock while enforcing: reason={reason:?} rule={rule:?} known={known}"
                    );
                }
            }
        }
    }

    // The pair above is only meaningful if both states are actually reachable;
    // two vacuous truths would also pass. This is that positive control.
    #[test]
    fn both_enforcement_outcomes_are_reachable() {
        assert!(matches!(
            disposition(INJECTION, None, false, true),
            Disposition::Block { .. }
        ));
        assert!(matches!(
            disposition(INJECTION, None, false, false),
            Disposition::WouldBlock { .. }
        ));
    }

    // Enforcement changes only the verdict arm. If it ever alters an exemption
    // or a silence, the "judging is independent of acting" property is gone and
    // the corpus would depend on whether protection happened to be on.
    #[test]
    fn enforcement_changes_only_the_verdict_arm() {
        for reason in [INJECTION, None] {
            for rule in [None, Some("10.0.0.0/8")] {
                for known in [true, false] {
                    let on = disposition(reason, rule, known, true);
                    let off = disposition(reason, rule, known, false);
                    let verdict_arm = matches!(
                        on,
                        Disposition::Block { .. } | Disposition::WouldBlock { .. }
                    );
                    if !verdict_arm {
                        assert_eq!(
                            on, off,
                            "enforcement changed a non-verdict outcome: \
                             reason={reason:?} rule={rule:?} known={known}"
                        );
                    }
                }
            }
        }
    }

    // The verdict names used by the exporter are part of the cross-repository
    // contract; sipnab matches on these strings.
    #[test]
    fn verdict_names_are_the_exported_contract() {
        assert_eq!(
            disposition(INJECTION, None, false, true).to_string(),
            "blocked"
        );
        assert_eq!(
            disposition(INJECTION, None, false, false).to_string(),
            "would-block"
        );
        assert_eq!(
            disposition(INJECTION, Some("r"), false, true).to_string(),
            "exempt"
        );
        assert_eq!(
            disposition(INJECTION, None, true, true).to_string(),
            "exempt"
        );
        assert_eq!(Disposition::Ignore.to_string(), "ignore");
    }
}
