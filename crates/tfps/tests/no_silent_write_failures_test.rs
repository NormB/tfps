// SPDX-License-Identifier: MIT OR Apache-2.0

//! A write that matters must not discard its own failure.
//!
//! # The defect this file exists for
//!
//! `log_block` was written as `let _ = self.conn.execute(...)`, justified as
//! "best effort: a failed audit write must never stop the block it describes".
//! The first half is right and the second does not follow. Not being fatal is
//! not the same as being silent, and the difference is the whole product: this
//! is a tool that is quiet by design, so the only evidence it works is what it
//! writes down. An audit table losing rows to a failure nobody prints is a
//! corpus with holes that read as "nothing happened".
//!
//! `SPEC.md` §12 states it as a rule — silence is an alarm.
//!
//! Three kinds of write are covered, chosen because a silent failure in each
//! makes the tool *misreport itself*:
//!
//! - **Enforcement.** `Enforcer::block` failing while the caller counts the
//!   address as condemned means printing "N addresses condemned" having blocked
//!   none.
//! - **Audit.** A lost row is a label the corpus will never have, and R1's whole
//!   output is labels.
//! - **`meta`.** It carries the APIBAN cursor, which the schema comment already
//!   calls out: losing it "would mean the integration silently protects nothing
//!   after a restart".
//!
//! Cleanup is deliberately *not* covered. `DROP TABLE IF EXISTS` and
//! `remove_dir_all` in a test fixture are allowed to fail; nothing is claimed
//! on their behalf.

/// Lines of a source file, with `let _ =` discards paired to what they discard.
///
/// The call being discarded is often on a following line, so a window is
/// carried rather than matching a single line.
fn discarded_calls(src: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if !line.trim_start().starts_with("let _ =") {
            continue;
        }
        // The window ends at the statement's own semicolon, not after a fixed
        // number of lines. A fixed span reached into whatever followed, so a
        // discarded INSERT sitting above an unrelated `remove_file` was excused
        // as cleanup — the exclusion became an amnesty for anything with a
        // tidy-up call nearby.
        let mut window = String::new();
        for l in &lines[i..] {
            window.push_str(l);
            window.push(' ');
            if l.trim_end().ends_with(");") || l.trim_end().ends_with(';') {
                break;
            }
        }
        out.push((i + 1, window));
    }
    out
}

fn is_cleanup(window: &str) -> bool {
    window.contains("DROP TABLE IF EXISTS")
        || window.contains("remove_dir_all")
        || window.contains("remove_file")
        || window.contains("create_dir_all")
}

#[test]
fn enforcement_failures_are_never_discarded() {
    let src = include_str!("../src/main.rs");
    for (line, window) in discarded_calls(src) {
        assert!(
            !window.contains(".block("),
            "main.rs:{line} discards the result of a block. A refused kernel write that \
             nobody prints means the tool reports sources as condemned having blocked none."
        );
    }
}

#[test]
fn audit_writes_never_discard_their_failure() {
    let src = include_str!("../src/store.rs");
    for (line, window) in discarded_calls(src) {
        if is_cleanup(&window) {
            continue;
        }
        let writes = window.contains("INSERT")
            || window.contains("UPDATE ")
            || window.contains("DELETE FROM");
        assert!(
            !writes,
            "store.rs:{line} discards the result of a write. Not fatal is not the same as \
             silent: a lost row is a label the corpus will never have."
        );
    }
}

/// POSITIVE CONTROL. Two assertions that never look at anything would pass over
/// a file with no `let _` in it at all, or one this scanner cannot parse.
#[test]
fn the_scanner_finds_the_discards_it_is_meant_to_judge() {
    let store = include_str!("../src/store.rs");
    let found = discarded_calls(store);
    assert!(
        !found.is_empty(),
        "no `let _ =` found in store.rs — the scanner is not reading what it thinks it is"
    );
    assert!(
        found.iter().any(|(_, w)| is_cleanup(w)),
        "expected at least one legitimate cleanup discard; if none is found the \
         exclusion is untested and could be hiding a real one"
    );
}

// ---- Owed: my mutation guard reported "gate blind" for a mutation that had
// ---- simply failed to compile. A checker that cannot run looks exactly like
// ---- one that found nothing, so the scanner's own reach is asserted here.

/// The discarded call is usually NOT on the `let _ =` line — it is on the next
/// one. If the window ever collapsed to a single line the gate would still
/// pass, having quietly stopped looking at the multi-line form, which is the
/// form every real one takes.
#[test]
fn the_scanner_sees_a_call_on_a_later_line() {
    let src = "\
fn f() {
    let _ = self.conn.execute(
        \"INSERT INTO block_log (ts) VALUES (1)\",
        params![1],
    );
}";
    let found = discarded_calls(src);
    assert_eq!(found.len(), 1, "the discard itself must be found");
    assert!(
        found[0].1.contains("INSERT"),
        "the window must reach the call being discarded, which sits on a later line; \
         got {:?}",
        found[0].1
    );
}

/// The cleanup exclusion must not be a blanket amnesty. A window that mentions
/// a cleanup call *and* a real write is a real write, and excluding it would
/// let the defect back in beside a `remove_file`.
#[test]
fn the_cleanup_exclusion_does_not_swallow_a_real_write() {
    let mixed = "\
fn f() {
    let _ = self.conn.execute(\"INSERT INTO block_log (ts) VALUES (1)\", params![1]);
    let _ = std::fs::remove_file(&path);
}";
    let found = discarded_calls(mixed);
    let real: Vec<_> = found.iter().filter(|(_, w)| !is_cleanup(w)).collect();
    assert!(
        !real.is_empty(),
        "an INSERT sharing a window with a cleanup call was excluded as cleanup; \
         the exclusion is an amnesty, not a filter"
    );
    assert!(real.iter().any(|(_, w)| w.contains("INSERT")));
}
