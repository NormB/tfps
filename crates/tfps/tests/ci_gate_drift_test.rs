// SPDX-License-Identifier: MIT OR Apache-2.0

//! The CI gate must keep running the checks it was added for.
//!
//! # The defect this file exists for
//!
//! This repository had no CI at all, so `cargo fmt`, `clippy` and the tests
//! were enforced only by whoever happened to run them. Adding the workflow is
//! half the repair; the other half is that a workflow can be quietly weakened
//! later — dropping `-D warnings`, or narrowing `--workspace` to one crate —
//! and nothing would notice, because a weakened gate still shows a green tick.
//!
//! So the gate's own contents are asserted here. A test is the only thing that
//! fails loudly when a check is removed.

use std::path::PathBuf;

fn workflow() -> String {
    // CARGO_MANIFEST_DIR is crates/tfps; the workflow lives at the repo root.
    let p: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "..",
        "..",
        ".github",
        "workflows",
        "ci.yml",
    ]
    .iter()
    .collect();
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("the CI workflow must exist at {}: {e}", p.display()))
}

#[test]
fn the_gate_checks_formatting() {
    assert!(
        workflow().contains("cargo fmt --all --check"),
        "CI must check formatting: an unformatted tree reached a commit once already"
    );
}

#[test]
fn clippy_runs_over_every_target_and_denies_warnings() {
    let w = workflow();
    assert!(
        w.contains("cargo clippy --workspace --all-targets -- -D warnings"),
        "CI must deny clippy warnings across all targets; a narrowed clippy is a green gate \
         that checks less than the local one"
    );
}

#[test]
fn the_tests_run_over_the_whole_workspace() {
    assert!(
        workflow().contains("cargo test --workspace"),
        "CI must run the whole workspace: tfps-core holds the decision logic and its tests"
    );
}

/// POSITIVE CONTROL: without this, three assertions over an empty or missing
/// file would be a vacuous pass in the exact case worth catching.
#[test]
fn the_workflow_is_not_empty() {
    let w = workflow();
    assert!(
        w.len() > 200,
        "the workflow is suspiciously small: {} bytes",
        w.len()
    );
    assert!(
        w.contains("runs-on:"),
        "a workflow with no job runs nothing"
    );
}

/// The gate above checks that the workflow *says* the right commands. It does
/// not check that GitHub will run the file at all.
///
/// # The defect this exists for
///
/// Found by mutation, not by review: replacing `name: CI` with an unknown
/// top-level key left every command string intact, so all four assertions
/// passed — over a workflow GitHub would reject outright. A green gate
/// guarding a workflow that never executes is worse than no gate, because it
/// is believed.
///
/// A full YAML parse would need a dependency this workspace does not carry, so
/// the structural claim is made directly: the top-level keys must all be ones
/// GitHub defines for a workflow, and the ones that make it run must be there.
#[test]
fn the_workflow_has_only_keys_github_will_accept() {
    // Everything GitHub allows at the top level of a workflow file.
    const ALLOWED: &[&str] = &[
        "name",
        "on",
        "permissions",
        "env",
        "defaults",
        "concurrency",
        "jobs",
        "run-name",
    ];
    let w = workflow();
    let keys: Vec<String> = w
        .lines()
        .filter(|l| !l.starts_with(char::is_whitespace) && !l.trim_start().starts_with('#'))
        .filter_map(|l| l.split_once(':').map(|(k, _)| k.trim().to_string()))
        .filter(|k| !k.is_empty())
        .collect();

    assert!(
        !keys.is_empty(),
        "no top-level keys found — is this a workflow at all?"
    );
    for k in &keys {
        assert!(
            ALLOWED.contains(&k.as_str()),
            "unknown top-level key {k:?}: GitHub would refuse this workflow, and every \
             command assertion would still pass over a file that never runs"
        );
    }
    // The two that decide whether it runs at all.
    for required in ["on", "jobs"] {
        assert!(
            keys.iter().any(|k| k == required),
            "the workflow has no {required:?} key, so nothing triggers or executes"
        );
    }
}
