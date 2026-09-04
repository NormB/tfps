// SPDX-License-Identifier: MIT OR Apache-2.0

//! The kernel and userspace halves of the drop event agree, and the spec
//! describes what the program does.
//!
//! # The defect this file exists for
//!
//! `SPEC.md` §7 said the event goes to the ring buffer before the `XDP_DROP`,
//! and §3 drew it. The program had no ring buffer at all. A document that
//! describes machinery that does not exist is worse than one that says
//! nothing, because it is believed — a reviewer reading the spec would have
//! concluded the sensor could see what it dropped.
//!
//! The C program cannot be compiled or run from `cargo test`: it needs clang
//! with a BPF target, a `vmlinux.h` from the target kernel's BTF, and `CAP_BPF`
//! to load. What CAN be read is its source, and the two facts written twice —
//! the record layout, which userspace parses by offset, and the counter
//! indices — are held to the Rust side here. The program pins its own layout
//! with `_Static_assert`, so a moved field fails the build there and this gate
//! here; neither can drift alone.

use std::path::PathBuf;

use tfps::drops::{offset, window_offset, EVENT_LEN, PREVIEW_LEN, WINDOW_LEN};

fn repo_file(parts: &[&str]) -> String {
    let mut p: PathBuf = [env!("CARGO_MANIFEST_DIR"), "..", ".."].iter().collect();
    for part in parts {
        p.push(part);
    }
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{} must exist: {e}", p.display()))
}

fn xdp_source() -> String {
    repo_file(&["ebpf", "tfps_xdp.c"])
}

fn spec() -> String {
    repo_file(&["SPEC.md"])
}

/// `#define NAME VALUE` — the numeric defines the program is built from. A C
/// integer suffix (`1000000000ULL`) is not part of the number.
fn define(src: &str, name: &str) -> Option<u64> {
    src.lines().find_map(|l| {
        let rest = l.trim().strip_prefix("#define ")?;
        let (n, v) = rest.split_once(char::is_whitespace)?;
        if n != name {
            return None;
        }
        v.split_whitespace()
            .next()?
            .trim_end_matches(['U', 'L', 'u', 'l'])
            .parse()
            .ok()
    })
}

/// `_Static_assert(__builtin_offsetof(struct drop_event, FIELD) == N, ...)`.
fn c_offset(src: &str, field: &str) -> Option<u64> {
    let needle = format!("__builtin_offsetof(struct drop_event, {field}) == ");
    let (_, rest) = src.split_once(&needle)?;
    rest.split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

#[test]
fn every_offset_userspace_reads_is_pinned_in_the_program() {
    let src = xdp_source();
    let fields: [(&str, usize); 9] = [
        ("ts_ns", offset::TS_NS),
        ("drops", offset::DROPS),
        ("src", offset::SRC),
        ("sport", offset::SPORT),
        ("dport", offset::DPORT),
        ("len", offset::LEN),
        ("proto", offset::PROTO),
        ("preview_len", offset::PREVIEW_LEN),
        ("preview", offset::PREVIEW),
    ];
    for (name, rust) in fields {
        let c = c_offset(&src, name).unwrap_or_else(|| {
            panic!("tfps_xdp.c has no _Static_assert for drop_event.{name}; the layout is unpinned")
        });
        assert_eq!(
            c, rust as u64,
            "drop_event.{name}: the program says {c}, userspace reads at {rust}"
        );
    }
}

#[test]
fn the_record_size_and_preview_length_are_one_number_each() {
    let src = xdp_source();
    let (_, rest) = src
        .split_once("_Static_assert(sizeof(struct drop_event) == ")
        .expect("the program must pin sizeof(struct drop_event)");
    let size: usize = rest
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(size, EVENT_LEN, "sizeof(struct drop_event) vs EVENT_LEN");
    assert_eq!(
        define(&src, "DROP_PREVIEW"),
        Some(PREVIEW_LEN as u64),
        "DROP_PREVIEW vs PREVIEW_LEN"
    );
}

#[test]
fn the_counter_indices_match() {
    let src = xdp_source();
    for (name, rust) in [
        ("C_DROPPED", tfps::xdp::C_DROPPED),
        ("C_SEEN", tfps::xdp::C_SEEN),
        ("C_EXPIRED", tfps::xdp::C_EXPIRED),
        ("C_REPORTED", tfps::xdp::C_REPORTED),
        ("C_LOST", tfps::xdp::C_LOST),
    ] {
        assert_eq!(
            define(&src, name),
            Some(u64::from(rust)),
            "{name}: the program and xdp.rs index the counter array differently"
        );
    }
}

#[test]
fn the_maps_userspace_opens_exist_under_those_names() {
    let src = xdp_source();
    for (name, kind) in [
        (tfps::xdp::DROP_EVENTS_MAP, "BPF_MAP_TYPE_RINGBUF"),
        (tfps::xdp::DROP_WINDOWS_MAP, "BPF_MAP_TYPE_LRU_HASH"),
    ] {
        let decl = format!("}} {name} SEC(\".maps\");");
        let Some((before, _)) = src.split_once(&decl) else {
            panic!("no map called `{name}` in tfps_xdp.c; userspace opens it by that name")
        };
        // The map type is in the struct body that ends at the declaration.
        let body = before.rsplit_once("struct {").map_or("", |(_, b)| b);
        assert!(
            body.contains(kind),
            "`{name}` is not a {kind}; userspace would fail to open it as one"
        );
    }
}

/// SPEC §7: the event goes to the ring buffer BEFORE the `XDP_DROP`. The
/// textual order inside the filter is the claim, checked.
#[test]
fn the_event_is_emitted_before_the_drop() {
    let src = xdp_source();
    let body = src
        .split_once("int tfps_filter(struct xdp_md *ctx)")
        .expect("the XDP program must still be called tfps_filter")
        .1;
    let drops: Vec<usize> = body
        .match_indices("return XDP_DROP;")
        .map(|(i, _)| i)
        .collect();
    // POSITIVE CONTROL: with no drop at all the ordering claim would be vacuous.
    assert_eq!(
        drops.len(),
        1,
        "tfps_filter should drop in exactly one place"
    );
    let emit = body
        .find("report_drop(")
        .expect("tfps_filter never calls report_drop: what it drops is invisible");
    assert!(
        emit < drops[0],
        "report_drop is called after the return; the event is never reached"
    );
    assert!(
        src.contains("bpf_ringbuf_reserve(") && src.contains("bpf_ringbuf_submit("),
        "report_drop must actually write to the ring buffer"
    );
}

/// The flood cost is bounded by sampling, and the numbers the spec quotes are
/// the numbers the program is built from. Prose that describes a policy the
/// code does not implement is exactly the drift this file was written for.
#[test]
fn the_sampling_policy_in_the_spec_is_the_one_in_the_program() {
    let src = xdp_source();
    let per_window = define(&src, "DROP_REPORTS_PER_WINDOW")
        .expect("the program must define DROP_REPORTS_PER_WINDOW");
    let window_ns = define(&src, "DROP_WINDOW_NS").expect("the program must define DROP_WINDOW_NS");
    assert!(per_window > 0, "a cap of zero reports nothing");
    assert_eq!(
        window_ns, 1_000_000_000,
        "the spec describes the window in seconds"
    );
    let spec = spec();
    let phrase = format!("first {per_window} drops");
    assert!(
        spec.contains(&phrase),
        "SPEC.md must state the sampling cap as `{phrase}` so the document matches the code"
    );
    assert!(
        !spec.contains("ring buffer (always, even when dropped)"),
        "SPEC.md §3 still says every dropped packet is reported; they are sampled"
    );
}

/// The second layout userspace reads by offset: the per-source window map,
/// whose `drops` field completes the count the sampled events stop short of.
#[test]
fn the_window_layout_is_pinned_too() {
    let src = xdp_source();
    let (_, rest) = src
        .split_once("_Static_assert(sizeof(struct drop_window) == ")
        .expect("the program must pin sizeof(struct drop_window)");
    let size: usize = rest
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(size, WINDOW_LEN, "sizeof(struct drop_window) vs WINDOW_LEN");
    let needle = "__builtin_offsetof(struct drop_window, drops) == ";
    let (_, rest) = src
        .split_once(needle)
        .expect("the program must pin drop_window.drops; userspace reads it by offset");
    let c: usize = rest
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        c,
        window_offset::DROPS,
        "drop_window.drops: the program says {c}, userspace reads at {}",
        window_offset::DROPS
    );
}
