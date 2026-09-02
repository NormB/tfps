# R1 — Export the TFPS ban log as sipnab's labeled corpus

*Design, 2026-09-02. Implements R1 of the cross-project review "The Enforcement
Seam" (31 August 2026).*

## 1. The problem

sipnab's `docs/design/threat-mitigation-hooks.md` §7 names one missing artifact
as the prerequisite for every automated-response decision it has deferred:

> A labeled corpus — real traffic with known scanners marked — measured for both
> false-positive and false-negative rate against a candidate signature.

sipnab cannot build that alone. Nothing in a capture says which source was
actually hostile. TFPS decides exactly that, continuously, and today it keeps
only part of the answer and throws the rest away.

R1 makes TFPS record what it decides, export it, and gives sipnab a harness that
scores `scanner_detect` against those labels.

## 2. What was found in the code, before designing

Five facts, each read this session, that differ from the review's sketch:

1. **`tfps_ctl log` already exists.** It prints a human table from `block_log`.
   The work is a `--json` mode, not a new command.
2. **`block_log` is `(ts, ip, reason, detail)`.** There is no `expires` and no
   `unbanned_at`. The export shape R1 asks for cannot be produced from what is
   stored.
3. **`unban` writes nothing durable.** `crates/tfps/src/bin/tfps_ctl.rs`
   removes the kernel map entry and prints a line. The operator unban — the
   human negative label, and SPEC §12's precision proxy — is not recorded
   anywhere.
4. **The `--no-enforce` defect is real.** The decision chain is three arms with
   no `else`, and the third is guarded on `enforcer.as_mut()`. With enforcement
   off, a condemnation is computed and discarded: no line, no row.
5. **APIBAN never reaches `block_log`.** The feed loop calls `e.block(ip, 0)`
   and no `log_block`. This matters: it structurally excludes the review's own
   §6 falsification that the corpus would score reputation rather than
   behaviour. Under `--no-enforce` the APIBAN drain is itself gated on
   `enforcer.as_mut()` and does not run at all.

## 3. Scope

**In:** the `--no-enforce` fix; durable records for condemnations, exemptions
and unbans; a JSON export; a sipnab test that scores against it; deployment to
opensips-1 in observe-only mode.

**Out:** R2 (ring buffer, HEP forwarding), R3 (sipnab depending on tfps-core),
R4 (sipnab emitting evidence for TFPS to act on). R4 in particular must not be
built before R1 has measured, which is the whole point of the ordering.

**Repository rule:** every TFPS change lands on a branch of
`github.com/NormB/tfps`. Nothing goes to `sippulse/tfps`.

**Standing constraint:** TFPS is optional operator-installed software, in the
same category as rtpengine, rtpproxy, Asterisk, OpenSIPS and Kamailio. A system
might have them or might not. sipnab never carries a hard requirement on any of
them. See §6.1.

## 4. Labels

Three verdicts, deliberately chosen; a fourth was rejected.

| Verdict | Meaning | Source |
|---|---|---|
| `blocked` | condemned and enforced | `block_log`, `enforced = 1` |
| `would-block` | condemned under `--no-enforce` | `block_log`, `enforced = 0` |
| `exempt` | tripped a rule, trusted anyway | `exempt_log` |

`exempt` is the **hard negative** and the most valuable label in the set: a
source that looked hostile and demonstrably was not. It comes from the two arms
that already compute the decision and only print it.

An operator unban attaches `unbanned_at` to a `blocked` row. That is the **gold
negative** — a human saying the machine was wrong.

**Rejected: implicit negatives** ("seen, never condemned"). Plentiful and cheap,
but "not yet condemned" is not "benign", so a scanner TFPS missed would be
recorded as a negative and would flatter sipnab's false-positive rate in exactly
the case worth catching.

## 5. TFPS changes

### 5.1 The `--no-enforce` fix (own commit, lands first)

A fourth arm on the chain in `crates/tfps/src/main.rs`: reason present, no
exemption matched, no enforcer → emit `WOULD BLOCK peer=… reason=… detail=…`
and write a `block_log` row with `enforced = 0`.

This is a live defect independent of R1. Today the tool reports the peers it
*declined* to ban and stays silent about the ones it *would* have — backwards,
and contrary to SPEC §12's rule that silence is an alarm. It lands on its own
merits whether or not the rest proceeds, and it is R1 Mode A's only blocker.

### 5.2 Schema

`block_log` gains `enforced INTEGER NOT NULL DEFAULT 1` and `expires INTEGER`
(`ts + ttl`; 0 means forever, matching the APIBAN convention). Two new tables:

    exempt_log (ts, ip, reason, detail, rule)
    unban_log  (ts, ip, actor)

`rule` on `exempt_log` distinguishes an `ignoreip` match from a registered peer,
because they are different strengths of evidence. Schema version bumps; an
existing database upgrades in place.

### 5.3 `tfps_ctl unban` becomes a writer

The store is opened read-write. Ordering matters and is deliberate: **remove
from the kernel map first** — that is the operator's actual intent and the
authoritative half — then write `unban_log`. If the write fails, say so loudly.
A silent failure here loses the highest-quality label in the corpus.

Unbanning an address that was not blocked writes **nothing**. Recording it would
manufacture a negative label for a source that was never accused.

### 5.4 `tfps_ctl log --json`

JSON Lines, one object per source-decision, joining the three tables:

    {"ip","rule","detail","first_seen","expires","unbanned_at","enforced","verdict"}

Absent values are `null`, not omitted, so a consumer distinguishes "no unban"
from "field missing".

### 5.5 Field semantics

Pinned here because each was ambiguous on first writing, and a consumer in
another repository cannot ask.

- **Grain: one object per condemnation event, not per source.** A source
  condemned three times produces three objects. Collapsing to one would discard
  the repeat behaviour that distinguishes a persistent scanner from a single
  probe, which is the thing the corpus exists to measure.
- **`first_seen`** — the `ts` of *this* event, as a Unix timestamp in UTC. It is
  named for the review's shape; it is the moment this decision was reached, not
  the first time the address was ever observed. A per-source first sighting
  lives in the learned-sources state and is deliberately not joined in: it moves
  independently of any decision.
- **`expires`** — absolute Unix timestamp at which the block lapses, computed
  `ts + ttl` at write time. **0 means never.** `null` means the event was not a
  block (`exempt`, or `would-block` under observe-only, where no TTL exists).
- **`unbanned_at`** — Unix timestamp of the operator unban, or `null`. Present
  only on `blocked` events.
- **`actor`** on `unban_log` — who lifted the block: the literal string
  `operator` for `tfps_ctl unban`, reserved for distinguishing a future
  automatic or TTL-driven lift. The corpus counts only `operator` rows as gold
  negatives, because a TTL expiring is not a human saying the machine was wrong.
- **`rule`** — the condemnation rule for a positive (`scanner`, `injection`,
  `user-agent`, `auth-failed`, `reg-scan`, `auth-volume`), and the exemption
  source for an `exempt` event.

### 5.6 Where the golden fixture lives

`tests/fixtures/tfps-labels-golden.jsonl` in **both** repositories, byte for
byte. Synthetic addresses from the documentation ranges of RFC 5737
(`192.0.2.0/24`, `198.51.100.0/24`), so it carries no PII and both repositories
can commit it. It covers all three verdicts, a `null` and a non-`null`
`unbanned_at`, and an `expires` of 0.

A gate on each side compares its own copy against the shape it must handle: TFPS
that its exporter emits exactly this, sipnab that its reader accepts exactly
this. If the two copies ever differ, both gates cannot pass.

## 6. sipnab changes

`tests/tfps_label_corpus_test.rs`, modelled on the existing
`scanner_signature_corpus_test.rs`, which already replays a real corpus and
scores behavioural alerts against an oracle derived *from the packets*. R1 adds
a second, **external** oracle.

- Gated on `SIPNAB_CORPUS` (existing, `src/capture/input_set.rs`) plus
  `TFPS_LABELS`. Unset, it skips, as its sibling does.
- Drives `ScannerDetector` as a library. No new binary surface.
- Reports recall, false positives, agreement, **and the rule breakdown** — the
  last as a first-class output, so the review's §6 falsification check fires
  automatically rather than depending on someone remembering to run it.
- Prints counts, filenames and rule names only. Never an address, Call-ID, user
  part or branch. The corpus is assumed to contain PII and is never committed.

### 6.1 TFPS is optional operator-installed software

**TFPS is a package an operator may or may not have installed. It is in exactly
the same category as rtpengine, rtpproxy, Asterisk, OpenSIPS and Kamailio: other
people's projects that may be on the system, and may not. sipnab must never
carry a hard requirement on any of them.**

sipnab already has the pattern and R1 follows it rather than inventing one.
`--rtpengine-control` is an `Option<String>` (`src/cli.rs:1490`) and every
consumer is an `if let Some(...)` (`src/app/bootstrap.rs:637`,
`src/app/batch.rs:2201`). When the operator does not name a relay, the
capability simply does not engage. There is no error, no warning, no degraded
mode, and nothing in the build changes.

TFPS labels are read the same way: **only when the operator points sipnab at
them.** Absence is the default and the normal case, not a failure.

Concretely:

- **No `tfps` or `tfps-core` entry in sipnab's manifest.** sipnab has no
  reference to tfps anywhere today, and R1 does not introduce the first. The
  label file is parsed structurally with `serde_json`, already a dependency.
- **No feature flag, no build-time coupling.** An absent TFPS is not a
  compile-time or configuration state; it is simply an input nobody supplied.
- **The interface is a documented JSON contract, not a shared Rust type.** A
  shared crate would make one project's release cadence the other's problem —
  precisely the coupling the rtpengine handling avoids.

The cost of that independence is one format with two implementations, which
drift. A gate that reads one copy of a fact written twice certifies only half of
it. So the contract is pinned by the golden fixture of §5.6, byte-identical in
both repositories, with each side gating on its own copy.

**The tested behaviour is that absence is normal:** sipnab's full suite passes
with no TFPS installed, no labels present and no configuration mentioning it —
which is the default state in CI and on every machine that never installs it.
The corpus test skips exactly as its sibling `scanner_signature_corpus_test.rs`
does when `SIPNAB_CORPUS` is unset.

## 7. Deployment — opensips-1 (carbon VM 140)

Measured this session: Debian 13, kernel 6.12.105, `eth0` on `virtio_net`,
OpenSIPS live on 10.0.0.40:5060 with 13 workers, 1.4 GB free, 4 CPUs. `clang`
present, `bpftool` absent.

The host is publicly exposed and takes real scanner traffic — a SIPVicious
OPTIONS probe from 198.244.200.163 appears in the journal. Over seven days:
**82 distinct public source IPs, 748 SIP requests**.

Observe-only attaches no XDP program, so neither `virtio_net`'s XDP support nor
the missing `bpftool` blocks collection.

At roughly 12 new sources a day, **collect 2–3 weeks before scoring**. One week
yields too few labels to separate a signature from noise.

## 8. Testing

TDD/BDD throughout: the behaviour is written as a scenario first, run against
the unfixed tree, and **watched fail for the right reason** — not because a
fixture is wrong — before any implementation.

Per change, with its negative control:

| Change | Scenario | Negative control |
|---|---|---|
| 5.1 no-enforce arm | condemnation under `--no-enforce` writes a row and prints a line | enforced path still writes exactly one row, not two |
| 5.2 schema | an existing database upgrades in place | pre-existing rows keep `enforced = 1` |
| 5.3 unban writer | unban of a blocked IP writes `unban_log` | unban of an unblocked IP writes nothing |
| 5.4 export | join produces all three verdicts | absent values are `null`, not missing |
| 6 harness | scoring math against synthetic labels | skips cleanly when `TFPS_LABELS` is unset |
| 6.1 absence is normal | sipnab's full suite passes with no TFPS installed, no labels, no config naming it | the manifest gate fails if a `tfps`/`tfps-core` dependency is ever added |

Every new gate is mutation-tested: break what it guards, confirm red, restore,
and prove the restore with `cmp -s` against a pre-mutation copy.

## 9. Sequencing

1. §5.1 alone, as its own commit.
2. §5.2–5.4 with tests.
3. Deploy to opensips-1, observe-only. Collect.
4. §6 harness, against the golden fixture first, then the real corpus.
5. Score. Only then is R4 discussable.

## 10. What would make this wrong

From the review's §6, with what is now known:

- **Reputation, not behaviour.** Structurally excluded: APIBAN never writes to
  `block_log` (§2.5). The harness reports the rule breakdown anyway, so the
  claim is checked rather than assumed.
- **Too thin to discriminate.** 82 sources a week is real but small. If three
  weeks of collection cannot separate the signature, the honest answer is to say
  so rather than to report a rate with no power behind it.
- **Mode B's joins mostly miss.** Not reachable in Mode A, where both tools tap
  one interface on one clock and labels join on the address exactly. Deferred
  with R2(a), and the harness keeps the join behind a seam so adding it does not
  restructure anything.
