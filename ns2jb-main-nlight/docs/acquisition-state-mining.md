# Acquisition state-oracle mining — 2026-10-27 (offline corpus)

Offline analysis of every acquisition report in `runs/` (no console time
spent). Tool: `tools/analysis/mine-acquisition-states.py` (rerun from the
repo root; `--era old|new` splits the cohorts, `--json` for machine output).
Complements the frozen CI report in `docs/acquisition-telemetry-report.md` —
that report's cohort statements remain valid for its frozen 103-run corpus;
everything below is the full-corpus/all-era picture.

## Cohort

- Corpus snapshot 2026-10-27 (a live session was appending during analysis —
  the numbers below are from the snapshot quoted in FINDINGS; re-run the
  miner for fresh counts). 366 runs with outcome logs (304 old-era
  `switchhax`, 62 current-repo era), 12,214 wave cases, 1,498 positive waves
  (452 hit / 804 miss-clean / 234 aborted / 6 other). Current era: 20/62
  runs READY (32%).
- **Corpus hygiene (fixed 2026-10-27):** the acquisition directory also
  stores `reserved-gap-<ts>-native-link-candidate.json` evidence files
  (success path only) which the naive `reserved-gap-*.json` glob matched —
  both analysis tools now filter with `^reserved-gap-[0-9]+\.json$`.
  The pre-fix runs of this miner over-counted "attempts" (one phantom per
  successful run) and its EMPTY-class rescue numbers were inflated by
  those phantoms; every corrected number below is post-fix.

The state fingerprint used throughout is the wave row's full 16-value
`preRelease.memory` counter vector + `preReleaseUsed` + the fixed-order
row-result vector — the same features the frozen report identified as the
within-run determinism signature.

## Findings

### F1 — the state oracle is strong per-attempt, but not a law

Within one acquisition attempt, repeated identical fingerprints:
63 groups / 138 waves, **59 consistent, 4 mixed** — the mixed groups sit
in three runs (two old-era, one current-era: `switch2-U2DIXx`), each
flipping hit↔miss-clean on a byte-identical 16-counter vector. The
counters do not encode the timing margin or the exact slot — the same
state can still flip outcome (~3%).

### F2 — cross-run state transfer is dead

1,498 positive waves collapse to 1,164 distinct states. Only 136 states
(435 waves) repeat across runs. Of those 136 cross-run groups:

| outcome across runs | groups |
|---|---:|
| hit-only | 11 |
| miss-only | 49 |
| **mixed** | **76** (46 of them same-era) |

A majority-vote state table misclassifies **99/435 (23%) of waves
in-sample** — with the table fully populated. Concrete same-era pair:
`switch2-I8sNt8` case 5 (hit) vs `switch2-K2gpdH` case 5 (miss-clean),
byte-identical fingerprints, same code era. Also 42/207 states seen in
READY runs appear in failing runs.

**Verdict: no shippable cross-run known-good/known-bad table. The counters
are usable as a per-boot/per-attempt oracle only.**

### F3 — no pre-positive classifier (reconfirmed at 3.5x scale)

Last pre-positive wave features vs placement pass/fail (223 pass / 139
fail): every univariate AUC lands at 0.501–0.556 (best: `memory[6]` 0.556
current era, `marginUs` 0.525 full corpus). Matches the frozen report's
multivariate 0.520. **Early-abort classification before the first positive
wave stays dead — do not build one.**

### F4 — the preReleaseUsed floor is exact but low-coverage

Across all 441 window-qualified hits, the minimum `preReleaseUsed` is
**9920 — in both eras** (revalidates the frozen-report rule). But a
reject-below-9920 rule catches only 2/804 misses. Keep it as a free
post-wave sanity guard; it is not a recovery lever.

### F5 — positive-wave budget 4 is proven, 6 is overspend

First-hit wave index among the 223 placement-passing attempts:
full corpus `{1: 174, 2: 35, 3: 10, 4: 3, 6: 1}` — a 4-wave budget captures
222/223 (99.6%); current era `{1: 37, 2: 2, 3: 4}` — 3 suffices. The
current 6-attempt budget plus abort-drain waves spends ~2 extra waves per
doomed boot for nothing.

### F6 — same-boot rescue rates by first-attempt fate (phantom-corrected)

Run-level attempt sequences, multi-attempt runs only (single-attempt runs
are excluded — no retry was ever attempted):

| era | attempt-1 fate | rescued | dead | rate |
|---|---|---:|---:|---:|
| old | EMPTY (probe died pre-wave) | 0 | 13 | **0%** |
| old | SETUPFAIL | 7 | 8 | 47% |
| old | **PLACEFAIL (decided miss / budget)** | **0** | **21** | **0%** |
| old | EXTFAIL | — | — | no multi-attempt data |
| new | SETUPFAIL | 4 | 12 | 25% |
| new | EXTFAIL (extent-present qualification) | 3 | 4 | 43% |
| new | **PLACEFAIL (decided miss / budget)** | **0** | **20** | **0%** |

Corrections vs the first-draft numbers: the pre-fix miner counted
`*-native-link-candidate.json` phantoms as EMPTY "attempts", which made
EMPTY-first rescue look like 88–100% — those were successful runs'
evidence files, not attempts. Post-fix, **EMPTY-first rescue is 0/13**
(old era; the current era has no multi-attempt EMPTY-first runs). The
placement-fail class — the one the fail-fast gate covers — is unchanged:
**0/41 across both eras**.

### F9 — the archaeology verdict: no arming regression; the miss wave kills the boot

Method: the run dirs snapshot their own probe/acquire sources, so the
code-eras diff needs no git spelunking. Compared a burn-era old probe
(`runs/switch2-hUomhb/switch2/memory/probe-reserved-gap.cjs`, 1268 lines)
against the current engine (1275): **the failure/retention semantics are
line-identical** — same `placementUncertain` flags gating the same cleanup
skips (probe finally-block lines 1241/1245 in both), same
"Overwrite missed the qualified canary; retain resources for recovery"
throw, same 3-attempt acquire loop (`MAX_ATTEMPTS=3` in the old snapshot).
What actually changed between eras: the old decided-miss path ran a
`locate-canary` diagnostic plus a 6-extent miss-sweep
(`canaryMissSweep`, deltas 1/4/5/6/7/17 — the 410-wave dead dimension
from the frozen telemetry report) before abandoning the boot; the current
probe replaces all of that with the corpus-evidence fail-fast. Same
console death either way — so there is nothing in the cleanup path to
"un-arm"; the boot was lost at the moment of the missed overwrite.

Mechanism, from the 41 attempt-2 death signatures:

| attempt-2 death signature | old | new | interpretation |
|---|---:|---:|---|
| socket hang up (carrier/handler dead) | 7 | 14 | fs wedged — BASIC handler blocked in a native call |
| native batch unjoined / native request timed out | 4 | 6 | fs wedged — workers' fs RPCs never answered |
| silent EMPTY report | 5 | 0 | early setup death (fs not answering) |
| **"Insufficient save space"** | **5** | **0** | **fs ALIVE — deterministic space starvation** |

- **36/41: fs wedged by the miss wave itself.** A placement miss with
  `changedPaths` empty is not a no-op: the ~8.7 KB `'B'`-filled payload
  landed in an *unwatched* fs heap allocation (that is what a miss is),
  corrupting live fs state. The PC cannot repair fs heap it can no longer
  reach — these boots are reboot-only, and the decided-miss fail-fast is
  the correct (and already-implemented) response. Nothing more to mine
  here.
- **5/41 (old era only): fs answered attempt-2 setup and failed the
  deterministic save-space check.** Attempt-1's retained scratch —
  `commit_data` is a 16 MiB file on the save FS, and the
  `placementUncertain` retention skips the `created` scratch deletion —
  starves attempt-2's `free > writeSize + 0x4000` = 20 MiB requirement.
  This class is **PC-side recoverable**: an inter-attempt scratch sweep
  (the existing `cleanup-scratch.cjs` logic, contents-verified, run
  between acquire attempts instead of only at pipeline start) would let
  those boots retry. Whether the class is still live under the current
  probe is unobservable — every new-era dead boot wedges fs first —
  but the sweep is one cheap command either way.

### F7 — the extent-prefix diagnostics prove recoverable geometry, then get discarded

12 current-era attempts failed the fixed-geometry `(extent=prefixEnd=9280)`
extent-present qualification. Their 105 diagnostic waves (five alternative
`prefixEnd` values × 2 trials):

| (selectedMarker, hasWindow) | waves |
|---|---:|
| (true, true) — the full qualification signature at alternative geometry | **84** |
| (false, false) | 20 |
| (false, true) | 1 |

So most "extent-qual-fail" boots are **geometry-dead, not boot-dead**: the
interleaved delivery demonstrably works at some other prefixEnd on the same
boot. The pipeline records this and then fails the attempt anyway
(`report.skipped = 'Negative control did not retain all paths…'`) — no
recovery path consumes the diagnostic result.

### F8 — burn calibration (current era)

Mean waves per attempt: passing ≈ 52 (leak-stage 41 dominates — that is the
working pipeline doing its job), failing ≈ 10.5, of which **2.5/attempt are
the extent-prefix diagnostics** with no consumer (~105 waves across the 42
failing attempts).

## Actions this changes

1. **(APPLIED 2026-10-27)** Drop the extent-prefix wave diagnostics from
   the failing path (F7/F8) — pure observation with no consumer; the cheap
   read-only normalizer-acceptance lookups are kept (input for action 6).
   `engine/switch2/memory/probe-reserved-gap.cjs`.
2. **(DROPPED as unsupported)** Cut the positive-wave budget 6 → 4. The
   all-era corpus has one placement whose first hit landed on positive
   wave 6, and F9 shows doomed boots die at the decided miss rather than in
   the tail waves — a cut below 6 risks a placement for no real saving.
   Budgets stay as-is.
3. **(APPLIED 2026-10-27)** The placement-fail path now stops the launch
   fast, with an explicit reboot-required signal
   (`engine/switch2/acquire.cjs`). Policy-verified against the corpus — see
   the replay section below. The one recoverable subclass (F9's 5/41
   "Insufficient save space" boots — fs alive, scratch-starved) needs no
   new wiring: the next boot's stage-1 orphan sweep (60 s age guard)
   already reclaims the retained 16 MiB scratch, and same-boot retries are
   futile anyway (0/41).
4. **(P2, rescoped, OPEN)** Per-boot steering only (F1/F2): after a miss,
   compare the measured counters against **this attempt's** recorded miss
   states before the next positive wave; identical → spend one cheap
   steering action (a varied-size allocation/free through the reservation
   machinery) instead of re-burning the same wave. Cross-run tables: do not
   build.
5. **(P1, unchanged, OPEN)** Stage-local retry with reset scopes — the
   placed-but-lost runs are the stage-2 loss class. The frozen report's
   projection stands; this mining adds the fail-fast economics of F6.
6. **(research flag, OPEN)** A prefixEnd-adaptive qualification could
   rescue the EXTFAIL class (F7: 84/105 signature waves) — viable but not
   cheap: the positive payload, `markerOffset`, and address-plan geometry
   assume the 9280 layout, so adaptation means re-deriving the placement
   constants. The normalizer-acceptance records (action 1) are its input.
   Design before spending console boots.

## Policy replay — verification of the 2026-10-27 changes

`tools/analysis/replay-acquisition-policy.py` simulates the acquire.cjs
retry policy (acceptance = `memoryControl.ready && !error &&
!cleanupError`; gate = a failed attempt whose report shows ≥1 positive wave
and no `markerSelected`) against every multi-attempt run in the corpus:

| old policy → new policy | runs |
|---|---:|
| success → success | **81** (60 old + 21 new) |
| fail → fail (non-placement classes retried as before) | 146 |
| fail → **reboot-required** (explicit, attempts skipped) | 139 |
| **success → fail** | **0** |

- **Zero success regressions**: every run that ever reached acquisition
  success reaches it identically under the gate.
- **61 provably-futile attempts** (the EMPTY/SETUPFAIL retries after a
  placement failure, corpus-wide) are no longer spawned — each was minutes
  of dead probing on a wedged console.
- The extent-prefix removal is not even policy-relevant: the trials ran
  last in already-failing attempts, consumed by nothing, and their data is
  banked in F7.

Both engine changes are inert to a session that is already running (the
pipeline executes its run-dir source copies, loaded modules stay in
memory); they take effect on the next `session.sh start`. Final verification
run: 366-run corpus snapshot, `node --check` clean on both files, 33/33
existing tests pass, hygiene grep clean.