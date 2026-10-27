# CI reliability report

## Scope and cohort

I froze the corpus at the task-start snapshot because a new run appeared during analysis.

- 103 runs had `acquisition.log`, `run.log`, and a primary `reserved-gap-<timestamp>.json`.
- 21 connection-only directories had no usable telemetry and are excluded.
- 3,172 wave cases were analyzed.
- No pipeline source under `engine/` was read.

The observed end-to-end pass rate is **11/103 = 10.68%**.

## 1. Funnel

| Outcome | Runs | Per 100 | Conditional rate |
|---|---:|---:|---:|
| Did not reach a `markerSelected` decision | 11 | 10.68 | — |
| `markerSelected:false` | 37 | 35.92 | 37/92 = 40.22% of runs reaching placement |
| `markerSelected:true` | 55 | 53.40 | 55/92 = 59.78% |
| Failed later in stage 2 after placement | 36 | 34.95 | 36/55 = 65.45% |
| Completed stage 2 | 19 | 18.45 | 19/55 = 34.55% |
| Failed in stage 3 | 8 | 7.77 | 8/19 = 42.11% |
| Failed in stage 4 | 0 | 0.00 | 0/11 |
| `SESSION READY` | 11 | 10.68 | 11/19 = 57.89% after stage 2 |

### Loss attribution

Run-specific `Inspect /…` paths are normalized below; error text is otherwise preserved.

Before placement, 11 losses:

- 6: `Error: FS acquisition did not complete.`
  - Five completed with `qualifiedReadSize:null` after the extent-prefix work.
  - One had `skipped:"Negative control did not retain all paths in the required order"`.
- 1: `Error: Two packets share a staging page`
- 1: `Error: Packet is outside its staging page`
- 1: `Error: Canary variant creation failed: /NS2_GAP_1792754332488/canary2/A`
- 1: `Error: Marker directory re-creation failed: 0x402`
- 1: `TypeError: Cannot convert undefined to a BigInt`

Placement failures, 37:

- 25: `Error: Overwrite missed the qualified canary; retain resources for recovery`
- 10: `Error: Positive wave budget (10) exhausted without a canary selection; retain resources for recovery`
- 1: `Error: A protected request ended during the overwrite; retain resources for recovery`
- 1: `Error: Console response timed out; restart the application`

Post-placement stage-2 failures, 36:

- 8: `Error: The bounded native leak contains no qualified, encodable link candidate`
- 7: `Error: Native request timed out; it was not replayed`
- 6: `Error: General-heap allocation changed while the cache was retained; stop overwrites and recover`
- 3: `Error: The owned cache alias did not survive address preparation`
- 3: `Error: Console response timed out; restart the application`
- 2: `Error: Clean alias did not qualify within its attempt limit`
- 1 each:
  - `Error: A protected request ended during the overwrite; retain resources for recovery`
  - `Error: Field copy did not qualify within its attempt limit: retire-address-entry`
  - `Error: Field copy did not qualify within its attempt limit: address-header-40`
  - `Error: Combined acquisition needs a qualified native over-read`
  - `Error: Neighbor invalidation changed general-heap geometry`
  - `Error: The planned bucket period did not qualify on this candidate`
  - `TypeError: Cannot read properties of undefined (reading 'length')`

Stage-3 failures, 8:

- 4: `Error: find-metadata failed.`
- 1: `Error: install-retained failed.`
- 1: `Error: Existing /main differs; restart the application to clear its temporary volume`
- 1: `Error: Invalid filesystem path`
- 1: no terminal error; the log stops after `ro/test-gate`

All 11 runs entering stage 4 reached `SESSION READY`. Eight later logged `Console connection is no longer available`, but that occurred after the explicit success marker and should not retroactively fail CI qualification.

## 2. Placement and parameter search

A positive-wave hit was identified by the canary-changing record (`changedPaths:["canary"]`, `canaryType:0`). The per-wave `selectedMarker` field was false in all 646 positive waves, so the authoritative placement result is the top-level `markerSelected`/`markerReproduced` state.

### First observed hit in the 55 passing runs

| First positive-wave hit | Runs |
|---|---:|
| Wave 1 | 47 |
| Wave 2 | 6 |
| Wave 3 | 2 |

The full hit/miss patterns were:

- 41: hit, hit
- 6: hit, miss, hit
- 6: miss, hit, hit
- 2: miss, miss, hit, hit

All 55 had `markerReproduced:true`, yielding 110 hit waves. Therefore, the literal assertion that success is always observable at the first positive wave is not supported: **8/55 successes first became observable on wave 2 or 3**.

A first-wave miss occurred in 45 runs: 8 subsequently passed and 37 failed. Thus a hard abort after the first miss would discard **8/55 = 14.55% of successful placements**.

### Nothing later succeeds in failing runs

Across the 37 placement failures:

- 520 positive waves were executed.
- Zero later waves changed the canary or selected the marker.
- 30 `locate-canary` cases also produced zero hits.
- 32 runs recorded 141 `canaryMissSweep` entries:
  - 141/141 had `hit:false`.
  - 139 had no changed paths.
  - Two changed only `filler0`, never the canary.

### Extent sweep

Every success occurred at:

```text
extent = 9280
prefixEnd = 9280
```

The swept alternatives produced:

| Extent | Positive waves | Hits |
|---:|---:|---:|
| 9281 | 91 | 0 |
| 9284 | 89 | 0 |
| 9285 | 63 | 0 |
| 9286 | 58 | 0 |
| 9287 | 57 | 0 |
| 9297 | 52 | 0 |
| **Total** | **410** | **0** |

The extent sweep has no demonstrated placement value in this corpus.

### Reproducibility and better search axes

Using only the programmed `(extent,prefixEnd)` pair, repeated positive-wave groups were not completely deterministic:

- 239 repeated within-run groups.
- 14 groups had mixed hit/miss results, all at `(9280,9280)`.

Adding `preReleaseUsed` and the row-result vector reduced this to one mixed group among 92 repeated groups. Adding the full 16-value `preRelease.memory` vector yielded 14 exactly repeated within-run state groups and **zero mixed outcomes**.

The row-result vector itself cannot guide search: all 646 positive waves had exactly:

```text
commit=0, hole=0,
tail0..tail3=3276802,
canary=0,
guard0=guard1=514
```

`preReleaseUsed` is somewhat more useful as a rejection signal:

- At the default extent, all 25 waves with `preReleaseUsed < 9920` missed.
- Common values still strongly overlapped:
  - 10480: 41 hits / 85 waves
  - 10368: 29/56
  - 10592: 12/18

Conclusion: keep `extent=prefixEnd=9280`. Search by rerolling the heap/layout state—fresh setup, allocation shaping, or reordered preparation that changes `preReleaseUsed` and the memory counters—rather than incrementing extent. Low `preReleaseUsed` can reject a wave, but no observed value guarantees success.

## 3. Predictability before the first positive wave

The prediction cohort is 92 runs: 55 later passing and 37 later failing placement. The 11 pre-placement failures are excluded because they never supplied a first positive wave.

AUC below uses 0.5 as chance and 1.0 as perfect separation.

### Last negative-wave telemetry

Ten of the 16 `preRelease.memory` counters—indices 1, 2, 4, 7, 8, and 11–15—were identically zero in both groups. The six varying counters all overlapped:

| Observable | Pass range | Fail range | Cohen’s d | Best-direction AUC |
|---|---:|---:|---:|---:|
| `memory[0]` | 20,541,440–22,294,528 | 20,541,440–22,450,176 | -0.19 | 0.538 |
| `memory[3]` | 16,384–737,280 | 16,384–720,896 | -0.30 | 0.585 |
| `memory[5]` | 3,751,696–3,784,656 | 3,751,808–3,784,704 | -0.06 | 0.512 |
| `memory[6]` | 6,328,128–6,328,256 | 6,328,128–6,328,256 | -0.06 | 0.504 |
| `memory[9]` | 32,522,240–32,620,544 | 32,522,240–32,604,160 | -0.03 | 0.503 |
| `memory[10]` | 0–16 | 0–16 | -0.12 | 0.522 |
| `preReleaseUsed` | 10,144–43,104 | 10,096–42,992 | +0.06 | 0.512 |
| `receiveOrderMarginUs` | 562–3,452 | 617–3,277 | +0.36 | 0.614 |

The strongest univariate result found anywhere in the enumerated pre-positive telemetry was the last abort-control `memory[9]`:

- AUC: 0.641
- Cohen’s d: -0.51
- Pass range: 32,161,792–32,702,464
- Fail range: 32,194,560–32,702,464
- Range overlap: 93.9%
- Fifteen exact values occurred in both classes

This is association, not a usable separator.

### Row results and reservation checks

All 516 pre-positive control/negative/extent waves had the same relevant result-code vector in both classes:

```text
commit=0, hole=0,
tail0..tail3=3276802,
canary=0,
guard0=guard1=514
```

Reservation checks were likewise non-separating:

- 51/55 passing runs had no anomalous pre-positive reservation check.
- 35/37 failing runs had no anomaly.
- Anomalies occurred in 4 passing and 2 failing runs.
- Retry/profile counts overlapped across both classes.

### Multivariate result

A 21-feature regularized model using the last-negative counters, timing, pre-release usage, prior-wave counts, and reservation summaries was evaluated with repeated nested stratified cross-validation:

- Mean held-out AUC: **0.520**
- Mean balanced accuracy: **0.507**
- Mean ordinary accuracy: 55.4%, below the 59.8% “always predict pass” class baseline

A richer 54-feature model overfit the training data but fell to held-out AUC 0.454.

Therefore, **no pre-first-positive early-abort classifier is supported by this corpus**. Before the first positive wave, retry/abort decisions would be effectively random. After a miss is observed, redirecting work from the zero-yield extent sweep to a fresh layout reroll is justified.

## 4. Drift

Six reports contained `heapDrift`:

| `heapDrift.difference` | Count | Distance from -32736 |
|---:|---:|---:|
| -32736 | 2 | 0 |
| -17056 | 1 | 15,680 |
| -704 | 2 | 32,032 |
| -176 | 1 | 32,560 |

Thus exactly `-32736` accounts for **2/6 heap-drift failures**, not a universal signature.

There were 10 `restored:false` cases among 3,172 cases, spanning 9 runs:

| `after - baseline` | Count | Distance from -32736 |
|---:|---:|---:|
| -32736 | 4 | 0 |
| -17056 | 1 | 15,680 |
| -704 | 3 | 32,032 |
| -688 | 1 | 32,048 |
| -176 | 1 | 32,560 |

The six `heapDrift` records are included in these ten. The remaining four restore failures occurred in two positive waves, one `locate-canary` wave, and one `extent-present` wave.

## 5. Runs with no acquisition error and metadata dead-ends

Exactly **25/103** acquisition logs contained no error.

| Final state from `run.log` | Count |
|---|---:|
| `SESSION READY` | 11 |
| `Error: FS acquisition did not complete.` | 6 |
| `Error: find-metadata failed.` | 4 |
| `Error: install-retained failed.` | 1 |
| `Error: Existing /main differs; …` | 1 |
| `Error: Invalid filesystem path` | 1 |
| No terminal line; stops after `ro/test-gate` | 1 |

### `find-metadata` failures

| Run | Attempts | Captures per attempt | Hypotheses | `maxCaptures` | `expansionSteps` |
|---|---:|---:|---:|---:|---:|
| `switch2-LA7uFJ` | 1 | 108 | 109 | 205 | 0/not recorded |
| `switch2-OqLJMm` | 3 | 159, 159, 159 | 160 each | 205 | 0/not recorded |
| `switch2-TGMl0q` | 3 | 199, 199, 199 | 204 each | 205 | 4 each |
| `switch2-lhH7nr` | 3 | 159, 159, 159 | 160 each | 205 | 0/not recorded |

Every attempt ended with:

```text
Error: The shared pool range has no further uncaptured buckets
```

The search did not generally hit the numeric `maxCaptures=205`; it exhausted the available uncaptured buckets at 108, 159, or 199 captures. The three retries in each of OqLJMm, TGMl0q, and lhH7nr revisited the same seed/candidate interval and reproduced the same capture/hypothesis counts. Observed-link counts varied, but no new bucket became available.

Successful metadata searches in this cohort used 0–161 captures, so a simple “capture count too high” threshold is not valid. The dead-end is candidate-space coverage: retries must change seed/range/expansion geometry or preserve and extend prior captures. Merely rerunning or raising `maxCaptures` without making new buckets addressable is unlikely to help.

## 6. Ranked pipeline changes

The projections below use empirical stage rates and assume state-changing attempts are approximately independent. They are planning estimates, not guarantees; the deterministic same-state metadata retries show why reinitialization matters.

1. **Add a stage-local retry controller with total-attempt budgets of 8 placement / 13 post-placement stage 2 / 7 stage 3.** Empirical rates are 55/103, 19/55, and 11/19 respectively. The projected combined success is:

   ```text
   [1-(1-55/103)^8] × [1-(1-19/55)^13] × [1-(1-11/19)^7]
   = 99.14%
   ```

   That is a projected gain of **+88.46 percentage points** over 10.68%. If checkpointing is impossible, the cruder fallback is 41 independent full launches, projected at 99.03%.

2. **Checkpoint after marker selection and retry stage-2 sub-stages at the correct reset scope.** Stage 2 loses 36/55 selected-marker runs. Thirteen state-changing stage-2 attempts project to 99.60% stage-2 survival and, holding other stages constant, about **30.79% end-to-end**, a **+20.11-point** gain.

   Classification should be:

   - Same-stage/new-candidate retry: eight bounded-native-leak, two clean-alias, two field-copy, one bucket-period, one combined-over-read failures.
   - Transport/application retry: seven native timeouts, three console timeouts, one protected-request termination.
   - Restart from placement: six heap drifts, three lost aliases, one neighbor-geometry change.
   - Fatal build defect: the single `TypeError`.

3. **Replace the extent sweep with fresh-layout retries at `(9280,9280)`.** The current alternative extents cost 410 waves for zero hits. Eight total fresh placement attempts project to 99.78% placement success; holding later-stage behavior constant gives **19.96% end-to-end**, **+9.28 points**. Do not pre-wave early-abort; after a default-wave miss, reroll heap/layout state rather than extent.

4. **Make stage-3 retries resumable and state-changing.** Stage 3 loses 8/19 entrants. Seven independent attempts project to 99.77% stage-3 survival and **18.40% end-to-end**, **+7.72 points**. Application/path cleanup errors require a fresh application state; the truncated `ro/test-gate` run should be resumable or timeout-classified.

5. **Change metadata retries from replay to search expansion.** The four metadata losses are a direct **3.88-per-100 ceiling opportunity**. Preserve completed captures, vary the seed/range, and expand addressable buckets. The existing identical 3-attempt replays for three runs produced no additional coverage and should terminate after the first repeated dead-end signature.

The central result is that reliability is being lost mostly after successful placement, while the current placement sweep searches an empirically dead dimension. State-changing, stage-local retries—not larger same-state retry counts—are the path from roughly 10% toward 99%.