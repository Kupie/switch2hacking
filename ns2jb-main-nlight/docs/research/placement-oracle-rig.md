# Research track 3 — placement oracle via the side-channel rig

*Goal: observe the fs heap geometry BEFORE the destructive positive wave, so
placement can be computed instead of drawn. Status: PARKED — constraint
analysis stands (no cross-address-space speculative read; see "The hard
constraint"), but the rig track is retired. The acquisition telemetry +
hardened tooling superseded the placement bet.*

## The hard constraint (read this first)

The rig runs inside the `ro` monitor's code cave (EL0, own address space).
On this platform:

- Per-process address spaces mean an EL0 speculative load from another
  process's VA simply faults architecturally; there is no cross-address-space
  Spectre read of `fs` heap from `ro` through speculation alone. (The
  `experiments/` Spectre-V1 gadget proves transient execution works *within*
  the cave's address space — a prerequisite, not the oracle.)
- `MapProcessMemory` (used by the ro payload) maps `fs` **code**, not its
  heap. It gives code-side RE material, not live heap geometry.
- Post-ARW we can read `fs` heap trivially through the cache alias — but that
  is exactly after the placement problem is already solved. The oracle is
  only valuable PRE-placement.

Therefore a *direct* oracle is not available through the rig as-is. What
remains are three routes, ordered by feasibility:

## Route A — in-band allocator fingerprints (near-term, do this first)

The wave already emits sub-millisecond timings and per-request result codes
for 13 concurrent requests. The hypothesis: the *latency profile* of ordinary
pre-positive waves (control/negative/extent) encodes allocator state more
finely than the 16 counters (which failed to separate: AUC 0.52).

- Offline: re-mine the corpus's 3172 wave rows (`startUs`/`endUs` per row,
  result codes) for features predicting hit/miss beyond the counter vector:
  per-row latencies of `hole`/`tailN`/`canary`/`fillerN` in the *negative*
  control wave, request-spacing jitter, `preRelease` row latency itself.
- Task 3 already found `receiveOrderMarginUs` AUC 0.614 — weak but nonzero;
  a combined timing-feature model is untested.
- If timing features separate where counters don't, the oracle is free (no
  rig work) and lands directly in the acquisition engine.

## Route B — cache-side observation of storage block placement (medium)

The leak window shows cached storage content. We proved path buffers are
absent, but FAT directory blocks ARE visible (`commit_data` name found in
one 2 MB window dump at offset 164516; the `canary`/`selected` name pair
appears in retained-memory snapshots at a constant 4128-byte separation).
The scratch tree's directory blocks encode the *storage-cache* geometry.

- Question: does the cache-block position of the scratch tree correlate with
  the heap placement of the path buffers (both driven by the same request
  stream)?
- Test offline first: the 132 saved window dumps + the `*-memory-*.bin`
  snapshots already in `runs/` (hit runs only — the capture machinery runs
  post-acquisition; a live test would capture windows on MISS rolls too,
  via a probe-only roll that stops after the read).
- If correlated, the pre-positive leak read (which happens before the
  positive wave!) becomes the oracle.

## Route C — microarchitectural rig experiments (long shot)

Only if A and B fail. The rig ABI (`void exp(const u64 args[8], u64 out[8])`,
`rig-harness.cjs load|run`) is the right platform for:

1. **Cross-core cache effects on shared memory**: `fs` and `ro` share nothing
   user-visible, but the kernel slab and page allocator are shared
   underneath. A speculative probe of *allocator metadata pages* the
   allocator touches during fs allocations (cache state induced by fs
   activity, observed from ro) is a known technique class (page-granular
   eviction-set monitoring). Experiment sketch: evict-rescan loop in the
   cave measuring timing shifts correlated with fs allocation bursts driven
   from the PC side.
2. **Counter constraints from the rig postmortems**: `dc ivac` kills EL0
   monitors on A78C/HOS (v3.6/v3.7 postmortems); keep `stack-stride` evict;
   all eviction must stay within the cave's own mappings.

This route is research-grade and uncertain; treat it as background work
behind tracks 1 and 2.

## Go/no-go

| checkpoint | decision |
|---|---|
| Route A model AUC > 0.75 on held-out corpus | ship timing oracle into the probe |
| Route B correlation r > 0.7 on paired dumps | build the pre-positive block scan |
| both dead after N≥20 fresh paired captures | park this track; roll compounding is the end state |

## Related existing assets

- (The Spectre-V1 / cache-timing / timing experiment blobs were retired with
  the spectre track; only `experiments/{hipc2,smoke}.c` + their `build/`
  blobs remain, both referenced from FIRMWARE_FINDINGS §7.)
- `rig-harness.cjs` exec protocol (NRO2EXEC), hot-reload cave.
- `rig-harness.cjs rig <n>` payload-resident subs (timer/regs/calibration).
