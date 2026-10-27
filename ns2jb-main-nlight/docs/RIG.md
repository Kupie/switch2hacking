# Side-channel rig (spectre research harness)

Research goal: find speculative-execution primitives on the console CPU
(Cortex-A78C class) that leak key material or cross a privilege boundary,
building on the retained-session jailbreak. This directory holds the live
experiment harness.

## Architecture

- **RO monitor payload** (`engine/switch2/ro/payload/`): the native program
  launched as `0x0400000000000037`. v3.1 adds command `0x524f0003`: a chunked
  blob upload into a fixed code cave (`void exp(const u64 args[8], u64 out[8])`)
  plus isolated execution. v2's rig subs (`0x524f0002`) stay for calibration.
- **Experiments** (`experiments/*.c`): stack-only, position-independent C.
  Rebuilt to blobs on every harness run; nothing console-side restarts
  between experiments. Writable globals are rejected at build time (the cave
  runs RX during execution).
- **`rig-harness.cjs`**: builds, uploads, runs, and reports. Hot-reloads the
  native dispatch chain per request, so handler edits are live too.
- **`engine/build-experiment.cjs`**: blob builder + `--test` qemu smoke runs.

Exec protocol (`0x524f0003`), fixed 16-word reply; state is post-op:

```
w0 tag "NRO2EXEC"   w1 sub            w2 status (0 = ok)
w3 cave address     w4 cave size      w5 expected | offset<<16 |
                                      committed<<32 | runs<<40
w6 checksum         w7 detail         w8..w15 run results
```

Status codes: `0xd401` malformed input, `0xd402` wrong state,
`0xd403` bounds overflow. Subs: 0 info, 1 begin(size),
2 chunk(offset, length, data), 3 commit(size, fnv64), 4 run(args[8]),
5 clear. Every call defines all 16 words, so clients never parse
message-buffer leftovers.

Safety rules (non-negotiable):

1. No permanent NAND writes. The rig touches only the RO monitor process's
   own memory. BIS writes and save writes are out of scope for this tooling.
2. Experiment code never executes in the fs process. A faulty blob kills at
   most the disposable RO monitor (recoverable; see below).
3. The working console program `TXT:NS2` is never modified. Program updates
   go to `TXT:NS2NEW` only.
4. The one reboot-relevant step is `deploy-monitor.cjs` (the gated PM/Loader
   launch dance). If the gate ever misbehaves, stop and reboot - do not stack
   recovery attempts.

## Workflow

```sh
# validate experiment logic on the PC first (no console contact):
node engine/build-experiment.cjs --test experiments/spectre-v1.c 65 8 30

# live run (netns-wrapped), session running:
sudo -n ip netns exec switchlab runuser -u nlight -- node rig-harness.cjs info
sudo -n ip netns exec switchlab runuser -u nlight -- node rig-harness.cjs run experiments/cache-timing.c 32
sudo -n ip netns exec switchlab runuser -u nlight -- node rig-harness.cjs rig 2      # id registers
sudo -n ip netns exec switchlab runuser -u nlight -- node rig-harness.cjs clear
```

`rig-harness.cjs run` rebuilds the blob when the source changed, uploads it
(begin/chunk/commit with FNV verification), executes it on a dedicated
128 KiB stack, and prints `out[0..7]` as decimal and hex.

## Experiment ABI

```c
typedef unsigned long long u64;
void exp(const u64 *args, u64 *out);   // 8 inputs, 8 outputs
```

- Position independent (compiled `-fPIC`, cave may run at a mapped address).
- Stack only: no writable globals, no heap, no libc.
- Read time with `mrs cntvct_el0`; `dc civac` works for owned lines.
- Keep runs short: the IPC loop is blocked while the blob runs. A hung blob
  wedges the monitor (the harness raises a deadline error; relaunch needed).

## Deployment and recovery

`node deploy-monitor.cjs` re-issues the monitor on a live session:

1. donor cycle (cleanup -> reset -> prepare; transient file-level writes to
   the application's own temporary volume, removed by the normal stop path),
2. the gated PM/Loader launch dance (child process; restores on failure),
3. start the accepted image, terminate the previous monitor, verify.

If pm rejects a second concurrent instance of the same program id, rerun
with `--terminate-first` (frees the slot first; if the subsequent launch
dance fails, the monitor service is gone until the next acquisition - the
session and the console are unaffected).

Fallback with zero added risk: the next fresh acquisition
(`session.sh start` after a console reboot) deploys whatever
`engine/switch2/ro/payload/main` is built - the acquisition path runs the
same donor+launch flow. Rebuild the payload and the next boot picks it up.

If the monitor dies (bad blob, service death): the fs process and session
survive; process-probe capability returns with the next deployment.

## Status log

- v3.1 built and qemu-validated (smoke, timing, cache-timing, spectre-v1).
  v3.1 fixes the v3 reply protocol: fixed 16-word layout, explicit status
  codes, post-op state echo (v3 leaked message-buffer leftovers into parsed
  fields and echoed pre-op state).
- PC-side chain verified live: worker lifecycle, hot-reloaded dispatch,
  service lookup, reply parsing; monitor deployment (donor cycle -> gated
  launch dance -> start-new-then-terminate-old) works live.
- `rig-probe.cjs` removed: superseded by rig-harness (it carried a socket
  signature bug, a join-reply bug, and off-by-3 result parsing).
- Stray stopped process: the first deploy attempt's aborted swap left the
  unmodified placeholder process (pid 210) created-but-never-started. It is
  inert and cannot be terminated via pm:shell (0xFA01 on unstarted).
  Documented; harmless.

## v3.6 postmortem (2026-10-23, run switch2-1uI3yx)

- v3.6 monitor (sha 337ec847, pid 214) died right after launch: no crash
  exception recorded (clean-exit/pm-kill signature), prime suspect the new
  1 MiB `rigEvict` `.bss` (total ~1.18 MiB vs ~150 KiB for every surviving
  payload) tripping a pm resource limit at launch.
- Its death unregistered `ro:dmnt`; the in-flight `sm-get` worker blocked
  forever inside sm, wedging the fs dispatch for that request, and the
  console BASIC loop wedged mid-RPC so it never saw the host socket die
  (no redial). Console-side armed/failed state; **reboot is the only exit**
  (per AGENTS brick-safety: no save ops on top of the armed state).
- Recovery: `session.sh resume` cannot rebuild through a wedged fs.
- v3.7 (sha 9b1f8714, commit 33cd505): drops `rigEvict`, evicts by striding
  the existing 128 KiB `rigStack` (2x A78C L1D), `.bss` back to 149.6 KiB
  (surviving footprint). Deploys on the next fresh acquisition.
- keep-host.sh now resume-first: a prior run dir starts `session.sh resume`,
  never a rogue fresh host over retained console state; on host exit it
  alternates to fresh (HELLO mismatch = console rebooted), so the console's
  ~25 min GO2 retry loop self-heals onto the right host.

## v3.7 rig-6 postmortem (2026-10-23, run switch2-zRFtwP)

- v3.7 survived launch (info answered; .bss size confirmed as the v3.6
  launch killer), then **died on `rig 6`**: 0xf601 transport loss, no crash
  record, ro:dmnt unregistered. Only dangerous element in that path:
  **`dc ivac` at EL0 is a process killer on A78C/HOS** (civac = no-op,
  dsb = benign, used by every sub). The flush question is answered:
  there is no ivac path; eviction must come from capacity/stride.
- **v3.8** (sha dd3d92b9, commit 1520f2c): sub 6 without ivac (civac cost,
  dsb cost, hot, afterCivac, 128 KiB rigStack-stride afterEvict); ABI slots
  kept, ivac slots return sentinel 0xffffffffffffffff.
- **Monitor-death wedge mechanics**: a monitor that dies mid-flight leaves
  the harness sm-get worker blocked inside sm (GetService blocks until the
  name registers) with values [0, sentinel]; deploy-monitor then refuses
  ("a native worker is still active") and worker-prepare is gated the same
  way. There is **no safe PC-side clear**:
  - `worker-cancel` cancels the **7 acquisition apiWorkers**, not the stuck
    worker's own thread. Cancelling the pool aborted console-mediated RPC
    state, the RPC link and then the USB carrier died; console-side wedge,
    host exited, reboot was required. **Never call worker-cancel to recover
    a wedged worker** — it is acquisition-scoped machinery, not a janitor.
  - The stuck thread is a fresh pthread (not pool); cancelling it would
    need its svc handle (pthread struct calibration: pool struct dumps put
    the source handle past +0x80; unfinished). Untested future path: hot-
    reload a targeted `cancel` of `state.worker.thread`'s handle.
- Recovery taken: console link recovered by itself (carrier returned);
  fresh host started for the next dial. v3.8 deploys via the acquisition
  path.

## A78C measurement foundation (2026-10-24, session switch2-JZjsZM, payload v3.9-v3.14)

Live-measured hardware facts (all from the RO monitor at EL0 on A78C/HOS):

- **CNTFRQ_EL0 = 31,250,000** — 1 tick = 32 ns ≈ 64 cycles @ 2 GHz. The ONLY
  userland timer: **PMUSERENR_EL0 = 0** (PMU disabled at EL0; PMCCNTR unreadable,
  probed conditionally, never blind). Single-access L1-vs-L2 (~10 cycles) is
  sub-tick → per-slot Flush+Reload-style oracle readout is impossible with
  cntvct; amplification is mandatory.
- **CTR_EL0 = 0x9444c004, DCZID = 64-byte lines.**
- `dc civac` = no-op at EL0 (v3.5 calibration: coldCount=0); `dc ivac` =
  process killer (v3.7 live). No flush primitive exists → eviction-only.
- **L1D demand loads allocate normally** (same-line 7 cycles; 512-line LCG
  walk P1=P2=P3 all L1-fast). The "streaming bypass / no-allocation" theory
  that briefly explained tonight's early nulls was MY measurement bug: the
  affine chase chain ((i+1)*67 mod 2048) is a permutation but NOT a full
  cycle (orbit ~512 lines), and rev6's 8-bit butterfly masks were not a
  bijection on 6-bit values (16 distinct outputs). Both fixed (v3.12/13).
- **Eviction works: full-cycle LCG chase** (x = 33x+1 mod 2048, all 2048
  rigStack lines, no constant stride): hot sweep 10 ticks vs post-chase
  sweep **14 ticks** (+40%, min-filtered, per-cycle, repeatable). Stride
  loops also evict (prefetch installs lines). Prime+Probe primitive ALIVE.
- Stride loop: 4 cycles/load (prefetcher-boosted) vs 9 cycles/load LCG walk
  (address math) — the L1 prefetcher catches constant strides; attack
  patterns must be permuted.

### Implications for the escalation goal

- **Working readout**: sweep-amplified (64 lines × ~14 cycles) = +14 ticks,
  clean. Prime+Probe against a victim's cache footprint is feasible at
  L2/L3 granularity; single-line granularity is not (sub-tick).
- **Victim coupling**: L1D is private per core; cross-process L1 attacks
  need core co-residency (scheduler-controlled). L2 is cluster-shared:
  cross-sysmodule Prime+Probe at L2 is the realistic near-term primitive
  (needs L2 eviction-set construction — larger buffers than tonight's).
- **Spectre-V1 oracle**: per-slot timing dead at 32 ns; would need
  computational amplification of the speculative effect, or the leak
  channel moves to Prime+Probe of a poisoned victim (we already hold fs
  heap R/W to plant victim state directly).

## Cache hierarchy map (2026-10-24, v3.15/v3.16 sub 13, session JZjsZM)

Full-cycle 33-affine dependent chases at pow-2 footprints, min over 4
passes (ticks/load = ticks x 64 cycles / 32 ns / lines):

| footprint | per load | class |
|---|---|---|
| 32 KiB | 4.4 cy | L1 |
| 64 KiB | 4.5 cy | L1 (fits) |
| 128 KiB | 12.9 cy | L2 hit |
| 256 KiB | 13.5 cy | L2 hit |
| 512 KiB | 14.1 cy | L2 hit — fits entirely |

**L1D = 64 KiB, L2 = 512 KiB per core** (512 KiB is the A78C maximum L2
config; a footprint equal to L2 size touches every line and stays
resident, so L2 >= 512 KiB => = 512 KiB). The L2->DRAM boundary would
need a >512 KiB chase buffer: ~1 MiB .bss is the v3.6 launch-death zone
(pm limit unproven between 530 KiB (v3.16, launched fine) and 1.18 MiB)
and a post-start death races the harness liveness gate -> possible
console wedge -> deferred until the pm limit is understood. DRAM latency
(~200 cy inferred) is not yet measured.

Design consequences for the escalation goal:
- A78C L2 is PRIVATE PER CORE -> cross-sysmodule Prime+Probe must target
  L3 (shared, if configured) or DRAM banks — L2 P+P against fs is dead.
- L1 eviction (full-cycle chase) works and is cleanly measurable at
  sweep amplification (sub 11: 10 -> 14 ticks, +40%).
- Same-core victim coupling (fs threads scheduled onto our core) is the
  only L1/L2-visible channel: requires core co-residency + scheduler
  cooperation, both uncontrolled from here today.
- Sub 11's "walk" loads were INDEPENDENT (register math), so its 4.6
  cy/load was L2 throughput, not latency — dependent chases (sub 13)
  are the latency instrument; keep them distinct.
