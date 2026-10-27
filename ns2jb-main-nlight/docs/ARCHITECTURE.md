# Switch 2 Jailbreak — Investigation Notes

*Working notes for the retained-session jailbreak on Switch 2, firmware 23.0.1,
SmileBASIC 4.4.9. Written during the takeover of the original agent session on
2026-10-23. Terminology note: this document describes a jailbreak; vulnerability
identifier jargon is deliberately kept out of these notes and the chain is
referred to as the jailbreak throughout.*

## 1. Context

- Original work was driven by an agent (Codex) across ~145 tasks / ~50M tokens
  on 2026-10-22; that session was interrupted right after a successful
  `session.sh start` and its host process died with it.
- This document was written after taking over that work: reconstructing state
  from `~/.codex/sessions/.../rollout-*.jsonl`, recovering a live retained
  session, hardening the acquisition path, and verifying access end-to-end.
- Upstream: [pepsipu/ns2jb](https://gitlab.com/pepsipu/ns2jb) and the
  [announcement write-up](https://pepsipu.com/blog/2026-10-switch2-jailbreak-ns2jb/).
  Our working tree is `ns2jb-session/` (session mode), derived from the
  upstream distribution plus local hardening.

## 2. What the jailbreak is (short form)

SmileBASIC 4 (a Switch 1 title running on Switch 2 through backward
compatibility) contains a 32-bit integer overflow in its array handling:
`REMOVE R,&H60000000,&H3FFFFFFF` wraps `position + count`, so the interpreter
performs an out-of-range `memmove` that pulls the 8 bytes preceding the array
backing — which contain a self-pointer — into `R[0]`. Treating that pointer as
a string length gives out-of-bounds read/write over the whole heap.

From there the chain hijacks an `fs` sysmodule `BufferedStorage` cache entry
(0x301-byte overflow in path normalization) to gain arbitrary read/write in
`fs`, sets the saved PID to 1 (FullPermission), and swaps the loader's ExeFS
filesystem object for one it controls — executing arbitrary native code with
`ro`'s NPDM permissions, including patching `fs` itself.

The jailbreak is **tethered**: it does not survive a reboot. The console side
must be re-armed after every reboot (see §4).

## 3. Local architecture

```
ns2jb-session/
  session.sh            start | status | probe | stop  (netns-aware wrapper)
  run.cjs               host: --session <host-ip> (default 192.168.77.1)
  engine/switch2/
    pipeline.cjs        4 stages (below)
    acquire.cjs         spawns the memory probe child
    memory/probe-reserved-gap.cjs   heap-shaping probe waves
    hold-session.cjs    keep-alive: polls rpc status every 5 s
  GO.bas                console helper (generated per session; gitignored)
  GO2.bas               dial entry defs — the tracked source of truth
  pairing.json          shared handshake token (gitignored)
```

Pipeline stages (from `run.log` of a successful run):

1. **Checking the console** — app map, inspect mounts, scratch cleanup, qualify.
2. **Acquiring FS memory** — heap probe waves (reserved groups, canary
   qualification, alias installation), then a bounded verification: the probe
   refuses to continue unless every wave's heap accounting restored exactly.
3. **Starting the native helper** — retained metadata → `ro` payload install →
   owned FS root/notifier → session bind.
4. **Verifying FS execution before retaining access** — instruction-challenge
   trials run inside `fs`, results captured as proof files under
   `runs/<session>/switch2/process/`.

Networking: the console sits on an isolated netns `switchlab`; the USB Ethernet
dongle (`enp17s0u6`) is the host at `192.168.77.1`, the console is
`192.168.77.25`, DNS by dnsmasq at `192.168.77.2`, **no internet route**
(`session.sh` refuses to start if the netns gains one).

## 4. Operating the retained session

Console side (after every reboot — the jailbreak is tethered):

```
Direct mode:
  LOAD "TXT:NS2"      (the saved bootstrap, contains the REMOVE)
  RUN                 → stops at "Out of memory" — expected, do not RUN again
  V=GO2()             → dials the PC at 192.168.77.1:39380 and waits
                      (GO.bas provides the short V=GO() wrapper)
```

Host side (from `ns2jb-session/`, detached so it survives the agent session):

```
setsid nohup sudo -n ip netns exec switchlab runuser -u nlight -- \
  node run.cjs --session 192.168.77.1 > /tmp/ns2jb-session-start.log 2>&1 &
```

Then `./session.sh status` / `probe` / `stop`. All three resolve the current
run via `runs/latest-session.json`.

## 5. Session takeover and recovery (2026-10-23)

The original agent's host process died with its session (bridge port dead,
`/tmp/ns2-*/memory.sock` stale). Console remained reachable. Recovery took
five attempts; each attempt is a full console reboot plus re-arm, because a
failed acquisition leaves the console heap dirty by design:

| # | run | stage | failure signature |
|---|-----|-------|-------------------|
| 1 | `switch2-UvelEo` | 2/4 | trigger aborted early → −32736 heap drift at `cache-combined-leak-0-7-0-1` |
| 2 | `switch2-yBKaaf` | 2/4 | same drift at `cache-address-alias-offset-4-0-0` |
| 3 | `switch2-Z8wFPt` | 2/4 | 5 deterministic canary misses after positive #1 aborted |
| 4 | `switch2-TFW07i` | 2/4 | alias requalification mismatch after address prep |
| 5 | `switch2-rxMCyH` | ✅ | `SESSION READY`, FS execution verified |

### Failure modes and fixes applied

- **Mode A — benign one-page drift.** A trigger row aborting early can shift
  the general heap by exactly one 32 KiB page (−32736). The probe treated any
  drift as fatal. **Fix:** in
  `engine/switch2/memory/probe-reserved-gap.cjs`, when the retained cache is
  provably intact (canary healthy, no changed paths) and the drift is exactly
  −32736, re-anchor the wave's accounting and continue; any other magnitude
  still aborts hard.
- **Mode B — residue after an aborted positive wave.** An aborted positive
  wave leaves a stuck 16 KiB BufferedStorage-cache chunk
  (`counter[3]` 393216 vs 409600) that silently shifts every later window, so
  retries miss the canary deterministically. **Fix:** `retryWave` now runs one
  safe `abort-control` wave to drain residue before the next positive attempt,
  and fails fast after two deterministic misses instead of burning all six.
- **Mode C — alias requalification mismatch.** After address preparation the
  re-read through the alias offset returned foreign bytes (attempt 4). Not yet
  fixed; it did not recur in attempt 5. Candidate direction: re-run
  `installCombinedLeak` (reprime) if the requalification read mismatches
  instead of aborting.

Remaining hardening (from the deep-dive report, partially applied):

- Generalize the pin-cost check (`newPersistentBytes === 13616` literal) to a
  measured value.
- The dormant `locate-` profile hook could serve as a one-shot canary-location
  diagnostic after an anomaly.

## 6. Current state and limitations

- Retained session `switch2-1u9ld7` verified end-to-end (FS execution
  verified, pid 8, trials 2, `restored: true`).
- **Tethered only.** Reboot persistence is not implemented and is not
  currently possible with this chain; every reboot needs the §4 dance.
- The keep-alive watchdog (`hold-session.cjs`) polls every 5 s and writes
  `runs/<session>/switch2/session.json`; if the host dies the console RPC
  stops and a full re-arm is required.

### 6.1 Persistence study (2026-10-23, definitive)

Two write surfaces were tested across multiple console reboots:

- **Raw BIS writes (USER partition, BIS 30) do NOT survive a reboot.**
  Four markers (4 KiB, 1 KiB, 1 KiB in a subdirectory, 192 KiB) written
  with CreateFile/SetSize/WriteFile/Flush/Commit and byte-verified in
  session were absent (0x202) after the next reboot; `/temp` itself
  survived but was empty. Interpretation: the fs driver's cached FAT and
  block state are not coherent with direct-NAND writes, and its shutdown
  flush restores stale content over them. Raw BIS remains useful for
  READ-ONLY analysis only.
- **Save-mount writes DO survive every reboot.** Forged SmileBASIC
  program files (TNS2TEST/TNS2NEW) persisted across ~10 reboots until
  deliberately deleted. The write path is the app's own save filesystem
  (mounted `save:` clone or the dispatch `root-write-save-file`, journal
  commit included).
- Therefore the persistence surface for this chain is the save
  filesystem. The console program itself (TNS2) is the only
  boot-time-reachable code store; see the entry-vector notes below for
  why that still requires the manual `LOAD`+`RUN` step.

### 6.2 System dumps

`dump-system.cjs` (netns-wrapped) collects read-only evidence to
`~/dev/switch/dumps/<session>/`: raw BIS 0/10 (boot chain, encrypted),
BIS 27 (calibration), BIS 35 (SD seed blob, plaintext), plus file-level
SYSTEM (31) and USER (30) trees (skips user saves/album and files over
40 MB). Raw BIS reads run ~90 KB/s; the skip-if-exists manifest makes
re-runs cheap.

### 6.3 Entry-vector options (task-3, decision memo)

Boot-flow research (fw 23.0.1, community-documentation based, flagged
inference) plus our empirical results reduce the options to:

**Established by our own tests:** save-mount writes are durable across
reboots; raw BIS writes are not. The console program (TXT:NS2/TNS2 on the
save card) is the only boot-adjacent code store we can write reliably.

**Candidates, ranked by research value and brick risk:**

| Rank | Surface | Assessment |
|---:|---|---|
| 1 | Qlaunch/NS HOME state saves | Plausible automatic consumption at HOME init; medium brick risk (shell crash loop). Needs a boot-time access trace before any write. |
| 2 | Settings saves | Strong startup relevance; no documented setting launches code; high brick risk. |
| 3 | News/BCAT content | Structured archives, conditional pre-interaction reachability; medium risk. |
| 4 | NCM metadata (`cnmtdb.arc` / save-backed 0120/0121) | Strong boot dependency; metadata alone does not execute code; very high risk. |
| 5 | FS save index | Foundational; corruption breaks all saves; very high risk. |
| 6 | PRF2SAFE.RCV | Weakest evidence; very high risk. Not a payload mechanism. |

**Honest bottom line:** no community-documented boot-time path executes
arbitrary content from SYSTEM/USER on 23.x, and none of the surfaces
above removes the console-side `LOAD`+`RUN` step by itself. The
practical auto-arm design is therefore: keep the console program as the
entry point, make the PC re-attach cheap (resume/redial — already
working), and treat "zero console-side steps" as requiring a separate,
not-yet-demonstrated execution mechanism. Any SYSTEM-partition write
experiment (ranks 1-5) remains gated behind an explicit stop-and-present
checkpoint with the user, batched, one candidate at a time.

## 7. Pointers

- `ns2jb-session/USAGE.txt` — full operating manual (console prep, session
  controls, troubleshooting).
- `runs/switch2-rxMCyH/` — reference artifacts of a fully successful run
  (acquisition log, retained heap dumps, session.json, connection.json).
- Prior agent session (read-only reconstruction):
  `~/.codex/sessions/2026/10/22/rollout-2026-10-22T19-02-03-01a16459-*.jsonl`.
- Upstream repository and blog (§1).
