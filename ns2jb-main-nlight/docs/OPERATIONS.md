# Local browser testing

Never open test browser windows on the user's desktop. Run **every command
that may launch a browser** inside Xvfb, including Playwright, Creator database
tests, private-player checks, integration tests, and workers or scripts that
spawn Chrome indirectly.

Wrap the entire parent command:

```sh
env -u DISPLAY -u WAYLAND_DISPLAY xvfb-run -a <command>
```

Clear inherited display variables **before** `xvfb-run` assigns its virtual
`DISPLAY`; do not unset `DISPLAY` inside the wrapped command. Configure Chromium
with `--ozone-platform=x11` so it uses the virtual X display instead of a desktop
Wayland session. Child browser processes must inherit this isolated environment.

Do not attach automated tests to the user's normal Chrome session. If an
unexpected desktop window appears, stop the test processes you launched and fix
their display isolation before continuing. Do not terminate unrelated sessions'
browser processes.

# Switch 2 retained session (ns2jb-session)

Everything below lives in `switchhax/ns2jb-session/` and operates the tethered
jailbreak over the isolated `switchlab` netns (console `192.168.77.25`, PC
`192.168.77.1`, no internet route). Full details: `ns2jb-session/USAGE.txt`,
architecture notes in `switchhax/INVESTIGATION.md`. Git repo: `ns2jb-session/`
(code + docs committed; `runs/` and `*.bin` excluded as bulk/reproducible).

## Operating rules learned the hard way

- **Never leave a stale host listening.** A leftover `run.cjs` accepts the
  console's dial, fails its own verification, and closes it — the console
  spams `RPC STOP 0` and every cycle leaks a socket FD until
  `BOOT FAILED 57`. `session.sh start|resume` now kills stale hosts and
  refuses to run while anything holds the dial port (`192.168.77.1:39380`).
  Don't start a second host while one is alive; don't background hosts
  without cleaning them up.
- **Only one acquisition lottery per console boot.** The heap-shaping stage
  (`2/4 Acquiring FS memory`) is boot-layout dependent. Failure classes seen:
  canary miss (`Overwrite missed the qualified canary`, resources retained),
  heap drift, pointerless leak (`no qualified, encodable link candidate`),
  find-metadata pool deadlock (retried in-stage ×3 since commit 65bae27).
  A failed shaping = reboot the console + dance again; same-boot recovery of
  a failed acquisition is not proven — the re-dial re-runs the pipeline on
  retained resources and may or may not recover.
- **Console program text (TXT:NS2 → save file `/f/###/TNS2`) is encrypted at
  rest.** Do not try to rewrite it through the fs bridge (read works, write
  produces an invalid file).
- **Hard-kill vs graceful stop:** `session.sh stop` runs the full fresh-mode
  cleanup and *destroys* console-side state (that's for ending a boot).
  `SIGKILL` of the host tree preserves console-side state — use that when the
  goal is "stop the PC, keep the console session" before switching to
  `session.sh resume`.
- Console-side state survives host death and (separately) survives `GO()`
  re-dials, but **dies with a console reboot** or a fresh-mode cleanup.

## The console entry point (typed into slot 0, saved)

`GO2.bas` (the repo's single tracked `.bas`, source of truth) appends the
dial entry defs to the console program:

- `COMMON DEF GO2()` — zero-arg wrapper with the dial baked in
  (`39380,192,168,77,1,<pairing token from pairing.json>`). The console
  entry is `V=GO2()`; it re-dials from PHASE 4/5/6 after a host restart.
- `COMMON DEF GO2DIAL(P,A,B,C,D,T0#..T3#)` — PHASE 0 runs the full fresh
  path (BOOT + START); PHASE 4/5/6 re-dial without re-running BOOT, with
  bounded auto-retry (~25 min, 5 s backoff). Every failed dial and every lost
  session closes its socket via `CALL#(&H140D90,FD,0,0,0)` (`closeSocket`,
  verified SDK map entry: `svc 0x21` = close handle) — without this, retries
  exhaust the interpreter socket table.
- `GO.bas` (the short `V=GO()` wrapper) is generated per session by the
  host from `pairing.json` — gitignored, never committed (it carries the
  live pairing token).

PHASE semantics: 0 fresh · 1-2 boot · 3 connecting · 4 connected · 5 RPC
running · 6 session ended (re-dialable) · -1 failed (stuck; only reboot +
`RUN` recovers, and `RUN` must not repeat in the same app process).

## Daily operation

Fresh boot (console was rebooted):
```sh
cd ~/dev/ns2jb
nohup ./session.sh start > /tmp/ns2-start.log 2>&1 &
# console: LOAD "TXT:NS2" → RUN (OOM expected) → V=GO2()
```
Watch with `tail -f /tmp/ns2-start.log`; the run dir is in
`latest-session.json`; `SESSION READY` in the log means stage 4 passed.

Host restart / iteration (console untouched):
```sh
./session.sh resume          # re-attaches without re-acquisition
```
The console auto-re-dials (GO2 retry loop); nothing to type. Resume preserves
retained memory, the RO payload, the owned FS root, and the candidate cache
slot; it does not re-run acquisition and cannot retarget the memory window.
Do not edit files that change HELLO-derived addresses while resuming.

Status/probe/stop: `./session.sh status|probe|stop`. `stop` on a FRESH session
cleans up console state; on a RESUMED session it only stops PC processes and
keeps console state (next resume re-dials).

## Console state and failure recovery

- `V=GO()` from PHASE 6 after a host crash = free re-dial (auto-retry).
- After `BOOT FAILED N`: PHASE=-1, console stuck — reboot + dance.
- Keep console app open and Ethernet attached; smilebasic direct-mode text
  edits require the program NOT to be running.
- If a dial shows `RPC STOP 0` spam: a stale host is grabbing it — kill hosts
  PC-side, then `V=GO()` again.

## BRICK SAFETY (learned from a community console loss, 2026-10-23)

A public report describes a Switch 2 BRICKED this way: the operator ran the
same SmileBASIC takeover, an attempt failed, and they restored their save
file (cloud save restore) BEFORE rebooting. The save restore wrote over
parts of NAND while the takeover machinery was still armed in the failed
state. Non-negotiable rules:

- **NEVER restore or restructure a save while the takeover machinery is
  armed or in a failed state.** This includes: cloud save restore, save
  data download/copy from system settings, any save-container-level
  operation. Reboot the console FIRST (clears the armed state), then do
  the save operation on the clean console.
- **Our own save writes are file-level only and post-READY only.**
  TNS2NEW/TNS2TEST writes happen strictly after `SESSION READY` via the
  app's own save mount (CreateFile/WriteFile/Flush), never during an
  acquisition, never via container-level restore mechanisms.
- **Keep the console OFFLINE for this work.** The switchlab netns must
  remain the only network (no internet, no Nintendo servers, no cloud
  sync). Cloud save auto-sync with an armed takeover is the exact brick
  scenario above.
- **Keep the original program backup forever.**
  `runs/switch2-1z3IsI/switch2/tns2-backup-*.bin` is the pristine TNS2.
  Restore it only on a REBOOTED console via the file-level path if the
  console program ever needs recovery.
- **A failed acquisition = the console is NOT clean.** The machinery is
  retained in the fs heap. Treat every failed dance as armed-state until
  rebooted. Do not stack save operations on top of it.
- **If the console ever misbehaves at the FS level after our work**
  (mount failures, save corruption warnings), STOP all save writes
  immediately, reboot, and re-evaluate before touching anything.

## PC-side tooling

- Dispatch handlers hot-reload: edit
  `runs/<session>/switch2/memory/fs-root-control.cjs` (or
  `retained-memory.cjs`) and the next memory-socket request picks it up.
- Probe tools (top level): `probe-bis-map.cjs` (BIS partition inventory),
  `probe-bis-structure.cjs` (raw GPT/FAT structure; BIS 20 is encrypted —
  BIS 30/31 filesystems open read-only; BIS 35 holds the SD seed blob
  plaintext), `probe-save-explore.cjs` (save listing + TNS2 dump),
  `probe-save-update.cjs` (TNS2 write — works only for unencrypted content;
  TNS2 is encrypted so it currently cannot update the program).
- All console-side probes run inside the netns:
  `sudo -n ip netns exec switchlab runuser -u nlight -- node <probe>.cjs`
- Probe scripts resolve the latest session via `latest-session.json` — never
  hardcode an old run dir (bridge port/token differ per run).
- Never leak save-file handles: an open handle on a save file wedges the fs
  sysmodule (console needs reboot). `probe-save-update.cjs` closes everything
  in `finally`.

## BIS filesystem API (the persistence surface)

The retained session can read AND write the raw NAND FAT partitions through
the owned root: USER (BIS 30) and SYSTEM (BIS 31). All commands run through
the hot-reload dispatch (`root-*` → `runs/<session>/switch2/memory/
fs-root-control.cjs`, reloaded per request via the retained routing):

- `root-probe-bis` / `root-read-bis` — raw partition inventory + reads
  (BIS 0/10 boot, 20 user NAND encrypted, 27 calibration, 35 = SD seed blob
  PLAINTEXT; 30/31 filesystems open read+write).
- `root-list-bis` {id, path} — directory enumeration.
- `root-read-bis-file` {id, path} — file read with sha256 + head hex.
- `root-write-bis-file` {id, path, hex} — CreateFile → SetSize → WriteFile
  → Flush → **Commit** → read-back verification. USER (30) is restricted to
  `/temp/` and SYSTEM (31) additionally requires `system:true` (untested —
  the brick-risk zone is gated until the user approves).
- `root-mkdir-bis` / `root-delete-bis-file` — directory create (command 2)
  and file delete (command 1), both followed by Commit.

IPC facts learned the hard way (all verified against the takeover's wave
machinery):

- **FsFileSystem commands are 0-based**: 0=CreateFile, 1=DeleteFile,
  2=CreateDirectory, 7=GetEntryType, 8=OpenFile, 9=OpenDirectory,
  **10=Commit (the FAT journal flush)**, 11/12=free/total size, 14=timestamp.
- **IFile Read/Write input is `(0, offset, size)` as three u64s.** A wrong
  shape (e.g. `(offset, size, 0)`) is accepted with result 0 but writes ZERO
  bytes — the file keeps stale cluster content. Always mirror the verified
  read shape.
- Result codes: `0x202` = not found, `0x402` = already exists (tolerated for
  create/mkdir).
- Staging buffer for file data: `s.base + 0x1000000` (the probe's idle
  big-write region). NEVER stage inside `b+0x100000..0x240000` — that is the
  live worker ring; staging there silently corrupts data.
- Writes must Commit: without it a fresh cluster reads back stale journal
  content (directory blocks) even though WriteFile returned success.

## Persistence state (goal mvkbhbsb-8a9mjb)

Markers already written and hash-verified on USER:/temp (session
switch2-1z3IsI, manifest `bis-persistence-manifest.json` in the run dir):
`ns2write-test.bin` (4 KiB), `ns2-marker-A.bin` (1 KiB),
`ns2-sub/ns2-marker-B.bin` (1 KiB, tests directory persistence),
`ns2-big.bin` (192 KiB, multi-cluster). **Next dance validates them**:
after the reboot+dance run `validate-persistence.cjs` (netns-wrapped) —
it reads each marker back and compares against the manifest hashes.

Mapped surface (read-only so far): SYSTEM:/ has Contents/{placehld,
registered (256 .nca registration records)}, PRF2SAFE.RCV, save/ (~130
system saves; largest 8000000000000041 473MB, ...0090 118MB, ...0082
349MB), saveMeta/ (6 per-save dirs). USER:/ has PRF2SAFE.RCV, temp,
Album, Contents/{registered, placehld}, save, saveMeta.

Boot-flow research (codex, read-only) output: /tmp/hos-boot-research.out;
the memo lands in INVESTIGATION.md (no exploit/CVE wording). Entry-vector
options go to the user BEFORE any SYSTEM write; NAND writes require an
explicit stop-and-present checkpoint.

## Resume architecture (for reference)

`run.cjs --resume` → validates HELLO against `connection.json` (mismatch =
console was rebooted → use fresh start) → rebuilds bridge → pipeline child
with `NS2_RESUME=1` → `resumeMain()` spawns `memory/controller-resume.cjs`
(rebuilds controller context from the report, re-opens the candidate slot via
owned-root command 200, verifies recorded hashes, serves) → hold-session.
Stop path never tears down console state. A resume generation token gates
readiness (`memoryControl.generation`). `fs-memory-control.cjs` hot-reloads
dispatch modules per request (`freshRequire`) and seeds `knownRanges` only
from verified captures.

## Git

`ns2jb-session` is a git repo (`main`): commit code/docs; `runs/`, `*.bin`,
`*.log` are gitignored (bulk per-boot evidence). pairing.json is committed —
it is required to re-dial and holds the reusable pairing token.
