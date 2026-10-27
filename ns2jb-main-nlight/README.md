# ns2jb — Switch 2 SmileBASIC takeover lab

A lab toolchain for the Switch 2 (firmware 23.0.1) built on the SmileBASIC
4.4.9 takeover exploit: run the exploit once, then **retain** the hijacked
FS session across host restarts and drive the console over RPC — enumerate
installed content, mount a game's decrypted RomFS directly, and dump it.

Original project by [**pepsipu**](https://gitlab.com/pepsipu) — see the
[announcement write-up](https://pepsipu.com/blog/2026-10-switch2-jailbreak-ns2jb/)
and the [pepsipu/ns2jb](https://gitlab.com/pepsipu/ns2jb) repo (the FS demo).
This fork merges the public improvements from
[kurumuz/ns2jb](https://gitlab.com/kurumuz/ns2jb) (acquisition retries,
find-metadata candidate loop, timeouts, save-space cleanup, layout
vtable-distance inference + SDK-page verification — with thanks to
**[crueter](https://github.com/crueter)** for the acquisition/reliability
work), then adds the retained-session toolchain and the research below.
The update-ExeFS/Update-RomFS composed-mount routes are ports of
[OunceCake](https://github.com/misshexa66/OunceCake)'s
`selectPatch`/program-registry techniques (by
[misshexa66](https://github.com/misshexa66)) — their public source was the
reference for the lr registered-patch, access-control, program-context and
fs-cmd-200 chain, adapted to this fork's heap-only memory channels.

**Everything here is tethered**: no reboot persistence, no installed CFW.
The console must keep SmileBASIC open; a reboot resets to a clean state.

## What this fork adds

- **Retained sessions** — the verified FS session survives PC restarts.
  `session.sh start|resume|status|probe|stop` drives the lifecycle; the
  console program re-dials on its own (`V=GO2()`, ~25 min bounded retry).
  A hold path verifies FS execution, then retains console-side state.
- **The game-content dump route** — installed games open
  **without launching them**: NCM content records give the NCA path,
  `es` prepares the title key ("license", with the owned-content context
  + account-rights dance), and fs `OpenDataStorageByPath` (cmd 206) returns
  the **decrypted RomFS as a live IStorage**.
  `tools/dump/game-dump.cjs` implements it end-to-end (resumable,
  per-file sha256, coalesced small-file windows, `--bulk` 4 MiB chunks).
  Validated live: Mario Kart World's complete 21.7 GiB base RomFS and
  Tears of the Kingdom's 15.9 GiB base RomFS stream from a retained
  session, no app switch.
- **The update-content routes** — `tools/dump/update-exefs.cjs`
  (lr registered patch → composed CodeFS) and `tools/dump/update-romfs.cjs`
  (patch + fake program context + fs cmd 200 → the **update-composed
  RomFS image**, with LayeredFS overlay extraction via
  `tools/dump/finish-overlay.cjs`). All console-decrypted, heap-only
  (no build-specific module-offset constants), armed-state-safe
  (records + removes everything it arms in `dump-state.json`).
  Validated live: MKW's update ExeFS (adds `subsdk1`) and its 21.9 GiB
  update-composed RomFS (delta: 631 added + 7,593 changed + 197,978
  identical vs base).
- **find-metadata rewrite** — node-predicate pool search: geometric
  candidates, disputed-link quarantine, best-first early-stop (retargets
  ~16 → mean 1.7 across 21 real captures), in-stage retry, adaptive window
  thresholds.
- **Window-slide memory primitive** — arbitrary fs-VA read and
  compare-verified write through the retained session's armed cache
  (guards relaxed to the 2^48 VA range); `tools/memory/fs-heap-chase.cjs`
  walks the fs region map and reads/dumps/writes anywhere in the fs
  address space, walk-rule validated.
- **BIS partition surface** — read/write USER/SYSTEM NAND FAT partitions
  through the owned root, with Commit and read-back verification.
  Brick-safety rules govern every write (`docs/OPERATIONS.md`).
- **App inventory + names** — the NCM content sweep
  (`tools/dump/game-dump.cjs` discovery path; ad-hoc probes in
  `/tmp/list-apps.cjs` shape) enumerates every installed title with
  versions, and control NACP readback resolves display names — 13
  installed applications on our lab console.
- **System-archive route** — `tools/dump/sysarch-cmd10-batch.cjs`:
  `fs cmd 10` (`OpenFileSystemWithId`) fsType 6 + archive title id opens
  system data archives DIRECTLY (IFileSystem, recursive cmd-9/cmd-8
  walk, sha256 manifests, resume-safe). Fresh-boot reproducible; the
  206 dispatcher mask-gate made every prior attempt refuse.
- **System-content surveys** — `tools/dump/sysmod-update-sweep.cjs`
  (update-meta sweep across storages: NONE on fw23.0.1) and
  `tools/dump/nca-structure-sweep.cjs` (per-title content-type
  inventory → `fw23/nca-structure.json`).
- **Research corpus** — `FINDINGS.md` (the distilled fact log: fw23 IPC
  command maps, error-code map, the content-registry walls, closed
  routes, recovery economics, the HIPC2 wall and why the nvdrv GPU
  ioctl surface stays closed), `FIRMWARE_FINDINGS.md` (fw23 system-code
  and HIPC2 research), `docs/` (architecture, rig ops, NPDM/registry
  reversing notes, **[`DUMPS-CATALOG.md`](docs/DUMPS-CATALOG.md)** —
  the complete sha256 catalog of every non-game dump), and Ghidra/NS
  reversing tooling in `tools/`.

## Proven end-to-end (live console)

- **All 57 fw23 system data archives** (39,052 files): fresh-boot single-
  pass via `fs cmd 10` fsType 6 — zero refusals, no state needed
  (`tools/dump/sysarch-cmd10-batch.cjs`).
- **Mario Kart World** (`0400c3f00006e000` + update v917504): complete
  matrix — base RomFS 21.7 GiB / base ExeFS / base control / update
  ExeFS (composed; the update adds `subsdk1`) / update control / update
  **composed RomFS image 21.9 GiB** (delta vs base: 631 added +
  7,593 changed + 197,978 identical) + LayeredFS overlay tree.
- **SmileBASIC 4.4.9** (`0100c9100b06a000` + update): complete matrix
  incl. the cmd-200 composed view (287 files) and both control versions.
- **Tears of the Kingdom** (`0100f2c0115b6000` + update v720896): complete
  matrix — base RomFS 15.9 GiB / base ExeFS / base control / update control
  (v1.4.3) / update ExeFS (composed; 5 files — TOTK ships **no
  `subsdk1`**, unlike MKW) / update **composed RomFS image 15.9 GiB**
  (delta vs base: 763 added + 7,125 changed + 296,355 identical —
  98.9%, a true overlay) + LayeredFS overlay tree (7,888 files).

## System firmware + data archives — COMPLETE

- **System programs** (`~/dev/switch/dumps/fw23/`, 88 titles): per-module
  decrypted `text/rodata/data` + `main.npdm` + `meta.json` (flags,
  build-id) — captured via the same NCM/CodeFS route. Inventory with
  sha256s: `FIRMWARE-DUMP.txt` in that directory.
- **System data archives (8xx, storage 3) — ALL 57 BANKED**
  (`~/dev/switch/dumps/fw23-archives/`, 39,052 files): the route is
  **`fs cmd 10` (`OpenFileSystemWithId`) fsType 6 + archive title id** —
  fresh-boot reproducible, no promotion/license/context/uptime state
  needed. `tools/dump/sysarch-cmd10-batch.cjs` (resume-safe, completed
  manifests skipped). The two-day 206-refusal mystery ("per-boot budget",
  "carrier fatigue", identity classes, es licensing, fake contexts,
  uptime) was one wrong command id: fs 206's dispatcher mask-gates
  type-6 into the host flow (`@Host:` only) for EVERY session class —
  data archives are unreachable through 206 by design.
- **NCA-level structure**: every storage-3 system title carries exactly
  ONE content type (Program, attr 1); zero Control/HtmlDocument/Legal
  content in the system corpus (sysmodules ship no `control.nacp` —
  games-only). **No system updates exist on fw23.0.1** (storage 3 has
  zero `0x81` update metas; storage 4's 11 update metas are all game
  updates, banked per-game). Full inventory:
  `fw23/nca-structure.json` + the `FIRMWARE-DUMP.txt` structure section.
- **Live fs sysmodule + boot partitions + full-BIS session**: see
  `docs/DUMPS-CATALOG.md` for every non-game dump set with full sha256s.
- **Complete dump catalog** (every non-game dump, full sha256 per file,
  Discord-ready): **[`docs/DUMPS-CATALOG.md`](docs/DUMPS-CATALOG.md)**.

The dumped sets live outside this repo (per-boot evidence and ripped
content are gitignored); the lab copies under `~/dev/switch/roms/<id>/`
carry per-file sha256 manifests and a `game.json` ledger per title.

## Requirements

- **SmileBASIC 4.4.9** on a **Switch 2, system software 23.0.1**
- **Node.js 22+** on the PC (no npm install needed)
- Over **20 MiB free** in the SmileBASIC save
- PC and console on the same reachable network (for a lab, see
  `network/` for the isolated netns setup)

This fork adapts to both memory layouts observed before and after the
microSD Express support update (check System Settings → Support/Health &
Safety, item 3; if it shows **(B)** you are on the post-update layout).

## One-time setup

The lab console's program is already deployed (`TXT:NS2`, resume-aware:
`RUN` performs `REMOVE` itself and stops at the expected Out of memory).
For a fresh console or save, enter the distribution bootstrap program into
slot 0 and save it as `NS2` (the upstream
[pepsipu/ns2jb](https://gitlab.com/pepsipu/ns2jb) distribution carries it;
insert `REMOVE NSR,&H60000000,&H3FFFFFFF` after the `DIST BOOT READY`
print), then append the dial entry defs from `GO2.bas` — this repo's
single tracked `.bas` (placeholder tokens; regenerate with your own).

`pairing.cjs` persists a pairing token so fresh sessions reuse one dial
code. `pairing.json` is **gitignored — never commit it**; `GO.bas` (the
short `V=GO()` dial helper) is generated per session from it and is
likewise gitignored — it carries the live token and must never be
committed either.

## Run

1. Restart the console, open SmileBASIC, enter Direct mode.
2. On the PC: `./session.sh start` (or `node run.cjs [pc-ip]`).
3. In SmileBASIC: `LOAD "TXT:NS2"` → `RUN` (the **Out of memory** from
   `REMOVE` is expected) → then the printed **`V=START(...)`** line, or
   `V=GO()` after saving the helper.
4. Wait for **SESSION READY** (acquisition is timing-sensitive; the
   pipeline retries 3x per boot, ~50% per attempt on our consoles).

Keep SmileBASIC open and the PC awake. `session.sh resume` re-attaches
after a PC restart without re-acquiring; the console re-dials on its own.
`session.sh stop` requests clean teardown; a hard host kill (SIGKILL)
preserves console-side state for a later resume. A console reboot resets
everything — dance again.

## Dumping game content

With a READY session, dump any **installed** game's decrypted content —
base game, no launch, no app switch:

```sh
sudo -n ip netns exec switchlab runuser -u nlight -- \
  node tools/dump/game-dump.cjs [title-id] [--out DIR] [--probe] [--bulk]
```

- Title ids on fw23 are 0400-prefixed; the default target is Mario Kart
  World (`0400c3f00006e000`). `--probe` mounts, checks size + RomFS
  header, writes the file list, and stops.
- The full run streams every file with a resumable manifest (per-file
  sha256; re-running continues where it stopped — across console
  reboots too). `--bulk` switches to 4 MiB RPC-transfer chunks (the fast
  path on a fresh carrier).
- Sections: `--content base|update|all` × `--section romfs|exefs|control|all`;
  `--control` pulls just the control NACP, `--overlay` the active-overlay
  romfs (running-app titles only).
- The base route: NCM metadata DB → content path + attributes → rights id
  (ncm cmd 20) → `es` cmd 503 license (with the export-rights context +
  linked-account dance for owned content) → fs cmd 206
  `OpenDataStorageByPath` → decrypted RomFS as IStorage.
- The ExeFS side opens through ldr:ro cmd 0 (`OpenCodeFileSystem`) on the
  cloned loader root — same session, **hot window**: granted early after
  acquisition. Run the dump IMMEDIATELY after SESSION READY, nothing
  between (identity/SMM probing after arming poisons the loader context
  and costs the boot).

Update content (the composed view the running process loads) needs the
registered-patch route: `tools/dump/update-exefs.cjs` and
`tools/dump/update-romfs.cjs` (self-contained; see FINDINGS for the full
chain). The update RomFS streams the full composed image and then
materializes the **LayeredFS overlay tree** (just the delta files) via
`tools/dump/finish-overlay.cjs`. Everything arms console state records
it (`dump-state.json`) and removes it on re-run — never leave armed
state behind on a wedged run.

**Console health (learned the hard way):** dump rate is a function of
carrier freshness. A long-lived carrier degrades badly (18 MiB/s →
35 KiB/s observed over one night); bulk chunks and fresh re-attaches do
NOT fix a tired carrier. When the rate collapses: power-cycle, dance,
resume — the manifests continue. The watchdog
(`tools/dump/dump-watchdog.sh <floor-KiB/s> <log> [args]`) monitors a
RUNNING dump (launch the dump first, then the watchdog) and clean-stops +
relaunches on stall/rate collapse, max 2 bounces.

## Optional system-code dump

`node dump-firmware.cjs [pc-ip]` (or `run.cjs --dump-firmware`) completes
the normal 4/4 exploit, then asks NCM for all installed system programs
and captures each accessible CodeFS `main` + `main.npdm` — decrypted,
with sha256 manifests, into `dumps/`.

## Safety (read this first)

- **Never restore or restructure a save while takeover state is armed**
  (cloud restore, save copy/download from system settings, any
  container-level operation). Reboot the console FIRST; a failed
  acquisition leaves the machinery armed until rebooted.
- **Keep the console offline** for this work — cloud save auto-sync with
  an armed takeover is a brick scenario reported in the community.
- All write tooling is file-level, post-READY only, and Commit-verified.
  SYSTEM-partition writes are gated behind an explicit flag for a reason.
- Full operating rules, failure classes, and recovery economics:
  `docs/OPERATIONS.md` and `FINDINGS.md`.

Use this only with your own console and your own games. Do not share
anything you rip with it.

## Repository layout

```
run.cjs, session.sh      host entry points (session lifecycle)
engine/                   exploit pipeline, retained-memory machinery,
                          RO payload + executor (zig), BIS/fs dispatch
tools/                    all lab tooling — see tools/README.md
  dump/                   game-content + firmware dumpers (game-dump.cjs,
                          sysarch-cmd10-batch, update-exefs/romfs, sweeps)
  memory/                 window-slide drivers, identity promotion
  pm/, rig/, bis/, mount/, hipc2/, npdm/, session/, maint/
  ghidra-scripts/, NS reversing tools
docs/                     ARCHITECTURE, OPERATIONS, RIG, surveys, research
  DUMPS-CATALOG.md        complete sha256 catalog of every non-game dump
FINDINGS.md               the distilled research fact log
FIRMWARE_FINDINGS.md      fw23 system-code + HIPC2 research
USAGE.txt                 step-by-step session operation
NEXT-RUN.md               live experiment queue
bootstrap.bas            the COMPLETE console program source (placeholder pairing
                         tokens); GO.bas is generated per session (gitignored)
network/                  isolated lab netns setup
experiments/              payload experiments (build via engine/build-*)
```

## Code

`run.cjs` is the host entrypoint; `engine/switch2/pipeline.cjs` holds the
launch sequence; the native helper and its source live in
`engine/switch2/ro/payload/`. The payload builds with Zig 0.15.2:
`node engine/build-payload.cjs --check --zig /path/to/zig`.

Test suite: `node --test test.cjs session.test.cjs find-metadata.test.cjs`
(+ `tools/maint/audit-runs.test.cjs`, `engine/switch2/memory/cache-window.test.cjs`).
