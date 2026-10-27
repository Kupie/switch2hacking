# FINDINGS

Important discoveries only. Not a worklog — process notes live in
`docs/RIG.md` and `docs/OPERATIONS.md`. Entries dated; each one changes
what we do next. Distilled 2026-10-25: superseded-theory narratives were
compressed to their final conclusions; all durable facts retained.

## Safety-critical hardware rules (A78C, fw 23.0.1)

- `dc ivac` is a **process killer** at EL0 (live-proven twice); blind EL1
  `mrs` is the same class. Experiment code must never emit either.
- `PMUSERENR_EL0` = 0 (no PMU at EL0); `CNTFRQ_EL0` = 31.25 MHz (32 ns/tick)
  is the only userland timer.
- Monitor payload `.bss` launch-death limit: between ~1.06 MiB (safe) and
  1.18 MiB (died) — keep payloads under ~1 MiB.
- The L3/DSU side-channel research track (shared-L3 eviction sets, sweep
  amplification, pointer-chase construction rules) is ABANDONED for now;
  its experiment sources were removed 2026-10-25. The measured facts live
  in git history if the track is ever revived.

## Session & carrier mechanics

### The fs native-read livelock and the retarget budget

The console fs process stochastically stops answering sustained round
trips through the retained session. Model (from a 34,693-entry op
ledger): **the budget unit is the DISTINCT-WINDOW RETARGET (~10-15 per
boot)**. In-window cycle-walk ops are effectively unlimited (20k+ ops in
one window proven; acquisition waves run 30k+). Wedge risk is a per-boot
retained-STATE-QUALITY property, front-loaded after the retire
transition: fragile boots die within the first few hundred post-ready
ops; survivors are stable for tens of thousands. Rules: keep
distinct-window touches under ~10/boot; batch work into single
windows; accumulate across boots; escalate off the fs session.

Not fixable from the PC once it hangs (the BASIC handler blocks inside
the native call). A wedge = reboot. PC-side cascade signature: console
wedge → child RPC timeout → child exits cleaning `/tmp/ns2-*/memory.sock`
→ downstream `connect ENOENT memory.sock` + `Native request timed out; it
was not replayed` = **console wedge happened first**, not a PC crash.

### Launch-window fatals

Console fatals (2162-0002 / 2021-0003) correlate with the post-launch
window of a PM/Loader dance, but four dances on one boot produced zero
fatals: it is a **per-dance dice roll**, not a near-certainty. The fs
host often wedges first and the fatal is the cascade. Operating rules:
the monitor ships via the boot pipeline (zero redeploys); after any
dance the first minutes are quiet — no liveness IPC storms.

### Session identity: strong/weak lottery, root-caused and FIXED

The hijacked fs-heap session that becomes the RPC root behaves per boot
as strong or weak. Root cause: **which process executes the memory-side
RPC worker threads** (apiWorkers). Weak = app identity (pid 207): cmd 2
returns 0x0 (the app's own RomFS), BIS denied. Strong = non-app
identity (helper/pid-1 class): cmd 2 returns **0x1408**, full-trust
fallback, BIS opens.

**Fix (live-proven, deterministic)**: `fix-session-identity.cjs` — write
the helper's pid (8, null-title full-trust class) into the three graph
fields (root+0x30, chase(root+0x18)+0x38, chase(root+0x28)+0x40) via
compare-verified retained writes. Arbitrary pids work too (`--pid N
--force`): promoting to am (158) gives am's fsaccess; to ns (167) passes
the fsaccess gate. The aliased graph fields make the last compare-write
fail harmlessly; the promotion still takes. **Never re-run
root-initialize after a promotion** (it rewrites root+0x30 with the RPC
executor's pid).

**Strength oracle (5 s)**: root-open, `root-native-ipc {handle: root,
id: 2, hex: ''}` — `0x1408` = STRONG, `0x0` = WEAK (promote or re-dance).

### Rig session-slot discipline

The monitor tracks `sessions[4]` — every unclosed `Client.open()` leaks a
slot; four leaks = all rig opens transport-timeout. Close in `finally`,
or free leaked ro:dmnt handles via `root-native-close-handle` (proven
live, 4/4 freed).

## NPDM & escalation

### fw23 NPDM format (empirical)

Differs from the pre-20.0 wiki in one place: the **ACID signature block
is 0x300 bytes** (sig 0x100 + pubkey 0x100 + 0x100 extra), not 0x200.
Flags at magic+0x0C, pid range +0x10, fac/sac/kc offset+size at
+0x20/+0x28/+0x30 — offsets relative to the ACID section start (META
@0x78), not the magic. ACI0 unchanged (kc @+0x30/+0x34, ACI0-relative).
KAC descriptors = classic trailing-ones encoding (SVC descriptor type 4:
bits24 = (d>>5)&0xFFFFFF, index = (d>>29)&7). `npdm-tool.py` decodes.
ro on this console: **55 final SVCs** (0x01–0x29, 0x34/0x35, 0x40–0x45,
**0x73–0x78** — SetProcessMemoryPermission/Map/Unmap/Query/MapCode/
UnmapCode); no debug suite, no CreateProcess, no CallSecureMonitor.

### Escalation architecture

We control the NPDM our monitor launches under (donor-prepare stages
`main` + any captured `main.npdm`). Any sysmodule NPDM is obtainable
read-only (`root-native-code-open` + `file-capture`). The intended
escalation was: strongest policy → `0x60 DebugActiveProcess` →
`0x6A/0x6B` cross-process R/W. **Closed on fw23** (see Closed routes).
`0x74 MapProcessMemory` works but refuses fs heap (t5, 0xd401 — all
attribute classes) and is restricted to t3/t4 for the 0016 rig reads.

### The staged-NPDM origin wall

**Staged-NPDM fsaccess is IGNORED by fsp-srv**: a patched 0037 monitor
(ns's fsaccess bits 4/6) behaves identically to flags-0 for cmd 10.
Takeover-launched processes get neither the staged NPDM's permissions
nor the real title's — an origin-based wall (same class as the executor
sm-namespace finding). NPDM patching remains a lever for the LOADER
(binaries run fine) and the SVC mask (kernel-side), never for fsp-srv
caller checks.

## fw23 IPC facts

### fsp-srv command set and error map (module 2)

- **cmd 7/8 are GONE and kill the session instantly** (unknown-command
  close). cmd 10 (OpenFileSystemWithId, {u8 attr, u32 fsType, u64 id} +
  path buffer) is the only path-based open. cmd 9/201 (by-id) are
  title-state-gated, not caller-gated: installed-but-not-running games
  return fs 2-77 from every caller. **cmd 2** handle rides in
  **reply.moves[0]** (copies stays empty). cmd 618 = GetProgramIdByPath
  (u8 attr + X path buffer).
- Errors: desc 6400 (0x320002) = caller fsaccess denied; desc 6001/6000
  (0x2ee202/ee002) = launch-authorization family (fsTypes 1 Code, 8
  RegisteredUpdate); desc 77 (0x9a02-class) = by-id lookup miss for
  not-running titles; 0x299002 = content-registry miss (user content);
  0x1fb402 = fsType-class mismatch; 0x7d802 = NcaExternalKeyNotFound;
  0x1408 = no data filesystem for current process (the STRONG oracle).
- **fsaccess bit → FsFileSystemType**: flag bit N maps to fsType N+2.
  bit 4 = ContentData (only ns carries it), bit 6 = RegisteredUpdate
  (am, ns, migration). Base game data RomFS = fsType 6 (bit 4); updates
  = fsType 8 (bit 6).

### Content path format (from ns/settings statics)

- Mount names: `@User`, `@System`/`@System0`, `@RegUpdate`, `@GcApp`/
  `@Gc`, `@Host`, `@upp`, `gcdata`; `@Umc`/`@UserContent` are NOT mounts
  — **`@UserContent://` is the live user-content prefix** (the string fs
  cmd 10 wants, and what ns:am2 cmd 21 returns).
- Content paths: `@UserContent://registered/<8-hex-dir>/<32-hex>.nca`;
  raw BIS form `@User:/Contents/registered/...` resolves as a real path
  but content opens still hit the registry wall.
- MKW (fw23 numbering): base app `0400c3f00006e000` v0, update
  `0400c3f00006e800` v917504. The 23.37 GB NCA `bc97cbf31eab065923e05c01a6de49ed`
  in registered/00000061 IS the program NCA (single-NCA game — RomFS is
  embedded; there is no separate data NCA). App ids in NCM on fw23 are
  0400-prefixed.

### ncm & ns recipes

- OpenContentMetaDatabase (ncm cmd 5, [storage]) + ListContentMeta (db
  cmd 5, {metaType@0, title u64@8, min u64@16, max u64@24} — binary
  range walk with full-u64 bounds; capacity-bounded lists recurse on
  total>count, GetLatestContentMetaKey at min==max).
- GetLatestContentMetaKey (6), GetContentIdByType (3, {type@0,
  key16@8}), GetContentInfoByType (24, same input; **attributes =
  info[21] & 15**), OpenContentStorage (ncm cmd 4).
- **IContentStorage GetPath (cmd 8) and GetPlaceHolderPath (9) KILL the
  session** for our callers (both descriptor forms, before/after
  activation) — the path oracles via ncm are sealed; use ns:am2 instead.
  Harmless storage commands: cmd 7 Has, cmd 12 count, cmd 13
  ListContentId (map-alias mode 0), activation, GeneratePlaceHolderId.
  (External validation 2026-10-25: cmd 8 with a fixedOutput receive
  descriptor DOES work from the app-session attach path — the killer is
  caller/dispatch-context dependent, not the command itself.)
- **ns:am2 content-path oracle**: cmd 7996 → IApplicationManagerInterface;
  cmd 21 on that object ({type u8@0, u64 app id@8}, 0x300 out) → the
  exact registered content path. Open ONE ns:am2 + ONE 7996 object and
  reuse for all queries (a fresh 7996 per app crashed ns: 2162-0002).
  cmd 21 breaks while the session identity is ns — order path queries
  before any promotion.
- Known session-killers: **fsp-srv cmd 7/8, ns:am2 cmd 21/604 sent to the
  session itself (must go via the 7996 object), ncm IContentStorage
  buffer commands from the rig caller, wildcard-tid (0xffff..ff) content
  mounts (suspected in one app crash), GetThreadContext3 (svc 0x36) with
  the current-thread pseudo-handle (console-wide freeze candidate),
  never sweep a CONTROL service (pm:shell) with a live-pid payload —
  ids 7-8 froze the app; use dead-pid baselines.

## The content-mount walls (final matrix)

| identity | cmd 10 (content) | cmd 2 | notes |
|---|---|---|---|
| helper/full-trust (pid 1/8) | 0x320002 / 0x1fb402 | 0x1408 | fsaccess gate |
| app (pid 207) | 0x320002 | 0x0 (own RomFS) | same gate; only cmd 2 works |
| ns (pid 167) | gate PASSED → 0x1fb402 type-class; valid big paths BLOCK | 0x7d202 | fs resolves the real ns process; a valid 23 GB path open blocks the whole controller (no per-request timeout) |
| am (pid 158) | 0x320002 | — | am lacks the ContentData bit |

- **Registry theory CONFIRMED**: titles enter fs's per-boot content
  registry only when they LAUNCH. Installed-but-not-launched games are
  absent → every by-path content open fails 0x299002, every by-id open
  fails 0x9a02, regardless of caller identity. The registry is GLOBAL
  per-boot state (session tid-swap at root+0x1b8 is INERT — cmd 2
  resolves current-process→program through the global registry).
- By-id opens are sealed to the program itself; the app's own cmd 2
  works (first RomFS mount+list milestone proven — SmileBASIC RomFS
  12 root entries).
- **Never send an fs cmd-10 open for large registered content without a
  plan**: one hung IPC wedges ALL PC-side commands until reboot (the
  controller serializes; no per-request timeout).

## THE DUMP ROUTE (path-based content mount, no launch, no pm) — SOLVED

External-tool analysis (OunceCake) + live validation produced a
content-mount route that bypasses every wall above:

1. ncm OpenContentMetaDatabase(4) → ListContentMeta binary range walk
   (metaType 0x80, wildcard title, full-u64 min/max) → app ids.
2. GetLatestContentMetaKey / GetContentIdByType / GetContentInfoByType
   (db cmds 6/3/24) → NCA id + attributes (info[21] & 15).
3. IContentStorage GetPath (cmd 8, fixedOutput receive descriptor) →
   `@UserContent://registered/<dir>/<nca>.nca`.
4. IContentStorage GetRightsId (cmd 20) → rights id + key generation;
   **es cmd 503 PrepareTitleKeyByRightsId** (send buffers: rights 16 B +
   generation 4 B) registers the external key — without it fs returns
   0x7d802 NcaExternalKeyNotFound. (0x1491/0x691 = owned-content context
   required — not hit for MKW.)
5. **fs OpenDataStorageByPath (cmd 206, [attributes, u32 1], path) →
   the DECRYPTED RomFS as IStorage.** MKW: 23,279,528,016 bytes
   (21.681 GiB), valid RomFS header, reads via IStorage cmd 0
   `(0, offset, size)` + cmd 4 GetSize.
6. ExeFS: ldr:ro cmd 0 (OpenCodeFileSystem) on a cloned loader root,
   `[attributes, storage, title u64]` → CodeFS IFileSystem (from the
   `-loader-root-copy.json` evidence handle).

Live-validated end-to-end on 92LuGr (mount + size + header + reads).
Lesson from the external tool's death: keep the flow minimal (one mount,
no update/DLC metadata walks), 256 KiB verified chunks, checkpoint
often. Our implementation: **game-dump.cjs** — our Session/domain/paths
primitives, resumable manifest, per-file sha256.

## The window-slide primitive (arbitrary fs VA read/write)

- `memory.read/write` (the Memory client) → `retained-read/write` →
  `setPointer` (descriptor u64 target write in the control bucket) —
  **fs itself dereferences the 64-bit descriptor target**: arbitrary fs
  VA read AND compare-verified write, 16 KiB/round. Guards relaxed
  2^39→2^48 (retained-memory.cjs setPointer/readMemory + fs-memory.cjs);
  bootstrap channels stay conservative.
- **Hot-reload**: the run-dir `retained/retained-memory.cjs` and
  `memory/fs-root-control.cjs` are `freshRequire`d per request — edit the
  run-dir copy for live behavior changes.
- Driver rule (ueJtC): `fs-heap-chase.cjs` validates every slide target
  against **this boot's own 0010 walk** (regions.json); `--slide-raw`
  only for recorded proofs. Never blind-read outside the walk.
- svc MapProcessMemory (0x74) categorically refuses fs heap (t5 →
  0xd401, all attribute variants); the slide bypasses it (fs reads its
  own memory through the armed cache).

### fs live map + registry structure (QbXIKZ boot; per-boot delta)

- fs module: L1 0x82d600000+0x23e000 (t3 **p4 execute-only text**), L2
  +0x58000 readable text (= fsText qualification anchor), a16 gap
  0x82d896000+0x11000 (vtable region), L3 0x82d8a7000+0x7c6000 (readable
  rodata). fs heap t5 RW: 0x7964660000+0x1fa0000 (31 MB),
  0x7966600000+0x1810000 (24 MB), 0x7968000000+0xe00000.
- **Uniform per-boot delta: elf = live + 0x5164a00000** (QbXIKZ; all
  three LOADs; recompute per boot from the qualification fsText base).
  Live LOAD-3 banked (8.1 MB) = fs-live.elf build **96.4% byte match**
  (live relocations only) — elf reversing notes are offline-valid.
- PTR_LOOP_59922a7030 = the fsp-ldr SetCurrentProcess assoc list — an
  EMPTY self-linked sentinel, NOT the registry. The real registry = the
  root-graph per-program entries: **root+0x1b8 = the running app's tid
  inline; root+0x1d8 = the per-program registration entry** — a
  polymorphic C++ object with 13 vtable-class fields; the 0x58-byte
  node class (vtable 0x59922997d8, ctor FUN_5992160c20 = the 0x10/0x4000
  FAH/FAC blob-load path) instantiated 3× inside it; entry+0x1e8 = the
  inline-path-entry family; 0x82e223150-class = the mounted-path tree;
  entry+0x368 = a second program id (0x1a-class, boot modules).
  FAH/FAC buffers are heap allocations reached through deeper graph
  tiers, not stored flat.
- fsp-pr service object decoded (elf 0x599229d0c0, 8-slot vtable); the
  RegisterProgram handler remains to be located — the fallback manual
  registration route via slide-write.

## Closed routes (do not re-run)

- **svc-debug (0x60/0x69/0x6A)**: fw23 DebugActiveProcess is
  **caller-authorized beyond the SVC mask** — creport works because pm
  launches it as a crash agent; attaching to a running sysmodule from
  our takeover-launched monitor kills the attacker (3 monitor kills
  with a correct-class ABI). Creport ground-truth fw23 ABI: 0x60/0x69 =
  x0-in = out-pointer, kernel returns result in x0 + value in w1
  (two-INTEGER struct return); 0x6A/0x63/0x67 plain pass-through.
  svc 0x65 is NOT GetProcessList on fw23 (creport contains no 0x65) —
  never call it. The read-only debug suite in the staged 0037-boot NPDM
  (0x60/63/67/69/6A/6D, no 6B) is real but unusable without a debug-
  authorization primitive.
- **pm handle hunt**: stock pm never returns PROCESS handles — cmd 3
  returns an EVENT handle (GetProcessEventHandle-class, ignores the pid
  input; rig 0010 on it → 0xE421). Unknown ids on pm:dmnt kill the
  session instantly.
- **pm LaunchTitle (create-only route)**: refused with desc-02 (a
  uniform per-boot refusal — even sysmodule titles, even as a fresh
  boot's 2nd launch — budget theory FALSIFIED on 92LuGr's successor).
  Result encoding: byte0 = desc (02 refuse, 08 not-found), bytes1-3 = a
  tick counter. Acceptance historically correlated only with the staged
  gate-dance launches (acquisition monitor + the lUQn26 MKW test). The
  content-mount route above supersedes this entirely.
- **Executor relay (two-process design)**: takeover-launched processes
  live in an sm namespace that cannot see system-registered names
  (GSH blocks); our own registrations are visible-but-denied. svc 0x21
  TLS transport never works from a takeover-launched process (loader
  doesn't set tpidrro); svc 0x22 user-buffer works through
  InitializeClient. Closed with the single-monitor design.
- **Session tid-swap**: inert (global registry). **By-id mounts**: sealed
  to self. **NPDM fsaccess patching**: origin wall (ignored).

## Recovery economics

- Monitor death ≠ boot loss: the worker joins cleanly;
  `deploy-monitor.cjs --terminate-first` restores a live monitor in ~3
  min. BUT a mid-session redeploy can leave ro:dmnt NAME-WEDGED (sm
  serves the dead registration; sends → 0xF5E1; the new monitor's
  register retries forever) — a fresh boot dance is the clean path.
- The sm-get wedge: a dying monitor leaves a released sm-get worker
  blocked inside sm on an unregistered name; every worker consumer gates
  on `worker.joined` → the launch dance itself deadlocks. Console reboot
  is the only exit. Never leave a stale host listening on the dial port.
- The acquisition lottery is ~50%/boot with 3 same-boot attempts
  (fresh probe re-run per attempt). A failed acquisition leaves the
  console armed — see docs/OPERATIONS.md brick-safety rules.
- Session sm budget: ~4-6 service opens per name per boot (exhaustion =
  0x615); open once, close right after.

## Persistence facts

- **USER:/temp is BOOT-VOLATILE** — fs purges it at boot (all markers
  absent across reboots). Persistent writes need a non-/temp USER path
  (the write gate currently restricts to /temp) or a save area.
- **Leaked scratch orphans cause deterministic 'Insufficient save
  space' acquisition failures**: each wedge/crash that skips retire()
  leaks a 16 MiB NS2_GAP_<ts> commit_data dir. The 1/4-stage orphan
  sweep (cleanup-scratch.cjs, age-guarded 60 s, contents-verified)
  runs on every start; NS2_NO_ORPHAN_SWEEP=1 disables.

## External intel (2026-10-25, user-relayed)

The "kernel-protected vtable region" wall record (7.2t-era) is
contradicted: an external FWDump capture (`fs-vtable-0x5af2296000.bin`,
282/512 pointer qwords at page 0) proves the region readable by their
path, and they hold a **complete fs main.nso (10,932,496 B, buildId
094c1cae…)**. Correction (7.2u): the wall was CROSS-PROCESS only — the
in-fs-context copy-region/memcpy class reaches it. The complete main.nso
preempts part of the live-read prize; the content-mount route makes
chasing their dump path optional.

## 2026-10-25 (session 7qEq1b post-mortem) — carrier death by hard-kill mid-RPC; long-run slide limits

The MKW dump session died after ~90 min / ~700k+ slide rounds (~35× the
previously-proven 20k-round envelope). Chain of events:

1. **Rate degradation 4.6 → 1.5 MiB/s over the run** — the boot's retained
   state aging under sustained slide traffic (symptom, not a fault state;
   the dump was still completing files and hashes).
2. **The watchdog "bounce" sent SIGTERM to the dump process mid-RPC
   round-trip** — an abandoned in-flight retained-session request. The
   carrier/wave machinery has no tolerance for this (the no-replay rule
   exists for exactly this reason): the app-side handler state broke, the
   retained endpoint stopped answering, the controller correctly reported
   "no ready retained endpoint on the current boot". Session dead; reboot
   required.

**Rules going forward:**
- **Never hard-kill an RPC client mid-request.** game-dump now handles
  SIGINT/SIGTERM as a CLEAN STOP: finish the current chunk, checkpoint the
  manifest, close handles, exit (resume-safe). The watchdog bounces via
  SIGINT + a 45 s grace and only SIGKILLs (with a warning) if a clean stop
  never lands.
- Long dumps on one boot should expect slide-rate decay; plan rotations as
  clean detach/reattach at file boundaries, never mid-chunk kills. (The
  console-side TCP streamer was retired — superseded by the coalesced
  window reads + --bulk transfer path; see the 2026-10-26 post-mortems.)
- Resume economics proven: 29,104 files / ~4 GiB banked across two
  interruptions with zero hash mismatches.

## 2026-10-25 (6ZLeKP post-mortem) — the sm budget is GLOBAL per boot; delivery discipline

Tonight burned a full boot's service budget before the emulator deliveries
landed. The budget (~4-8 opens) is **global per boot across all service
names** — not per-name: four ad-hoc archive attempts (each a fresh process
re-opening ncm) plus probe re-runs exhausted it; ns:am2 then refused having
never been opened once (0x...8192-class refusals, desc 92/93 with tick
bytes). System content facts landed along the way:

- System data archives (the 8xx titles, e.g. TimeZoneBinary 080e) register
  under **metaType 0x02** keys in the BuiltInSystem (storage 3) database;
  system programs under 0x01; app/game content stays in storage 4/5.
- Archive NCAs resolve to **@SystemContent://registered/<nca>.nca** paths.
- Mount class matters: type 1 (program) → launch-auth family error for
  archive NCAs; **type 6 (data) → the fsaccess gate** (0x320002 — the
  natural identity lacks the ContentData bit; ns carries it). The archive
  mount therefore needs the ns-identity promotion + type 6.
- pm:dmnt id-7 sweep: reply program-id parse is dual-offset (0 or 8);
  single-offset parses have read zeros on some boots.

Delivery discipline (now in game-dump.cjs as one bundle): all deliveries are
phases of ONE attach — control path queries first (natural identity;
ns:am2 cmd 21 fails under a promoted ns identity), archive dump with the
fsaccess->ns-promotion fallback, control mount retry under the promotion,
identity restore, then the content stream. resolve-state sidecar makes
transport bounces cost zero service opens (saved source + lazy re-license
on 0x7d802). Watchdog rate-bounces capped (each bounce = fresh attach =
budget burn). No ad-hoc probe re-runs on a delivery boot.

## 2026-10-25 (t02Ljl) — update-content facts (SmileBASIC v1048576 matrix)

- **cmd 10 OpenFileSystemWithId mount id = the OWNING APPLICATION tid**
  (base app id), never the update tid or content id: base tid + type 3
  opens the 4.4.9 update control NCA; update tid -> 0x235e02
  (InvalidNcaId). Update control NCA:
  `@UserContent://registered/00000036/1303f221180ea10a9f828d2a8dcd6df1.nca`.
- **Base and update ExeFS are byte-identical** for SmileBASIC (both keys
  resolve to program NCA `9c366949...` in 000000A3; the installed base
  program NCA self-identifies 4.4.9 — the base NCA was updated in place;
  a true 4.0.0 executable is NOT reachable through NCM on this console).
- **Update RomFS via fs 206 is a DELTA VIEW**: GetSize reports the composed
  size (144,827,272) but only ~26 MB is readable (frontier 0x18f3200);
  the header shows data@0x200 (data-first builder layout), metadata at
  ~145 MB — unreachable in the raw delta view. The console composes
  update-over-base at mount time; a flat IStorage dump of the composed
  image is NOT available in-band. The update's own delta files ARE in the
  readable prefix. PC-side composition (delta tables + complete base tree)
  remains possible.
- Update joint-license chain (base license + update license, es 503)
  WORKS live: both prepare cleanly, mounts accepted.

## 2026-10-26 (V5iho9, post-completion) — MKW ExeFS wall: ldr:ro cmd 0 refused; the loader key path

MKW base RomFS COMPLETE (205,660/205,660, 21.67 GiB, manifest repaired offline —
the rest-loop manifest-recording bug was clobbered entries, no data lost; fix
f526e44). The remaining standard sections hit a wall on this carrier:

- fs 618 (GetProgramIdByPath) works on MKW's program NCA without a fresh es
  license (the key registered by tonight's earlier --fast runs persists for
  the boot in fs) -> runtime id 0x400c3f00006e000.
- ldr:ro cmd 0 (OpenCodeFileSystem) on that runtime id: 0xd387d802
  (NcaExternalKeyNotFound) — the LOADER resolves the program NCA's key through
  its own es path, which was never registered for MKW this boot.
- es service: budget-dead on this carrier (all opens refused across both
  session paths — the boot's sm namespace is spent for es/ncm).
- LaunchTitle create-only (mkw-create --create): 0xd407d802 (desc-02 family —
  the uniform refusal recorded 2026-10-25).

=> MKW ExeFS (base + update) needs: es openable (license + ldr key
registration via the pm-launch path or the loader's own resolver) — i.e. a
fresh carrier boot. SmileBASIC ExeFS worked tonight because its rights id
(gen 0) licensed cleanly and its loader context was the running app's.

## 2026-10-26 (rqphnE) — es is a per-boot SAC wall: opens ONLY with the wave's own identity (desc 0x192 = not-registered)

Fresh-boot es probing matrix (per-boot, name es):
- bare Session (wave default identity): direct GSH + sm-packet both refuse
- Session under the SmileBASIC APP identity (promoted pid 207): refuses
- Session under the helper identity (pid 8): refuses (earlier boots)

But es 503 LICENSE calls WORKED all week — always from sessions whose
identity was the WAVE'S DEFAULT (the acquisition pipeline's own root
session, pid 1/None class). The es service registers per-boot SAC entries
for exactly the wave/session identity class the acquisition creates. A
fresh plain Session created post-hoc carries a DIFFERENT client identity
(the monitor clones get fresh session ids) and es rejects those.

=> es opens are NOT budget-limited — they are IDENTITY-gated per boot, and
the working identity is the acquisition root session's. Use the memory-
controller's root-native-* IPC path (which rides the acquisition session
identity) for es calls, or run the license inside the pipeline's own
context. The game-dump Attachment.service worked earlier because those
boots' session shapes matched; tonight's fresh Session does not.

## 2026-10-27 (offline corpus) — the acquisition state oracle is per-boot; decided-miss boots are dead; extent-qual-fail boots are geometry-dead

Full-corpus mining of the acquisition reports (366-run snapshot, both code
eras; tool `tools/analysis/mine-acquisition-states.py`, full tables in
`docs/acquisition-state-mining.md`). Current era 20/62 READY (32%). The
facts, each one load-bearing (numbers post the 2026-10-27 corpus-hygiene
fix — the `native-link-candidate` evidence glob-phantom inflated the
first draft's EMPTY-class rescue numbers):

- **Cross-run state tables are DEAD**: of 136 state fingerprints that repeat
  across runs, 76 are outcome-mixed (46 same-era); a majority table
  misclassifies 23% of waves in-sample. Same fingerprint, same era, opposite
  outcomes exists as a concrete pair. The 16-counter oracle is usable
  per-attempt only (59/63 within-attempt groups consistent — strong, ~3%
  flips, in three runs: two old-era, one current-era).
- **No pre-positive classifier** — reconfirmed at 3.5x the frozen cohort:
  every univariate AUC 0.50–0.56. Early-abort stays dead.
- **`preReleaseUsed` floor 9920 is exact** (min over all windowed hits, both
  eras) but catches ~1% of misses — a free post-wave guard, not a lever.
- **First-hit wave ≤ 3 in every current-era passing attempt** (≤ 4 in
  222/223 all-era). The retryWave budget is NOT being changed — the
  all-era wave-6 first-hit means a cut below 6 risks a placement for zero
  real savings (F9: doomed boots die at the decided miss anyway).
- **Same-boot rescue after a placement-class failure: 0/41 across both
code eras — the regression hypothesis is FALSIFIED, and the phantom-
corrected rescue table kills the "EMPTY retries save boots" story too**:
  every attempt-2/3 after a placement-fail is EMPTY (console wedged —
  36/41 with fs-wedge signatures). Phantom-corrected same-boot rescue:
  EMPTY-first 0/13 (old), SETUPFAIL 47% old / 25% new, EXTFAIL 43% new.
  Reboot is the only recovery after placement fails. **Source archaeology
  (run-dir probe snapshots vs current): the retention semantics are
  line-identical** (`placementUncertain` gating, same "retain resources"
  strings) — no arming regression exists. What changed: the old probe
  burned locate-canary + a 6-extent miss-sweep before dying (the 410-wave
  dead sweep); the current probe fails fast. Same console death either way.
  **Mechanism: the miss wave itself** — a clean miss (changedPaths empty)
  means the ~8.7 KB 'B' payload landed in an *unwatched* fs heap allocation;
  36/41 dead boots show fs-wedge signatures (socket hang up = the BASIC
  handler blocked in a native call; native batch unjoined = workers' fs
  RPCs unanswered) — inherently unrecoverable same-boot. **Minority
  recoverable class: 5/41 old boots reached attempt-2 setup and failed
  deterministically on "Insufficient save space" — fs was ALIVE**; the
  retained 16 MiB commit_data scratch (retention skips the `created`
  cleanup) starves the 20 MiB save-free check. An inter-attempt scratch
  sweep (existing cleanup-scratch logic run between acquire attempts)
  rescues that class. After a decided miss: FAIL FAST with an explicit
  reboot-required signal — two more 25-min attempts are pure burn.
- **Extent-prefix diagnostics prove recoverable geometry and are then
  discarded**: 84/105 diagnostic waves on the 12 extent-qual-fail attempts
  carry the full qualification signature at alternative prefixEnd — those
  boots are geometry-dead, not boot-dead. No consumer exists today; a
  prefixEnd-adaptive qualification is a research design (payload/marker
  offsets assume 9280).

Rules going forward: no cross-run tables; per-boot steering only (compare
against THIS attempt's recorded states, steer with a varied-size alloc/free
when a repeat is detected); drop the extent-prefix wave diagnostics (zero
consumers, 155 corpus waves); fail-fast with an explicit reboot-required
signal after placement-class failures (policy-verified against the corpus:
zero success regressions, 61 futile attempts not re-spawned). The positive
wave budget stays as-is — a cut below 6 risks one all-era placement for no
real saving (F9: doomed boots die at the decided miss, not in the tail
waves).

## 2026-10-27 (code changes applied, policy-verified offline)

Two changes shipped to the engine after offline verification (see
`docs/acquisition-state-mining.md` §"Policy replay — verification of the
2026-10-27 changes"):

- `engine/switch2/acquire.cjs`: a placement-fail gate — when a failed
  attempt's report shows ≥1 positive wave and no `markerSelected`, the
  retry loop stops immediately with an explicit **console reboot
  required** error (`.rebootRequired`). Corpus replay: 0/81
  acquisition-success runs change outcome; 139 failing runs terminate
  with the explicit signal instead of burning 61 provably-futile extra
  attempts. Transport/setup/extent failure classes keep their retries
  (phantom-corrected rescue: SETUPFAIL 25–47%, EXTFAIL 43%).
- `engine/switch2/memory/probe-reserved-gap.cjs`: the extent-prefix wave
  trials are removed from the extent-qualification failure path; the
  cheap read-only normalizer-acceptance lookups are kept. The wave data
  they produced is already mined (F7: 84/105 alternative-geometry waves
  carried the full qualification signature) and nothing consumed it.
- The inter-attempt scratch sweep and the positive-budget cut from the
  earlier proposal are DROPPED as unsupported: the sweep is already covered
  by the next boot's stage-1 orphan sweep (60 s age guard), and the budget
cut risks a placement for no real saving.

Engine edits are inert to a session that is already running (the pipeline
executes its run-dir source copies; a live session was mid-acquisition
when the edits landed and was not touched).

## 2026-10-26 (rqphnE, continued) — MKW ExeFS: license SOLVED via controller; cmd-0 is a hot window

The es wall decoded: es opens are IDENTITY-gated per boot, and the identity
that works is the acquisition/wave session (`root-native-sm-service` from
the memory RPC controller). Fresh post-hoc Sessions (bare, app-promoted pid
207, helper pid 8) all get sm desc 0x192. Working controller-only recipe
(all through `root-native-*` commands, no fresh-session es needed):

- `root-native-sm-service ncm` -> `root-native-ipc(ncm, 4, [storage])` =
  OpenContentStorage -> `root-native-ipc(storage, 20, contentId16+attr)` =
  **GetContentRightsId** (the REAL rights id + generation; banked guess
  title+zeros happened to be right for MKW base).
- `root-native-sm-service es` -> stage rights(16)@0x5200 + gen(4)@0x5300 ->
  `root-native-ipc(es, 503)` = PrepareTitleKeyByRightsId.
- 0x1491/0x691 -> export-rights context: es 2001 -> ctx 2 (title, staged
  idBytes(u64BE(rights[0:8])) @0x3200) -> ctx 17 (input [1]) -> ctx 3 ->
  retry 503. Still 0x1491 -> account branch: acc:su -> ListUsers via
  `root-native-raw-ipc bare` (OunceCake fixedOutput(2, alloc(2), base+0x3600,
  128) + writeUInt16LE(128, 40)) -> rows via `root-native-owned-fetch` ->
  per user ipc(acc, 102, user) -> ipc(mgr, 120) -> uid8 -> stage uids @0x3400
  -> ctx 1 (input [0]) -> ctx 17 -> ctx 3 -> 503 retry -> **result 0**.

**The cmd-0 lesson (the real blocker):** `ldr:ro cmd 0` OpenCodeFileSystem
on the cloned loader root is granted ONLY during the hot window right after
acquisition. Timeline tonight: 02:17 acquisition armed -> 02:25 cmd-0
GRANTED (errors were key-class 0x7d802) -> ~02:5x-03:00+ cmd-0
PermissionDenied (0x320002/0x720002/0xf20002, desc varies with input) for
EVERYTHING incl. SB base/update and the acquisition's own proven
`root-native-code-open(title 37, storage 3)` control — while the pipeline's
02:17 CodeFS entry stays alive (fresh:false returns it, result 0).
Suspected poison: my mid-run `fix-session-identity --force` promotions
(207 then 8) + failed SM/TIPC probing mutated the identity context the
loader session's permission rides on. **Next boot: no promotions, no SM
experiments — acquire, then IMMEDIATELY run the dump.**

The license path needs NO porting: game-dump's own prepareLicense ran the
full dance (es open + ctx + linkedAccounts) from its own Session at 03:15 —
base AND update licenses prepped; both exefs jobs died only at cmd-0.
Remaining pieces for the standard matrix: base exefs + update exefs via
the plain game-dump path (618 -> cmd 0 [attrs, storage=source.storage,
runtimeId]) while hot. No selectPatch/lr port needed for the raw update
exefs (the composed view is separate).

OunceCake (github.com/misshexa66/OunceCake) banked as the cross-check:
their engine = thin wrappers over this same run Session class; their
prepareInstalledLicense = the same 503/ctx/linkedAccounts dance; their
openCodeRaw = same [attrs, storage, title@+8] input; their update mount =
lr registered patch + registry pair-swap (only needed for composed views).

## 2026-10-26 (549Kap) — MKW matrix COMPLETE: the hot-window protocol + lr registered-patch update route

The night's failures were all stage-2 lottery (7 attempts, 2 landings). The
549Kap landing ran the full protocol clean: acquire -> IMMEDIATELY dump,
nothing in between.

**Result (all sha-verified, `~/dev/switch/roms/0400c3f00006e000/`):**
- base romfs: ok (manifest skip; offline verify 205,665 files)
- base exefs: ok (5 files) — cmd 0 granted IN the hot window, in the
  licensed attach (the tool's own session)
- base control.nacp: ok
- update control.nacp: ok (v1.8.0)
- update exefs: ok (6 files) — via the NEW lr registered-patch route

**Two hard lessons (both cost a run):**
1. `--overlay` on a non-running app hard-fails the whole invocation
   (runOverlay throws "app pid not found") — killed the first attach.
   Overlay is SB-only; never pass it for MKW.
2. The romfs manifest skip checked files but still read EVERY window:
   `coalesced: 190167 small files into 30637 read windows` fired before
   the per-file done check — 21.7 GiB of useless window reads. Fix:
   skip windows whose every file is complete (51a1ffe).

**The update-ExeFS route (ported from OunceCake selectPatch, proven live):**
0x691/0x7d802 for update content = the standalone es license doesn't apply
to update NCAs. The fix — one Session, in order:
1. SM-fallback service opens (helper-svc getService refuses fresh
   sessions; TIPC 0x11 packet on the monitor sm handle works)
2. license the BASE: ncm cmd 4 OpenContentStorage -> ncm cmd 20
   GetContentRightsId(contentId+attr) -> es 503 (ctx dance if 0x1491)
   — the base license context is what the composed mount rides
3. lr cmd 0 (original resolver, storage 4) + lr cmd 1 (registered resolver)
4. readLocation (fixedOutput cmd 0) on the original resolver for BOTH
   titles: base 0x...000 and update 0x...800 -> paths + attributes
5. RegisterOwnedPatchLocation on the registered resolver:
   pathRequest(1, input32(runtimeId + title + attrs16), patchPath, 0x300)
   — runtimeId from fs 618 on the update path (= title>>4)
6. ldr:ro cmd 0 with [patchAttrs, BASE storage, runtimeId] -> the loader
   composes update-over-base -> CodeFS with main/rtld/sdk/subsdk0/subsdk1
7. unregister (registered cmd 2) + close, walk/dump as usual

MKW update delta is REAL content: update adds subsdk1 (2,016,656 B) and
replaces subsdk0/subsdk0-scaled (531,825 B) — not just a main rebuild.
Script banked: tools/dump/update-exefs.cjs (standalone, latest-session).
Update RomFS (composed) needs the same machinery at the fs 206 layer or
cmd 200 with the app running — optional, not part of the standard matrix.

## 2026-10-26 (0fIkWJ) — overlay route post-mortem: our fork cannot read fs module rodata; OunceCake assumes kurumuz's

Two carriers wedged tonight chasing the update-RomFS overlay (cmd-200 composed
route). Both freezes decoded:

- **Freeze 1 (549Kap): retained slide on `text+0x11e12d0`** (the registry
  manager vtable slot) — killed mid-RPC by my own bash timeout; the console
  worker stuck in the slide.
- **Freeze 2 (0fIkWJ): `root-native-fs-region-read` on `text+0x11e11d8`**
  (the map manager slot)** — my "fix" was wrong: the RPC read-helper ALSO
  wedges on fs module pages (the region query itself returns garbage for
  them; the helper call hangs).**

Our own `retained-memory.cjs readMemory` comment states the model plainly:
"fs reading its own RW heap cannot fault — the hazardous classes are module
RX text/rodata (excluded driver-side) and unmapped VAs". The slide+helper
channels are heap-only on this fork. OunceCake's engine
(github.com/misshexa66/OunceCake) rides kurumuz's ns2jb memory RPC and
reads those slots through it — a fork difference, not a technique we can
copy as-is.

**Offline capture analysis (0fIkWJ bootstrap capture, 4.8 MiB):**
- Registry row structs ARE in-window: SB title rows at 0x519dd38060/0x519dd3c020
  (owner 0x519dd0a618) and 0x519dd3c360/.../0x519dd3c820 (owner 0x519dae7e98),
  storage 4 — matches OunceCake's registry row shape {owner, title, storage@0x10}.
  MKW: ZERO rows (not a loaded program — expected).
- **No list nodes in-window reference those rows** → the intrusive-list
  nodes (what OunceCake's entries() walks) live OUTSIDE the capture window
  → live walks of them would wedge the slide.
- The program-index map (fs 810) structures: not identifiable in the capture.

So the OunceCake route on our fork would need: registry pair-swap (unproven
here), map discovery (unknown), and post-registration walks (out-of-window,
wedge-prone). NOT portable as-is. The update-RomFS overlay stays documented
as a gap; the complete delivered matrix (base romfs+exefs+control, update
exefs+control) is unaffected.

Cheap residual option for a future boot: fs 206 type 1 on the update NCA
path WITH the base license already prepared (never tried — the tool licenses
per-source and update-standalone is 0x691-blocked). If that opens, the ~26 MB
delta view is readable directly and no composed mount is needed.

## 2026-10-26 (PsUUUT) — fork-gap RESOLVED: the slide reads fs module rodata fine; OunceCake's module-offset constants are build-specific

Ladder experiment on a fresh carrier (after porting upstream kurumuz/ns2jb
fixrpc layout.cjs — vtable-distance inference + sdkPageHeader, commit 34c49c7;
offline inference on the live capture CONFIRMS rootVptr == nominal):

1. **Retained slide @ rootVptr+0x5880 (fs module rodata): 66 ms, canonical
   module-text pointers back** (entry vtable object ptr 0x4ccf40ab60 —
   32-bit relative vtable entries). The slide CAN read fs module rodata.
   The "fork-gap" was never the mechanism.
2. Slide @ text+0x11e12d0 (OunceCake's registry-manager slot): HANGS ->
   carrier wedge. text+0x11e1xxx = 18.6 MB into our ~<14 MB fs module span
   — lands in a heap-gap/unmapped VA on OUR build. Their constants are for
   a different fs build. **Slide to unmapped VA = fs worker fault = wedge**
   (both earlier freezes were this class: freeze 1 = user-abort mid-RPC,
   freeze 2 = fs-region-read helper on the same bad constant).

Model correction: heap AND module-rodata reads through the retained slide
are fine (39 ms / 66 ms); the ONLY fatal primitive is sliding to an
unmapped VA, and rpc.query (the fs-region-read region query) is NOT a safe
pre-filter (its reply needs verification; preflight showed nonsense regions).

Route consequence — the OunceCake update-RomFS chain ports WITHOUT any
module-offset constants:
- registry pair-swap: offline domain-table capture scan (already in
  tools/dump/update-romfs.cjs) — heap only.
- fake context: register/remove are fire-and-forget IPC (no walks needed).
- cmd-200 spoof: offline entry/object derivation + live heap reads.
- module global slots (registry/map managers) are ONLY needed for the
  entry walks; skip them, or derive OUR offsets by RE if a walk proves
  necessary (fs-810 map may not even be required — test cmd 200 bare).

## 2026-10-26 (6NFko3) — MKW UPDATE ROMFS COMPLETE: the OunceCake route, ported and finished

The composed update RomFS (the last matrix cell) is DONE — streamed at
18.18 MiB/s sustained (4 MiB bulk readStorage chunks), 206,202/206,202
per-file sha256 verified during stream:

- composed image: 23,500,548,964 B (21.887 GiB) — data-first builder order
  (data at 512, dir/file tables at the tail; NOT the classic order)
- delta vs base: 631 added + 7,593 changed + 197,978 unchanged (96% identical
  bytes — a genuine overlay, matching the loader's composition semantics)
- LayeredFS overlay tree (393 MiB loose): the 8,224 delta files,
  drop-on-base mod directory; delivered to ns2emu/reference/mkw/

The route that landed (tools/dump/update-romfs.cjs, fully heap-only):
license base (ncm cmd 20 rights + es 503 + ctx/account dance) -> lr cmd 0/1
(original + registered resolvers) -> RegisterOwnedPatchLocation ->
ldr:ro cmd 0 composed CodeFS -> read /main.npdm -> capture-scan the domain
table (offline) + live verify -> pair-swap the registry interface into an
aux domain slot -> CopyObject -> RegisterOwnedTemporaryProgramContext
(fake owner id + the game's own npdm access controls) -> spoof a fresh
fsp-srv domain's owner fields -> fs cmd 200 -> composed IStorage.

Hard lessons banked (each cost a carrier or a run):
1. **Armed-state accumulation kills the carrier.** A failed run after
   arming (patch location / fake context) leaves it armed; same-boot
   retries stack it; the third open wedged the fs worker (GzUvcX).
   Fix: dump-state.json records every armed piece AT ARM TIME; a re-run
   removes stale ones by recorded value before re-arming (e923657).
2. **OunceCake's module-slot constants are fs-build-specific.** text
   +0x11e11d8/0x11e12d0 are 18.6 MB into our ~<14 MB fs module — unmapped
   VAs; the slide faults/wedges (freeze 2 + ladder-2). The route does NOT
   need them: pair-swap + fire-and-forget register/remove + offline entry
   derivation are enough (f4dd7e8).
3. **The retained slide reads fs module rodata fine (66 ms)** — the earlier
   "both channels wedge on module rodata" model was wrong; the wedge
   primitive is sliding to an UNMAPPED VA, and rpc.query is not a safe
   prefilter. (Ladder-1 on PsUUUT.)
4. **node write-position arg trap, twice.** `fh.write(bytes, read)` treats
   read as the BUFFER offset (cap 256 KiB) — the stream died at 17.2 GiB;
   `fh.write(buf, at)` in the overlay copy died the same way. Correct
   shape: `fh.write(buf, bufferOffset, length, position)`.
5. Composed-image path normalization: the romfs dir walk emits paths
   WITHOUT the leading slash when prefix starts empty — base-manifest
   compare needs one shape.

Remaining known-gap: NONE for the standard matrix. All sections of both
base and update dumped, verified, and delivered to the emulator repo.

## 2026-10-26 (6NFko3, end of session) — console-side disarm complete

The successful update-romfs stream run died at the overlay-copy write bug
AFTER its finalize deleted dump-state.json but BEFORE section 9 cleanup —
so the fake program context (owner 0xf053c2e846d449ea) + lr patch
registration stayed ARMED on the console post-run. Disarmed cleanly while
the session was live (tools: same heap-only machinery as the route):

- lr registered resolver -> RemoveOwnedPatchLocation(runtimeId): **removed**
- domain-table capture scan -> pair-swap -> CopyObject -> registry session
  -> RemoveOwnedTemporaryProgramContext(owner): **removed**
- The three older owner ids (from runs on earlier boots): refused
  0x...e202 ("not found") — correct: console reboots clear armed contexts.

Lesson: a route that arms console state must disarm on EVERY exit path —
the finalize section deleting the state file before cleanup ran left the
cleanup blind (it had just erased its own record of what to remove).
The next update-romfs run order should be: cleanup FIRST (disarm + then
delete the state file), or the state file deletion belongs after section 9.

## 2026-10-26 (TOTK start) — first TOTK attempt died at the control read (attr-0 control NCA)

Session 6NFko3, RPC alive and clean (post-MKW, post-disarm), TOTK
(0100f2c0115b6000) standard matrix started. The control NCA is
98ecf5af... @ dir 0000002E **attr 0** (MKW's control was attr 1). The
control read wedged the carrier ("Console response timed out"; the
hold-session health check then declared the console connection lost).

Not yet root-caused: MKW update control (attr 0) ALSO opened fine on
GzUvcX/549Kap earlier the same night, so attr-0 alone is not the killer —
possibly the cmd-10 fsType-3 mount id (owning tid) for this title, or a
console-timeout class like the acquisition-lottery transport failures.
Nothing was armed (died before any arming); console reboot needed.

TOTK content layout (from the discovery): control NCA 98ecf5af
(dir 0000002E), update 0100f2c0115b800 v720896, base app v0 — all storage 4
(NAND). Same shape as MKW. Next attempt: retry the plain --control path on
a fresh carrier; if the control read wedges again at attr 0, probe the
mount id shape (owning tid) before retrying.

## 2026-10-26 (ss9Gi3) — TOTK matrix COMPLETE: 7/7 cells

Third title fully dumped (after MKW + SmileBASIC). All routes proven on
this console now chain for any installed title:

- base romfs 15.87 GiB / 304,207 files (game-dump --bulk, disk-verified)
- base exefs (hot-window ldr:ro cmd 0) — 5 files
- base control.nacp
- update control.nacp (v1.4.3)
- update romfs: COMPOSED image 15.88 GiB via cmd-200 route
  (tools/dump/update-romfs.cjs — title-arg generalized), delta
  763+7125+296355 (98.9% identical — a true overlay), LayeredFS overlay
  tree 7,888 files (tools/dump/finish-overlay.cjs)
- update exefs: composed via lr registered patch (update-exefs.cjs) —
  5 files (TOTK ships NO subsdk1 vs MKW's 6-file update)

Delivered to ~/dev/ns2emu/reference/totk/ (romfs.img repacked + loose tree
+ exefs + controls + manifests + overlay). The composed image stays in the
lab tree (15.88 GiB too large to duplicate; retrievable).

Tooling generalizations banked this session: title-arg + runtime NCM
content-id resolution (was MKW-hardcoded), rights-attributes from cmd 24
(attr is title-specific: TOTK base=0 vs MKW=1), per-title output-dir
resolution, positional-write fixes, checkpoint-interval 8->32 chunks,
romfs rest byte-meter, finish-overlay offline finisher.

Two carrier deaths today were console fatigue after ~32 GiB of streams
(HAXRE5 ran everything); TOTK update-exefs needed one fresh dance.

## 2026-10-26 (M77Tgv) — the archive-refusal maze: 9 hypotheses killed; RE next

fs 206 (OpenDataFileSystemByPath) on system data archives (8xx, storage 3)
refuses on every fresh carrier tonight, both type 1 and type 6, in every
identity class. Controlled tests, all negative:

1. Virgin boot, first command (no fatigue/budget): refused (0xcdf20002)
2. ns identity promoted + oracle-verified BEFORE attach (0x7d202): refused
3. Full es license dance (TOTK, 503=0) same-session then open: refused
4. NCM storage-3 resolve chain (GetLatest/GetContentIdByType/GetPath ok):
   refused — GetPath resolves the archive path fine, so NCM/registry state
   is NOT the problem
5. Full storage-3 ListContentMeta sweep primer: refused
6. 8 cmd-10 mount-attempt refusals then 206: refused
7. game-dump's own archive path (the Oct-25 tzdata route, prepareLicense
   included): refused — license: false (archives carry no rights id)
8. Helper (0x1408) vs app (0x0) vs ns (0x7d202) identity classes: all refused
9. Cooldown spacing between opens: refused

The ONLY passes that ever opened archives ran on ss9Gi3 (16:29-16:40):
unpromoted controller root, after TOTK update-exefs + NCM sweep + 57
cmd-10 refusals, in that order — 5 archives opened (0802/0806/0823/0849/
0858), repeatably, same 5 every pass. Same code refuses everywhere else.
Oct-25 tzdata (080e) opened via type-6 + mid-run ns promotion.

Refusal codes carry a per-call-serial component in the high bits
(0xce..., 0xd3..., +0x40000-0x80000 per call) — not static enums; we may
be misreading a task-token reply as a result word. Decoder needs a
re-look with a live refused reply dump.

Banked regardless: 5 archives fully dumped today (0802/0806/0823/0849/
0858, sha manifests) + tzdata (Oct 25). sysarch tools committed:
sysarch-sweep (inventory), sysarch-batch (identity pre-flight + resume
manifests), sysarch-dump (cmd-10 path; has a BigInt crash on
attr-version parse mid-run — TODO).

NEXT (offline): RE the fs 206 handler in the dumped fs module — locate
the access-control branch producing this refusal family and read what
state satisfies it (diff a live refused reply's inputs). The per-call
high bits suggest a task/token structure the tool parses wrong —
decode that first.

## 2026-10-26 (M77Tgv, offline) — archive gate DECODED: 0x320002 + task serial; the identity object mismatch

Two decisive offline finds from tonight's refusal corpus + the banked fs
decompile (fs-live.elf, FSDUMP.md):

1. **The refusal family is ONE error.** 0xf20002 / 0x720002 / 0xd33...002
   all mask (val & 0x3fffff) = **0x320002 PermissionDenied** — the varying
   high bits are a task/token SERIAL the dispatcher ORs into the result word
   (result | serial<<22), not distinct error classes. The "per-call
   incrementing descriptor" mystery is closed: it's a serial, and the gate
   it reports is plain fsaccess denial.

2. **The identity machinery was the wrong object.** fix-session-identity
   patches rootAddress+0x30 = the DEDICATED PID-TEST ROOT object (the one
   root-initialize created via SetCurrentProcess). game-dump's archive route
   opens THAT root (a.root) and its promote patches THAT graph — worked
   Oct 25. My batch session CLONED THE CONTROLLER'S ROOT
   (proof.rootHandle -> domain.control(2)) — a different object entirely —
   so the ns promotion never touched the object my cmd-206 open consulted.
   The oracle (cmd 2 on clones[0]) measured the controller root's class,
   which DID flip ns, but the batch's clone was made from the controller
   root BEFORE... regardless: the FAH/FAC content-mask check follows the
   session's registered pid; patching one object's pid fields does nothing
   for opens through another.

PER COLLECTED EVIDENCE (FINDINGS fs-registry notes + FIRMWARE_FINDINGS):
the 0x320002 gate consults the FAH/FAC (FsAccessControl) masks installed
by RegisterProgram — the ContentData bit ("only ns carries it" — because
ns's NPDM registers ContentData). This is consistent with EVERYTHING:
tzdata (type 6 + mid-run promote on a.root = the session's own root) worked;
my batch (clone of a different root, promote on the wrong graph) refused;
virgin-boot + es-license + NCM-priming tests never changed the right object.

NEXT (live, one carrier): batch archive dumper reworked to
  (1) open its OWN fsp-srv root (SetCurrentProcess 0),
  (2) promote THAT root graph to the ns pid (fix-session-identity
      patches root+0x30 of the proofed rootAddress — point the proof at
      the session's own root object),
  (3) cmd 206 through the own root.
The same applies to any future type-6 consumer. sysarch-batch.cjs needs
this rework; game-dump.cjs's archive path already has the right shape
(root-open + mid-run promote) but pre-flights the license pointlessly for
archives (license: false is fine — no rights id needed).

## 2026-10-26/27 (offline, console down) — correction + the narrowed hypothesis

CORRECTION to the previous entry: the "promote patches the wrong root
object" theory is WRONG, and I should have caught it in the entry itself.
Test 8 tonight ran game-dump's OWN archive route (0400000000000812
--archive --content archive): that route clones the SAME dedicated root
as the batch, does the mid-run in-catch promote (right object, right
order, sweep + fix-session-identity --pid ns --force, oracle 0x7d202),
then retries the type-6 open — and STILL refused 0xd4320002. Both
"pre-attach promote" and "in-catch post-failure promote" are now tested
and both are insufficient. The root-object mismatch theory is dead.

What ACTUALLY differs between the refusing boots and every archive pass
that ever worked (ss9Gi3 16:30 x5, Oct-25 tzdata):

  the working carriers had run the TOTK UPDATE-ROMFS/UPDATE-EXEFS route
  FIRST — the OunceCake fake-program-context machinery:
  RegisterOwnedTemporaryProgramContext (fake owner + game's NPDM
  FAH/FAC) + the fsp-srv owner-field spoof + fs cmd 200.

This fits every data point:
- FS-REGISTRY-NOTES concluded long ago: "the data-fs open consults the
  FAH/FAC content masks in fs heap" — i.e. the cmd-206 type-6 gate
  consults the CALLING process's REGISTERED PROGRAM content masks,
  not the session's pid field.
- ns-pid promotion (root+0x30 + chase) changes the pid the session
  REPORTS, but does not install a registered-program FAH for it —
  hence oracle 0x7d202 (ns class) with the gate still refusing.
- RegisterOwnedTemporaryProgramContext IS a RegisterProgram-family
  operation: it installs a program context (with the game's full-trust
  FAH/FAC) into the fs heap registry. THAT is the state the gate wants.
- tzdata opened on Oct 25 AFTER the TOTK update route had armed the
  context in that boot; ss9Gi3 likewise after the MKW/TOTK routes.

NEXT BOOT — controlled test (one command, then decide):
  1. SESSION READY -> run update-romfs.cjs 0100f2c0115b6000 --probe
     (or the cheapest arming mode) to arm the fake program context,
  2. then sysarch-batch.cjs --only 0400000000000812 FIRST,
  3. open -> theory confirmed -> run the full 46-remaining batch,
     refuse -> fs-heap registry walk (careful RE, brick-risk discipline).

sysarch-batch.cjs is reworked for this: unconditional attach-time promote
(kept — cheap, harmless), in-catch 0x320002 re-promote+retry (rules out
promote-order per-archive), and a decisive FAH-gate hint line + `gate:
true` result marker when the refusal persists, so the logs from any
future boot self-document which hypothesis state they ran under.

## 2026-10-27 (offline) — the 206 gate decoded from the banked fs decompile

Full RE pass on the dumped fs module (fs-live.elf) + tonight's refusal
corpus, no console needed. Findings (fw-re/out/fs-live.elf.dispatch.c,
fw-re/out/fs-live.elf.gate-fns.c):

- The refusal pair is a HANDLER ATTRIBUTE MATCH, not FAH: the cmd-206
  handler (FUN_59920d49c0, identified uniquely by tonight's empirical
  {type-1 -> 0x2ee002, type-6 -> 0x320002} pair) branches on a
  DISPATCHER-PROVIDED MASK BYTE (param_7):
    bit0 CLEAR  -> registered-content flow (FUN_59920d2ac0 opens the NCA
                   by type; local_d8==0 -> 0x2ee002 "no nca"),
    bit0 SET    -> HOST flow, which REFUSES 0x320002 unless the path
                   KIND (from FUN_59920d1800) == 2 (@Host).
  The parser maps path forms -> kinds: @SystemContent* -> 0,
  @Host -> 2 (the type-6 host flow then reads the raw file straight off
  the partition mount).
- param_7 is PER-CALL (type-1 and type-6 behaved differently in the
  SAME session tonight) — the dispatcher computes it in the fsp-srv
  worker from per-request state, then tailors the branch. The
  computation lives in the ONLY undumped region: fsRodata (t4/a16,
  0x11000 = the runtime fsp-srv/fsp-pr interface objects at
  0x5992296000+). All text/code/statics (rodata A+B are RW t4/p3) are
  banked already.
- Tonight's refusals vs the Oct-25/ss9Gi3 successes on the SAME path
  form and cmd therefore differ in dispatcher state — consistent with
  the fake-program-context (RegisterOwnedTemporaryProgramContext)
  route arming the worker's per-session table on the working carriers.

NEXT BOOT (all offline-prepped):
  1. SESSION READY -> dump-fs-gap.cjs (exists; per-boot ASLR via the
     qualification record; ~70 KiB, 2 chunks, <1 min) -> r-<base>-11000.bin
  2. fw-re/scan_gap.py <gap.bin> <new-qual.json> -> rebased dispatch/
     vtable tables vs the existing Ghidra project
  3. decompile the fsp-srv worker/dispatch (text, old-ELF addresses) ->
     read the param_7 computation -> the EXACT archive-open condition,
     no more hypothesis testing.

## 2026-10-27 (x7Edbi, live) — the archive route decoded end-to-end; carrier died

Major decode session on a live carrier (SESSION READY 18:37, died ~19:06
console-side). The archive mystery is now STRUCTURALLY decoded:

1. **type-6 on @SystemContent CANNOT open — ever.** The 206 handler
   (FUN_59920d49c0) branches on a dispatcher-provided per-call mask byte
   (param_7): bit0 SET -> HOST flow, which hard-requires path kind 2
   (@Host:) and returns 0x320002 for every other path form
   (@SystemContent -> kind 0). bit0 CLEAR -> registered-content flow
   (NCA open; no-nca -> 0x2ee002). The type-6 + @SystemContent refusals
   are BY DESIGN. Archive opens must ride type 1.
2. **The refusal family is ONE canonical code**: (val & 0x3fffff) ==
   0x320002 everywhere; high bits = request serial. Same for 0x2ee002.
   The "incrementing descriptor" mystery was a TIPC token artifact.
3. **The 206 route needs the FULL licensed prelude** (from the update-romfs
   route): a bare RegisterOwnedTemporaryProgramContext (no license, no
   patch) REFUSES 0x320002. With license (es 503 dance) + lr patch
   registered first, the register succeeds. The register also fails with
   NS-npdm buffers (all fw23 module FAHs are v1; TOTK's game FAH is what
   the route uses) — the register validates FAH content, v1-ns rejected.
   (Not fully decoded: which FAH class registers OK besides game v2.)
4. **The ns promotion BREAKS the loader compose**: ldr:ro cmd 0 (the
   composed CodeFS) refuses 0x320002 under an ns-promoted controller root
   (root+0x30 = 167) and opens under the natural helper class (0x1408).
   Tonight's sequence: route OK 18:54 (unpromoted fresh boot root) ->
   game-dump archive probe promoted ns (in-catch) 19:0x -> every later
   route CodeFS refused. FIX: fix-session-identity --pid 8 --force
   before the route (verified: oracle back to 0x1408, CodeFS would need
   a re-run — carrier died first).
5. **A stale armed CONTEXT blocks the route re-run**: with a context
   registered (18:54 arming), the route's CodeFS refused until the
   stale context was removed. The route now REMOVES stale context
   BEFORE the CodeFS (steps 5+5.5 reordered before 3) — and the remove
   only works from a fully-licensed session (a bare pair-swap session's
   remove refuses).
6. **update-romfs.cjs now has --archive <tid> / --archives mode**: after
   the licensed prelude + context register, it spoofs a fresh fsp-srv
   domain (owner fields <- context owner), then opens the archive via
   fs 206 type-1 (domain-wire pathPacket), walks + dumps the RomFS
   tree with sha256 manifest to ~/dev/switch/dumps/fw23-archives/<tid>/.
   The 206-domain packet needed the pathPacket SEND descriptor (w0 bits
   16-19) + manual wire.domain injection (ipc.packet's send option
   lands in the wrong w0 bits -> 0xF601 invalid).
7. **The fsRodata gap (attr-16, 0x11000 = the fsp-srv/fsp-pr interface
   objects, the param_7 computation) cannot be dumped via rig 0016**:
   svc 0x74 (MapProcessMemory) REFUSES attr-16 regions (kernel 0xd401)
   regardless of trusted mode; attr-0 regions map fine. The debug-suite
   (0x60/0x69/0x6a) route reads any region type but is LETHAL from our
   monitor (3 documented kills). The gap stays unread for now.
8. fix-session-identity has a benign compare-write race (threw on a
   changed field mid-scan; the critical root+0x30 was already written).

NEXT BOOT (clean, unpromoted root, no context):
  1. SESSION READY -> update-romfs.cjs 0100f2c0115b6000 --archive
     0400000000000812   (the route handles license+patch+context+spoof+206)
  2. opens -> --archives for the remaining 45 (11 banked).
  3. do NOT run game-dump --archive (its in-catch ns promote breaks the
     loader compose for the rest of the boot).

## 2026-10-27/28 (offline RE) — the 206/10 reader chain FULLY decoded; kind-byte + flags

Complete static decode of the archive route (fw-re/out/fs-live.elf.reader-chain.c,
raw capstone on fs-live.elf). The whole chain, end to end:

- **Handler d49c0**: mask byte param_7 (bit0 = host-mode flag, dispatcher-computed
  per call): bit0 CLEAR -> registered-content flow, bit0 SET -> host flow
  (hard kind-2 gate = @Host: only). Top gate: type6+mask0 -> 0x2ee002;
  **type-6 ALWAYS errors or host-flows -> the DATA path is unreachable from
  d49c0** (it must live in a different dispatch — the Oct-25 tzdata type-6
  route went elsewhere). Confirms: type-6/@SystemContent refusals are
  structural, as banked.
- **d2510 (reader ctor)**: wraps the session content-storage object +
  path + FLAGS. FLAGS = 0x5000007 (param bit set) | 0x70000007 | **1 when
  (titleId & 0x00ffffffffffffff) <= 0x1fff** (DAT_59931cb2e8/2f0 = 0/0x1fff) —
  **archive tids (0x04000000000008xx -> low-56 0x8xx) land in the range ->
  SYSTEM-CLASS reader flags = 1**; game tids (low56 huge) -> 0x7000007.
- **d94e0 (mount)**: reader+0x10 = rights-id; == zeros -> plaintext (no key);
  else d9260 walks the **key-cache linked list at ctx+0x400** (node+0x10
  rights-id, +0x20 key entry 0x134B; not-found -> 0x7d802
  NcaExternalKeyNotFound). Header read via reader virtual (21c9bf0);
  **NCK0 magic parse; OUR FRESH-BOOT ARCHIVE MOUNTS SUCCEED** (the 0x2ee002
  refusals happen AFTER, at the open).
- **d2ac0 (section open)**: type-switch on reader+1 **content-kind byte**
  (set by ctor from resolved content info): type1 -> kind 0 (program),
  type3 -> kind 2 (control), type6 -> kind {4,5} (data), type8/9 -> kind 0.
  **0x2ee002 IS CONSTRUCTED AT THESE KIND MISMATCH BRANCHES** (0x59920d2f3c:
  mov w0,#0xe002; movk #0x2e<<16). After the kind check: d3940 mount ->
  per-type content table DAT_59922515c0 = [1]=1,[6]=0,[8]=1,[9]=1,... ->
  **open via ctx+0x28 object's vtable[+0x10]** (the session content-manager,
  HEAP object, vtable IN THE GAP) -> result byte (out+2) -> 0x2ee002 family.
- **So the kind byte is NOT the archive blocker on type-1** (mount passed);
  the failing byte comes from the ctx+0x28 open call. The 5 uptime-boot
  archive opens (flags=1 system-class readers) succeeded because qlaunch
  had warmed that open path (same 5 NCAs every time). Fresh boots: open
  refuses. **The remaining unknown = ctx+0x28 object's open method = the
  gap vtable** — undumpable via rig 0016 (attr-16 kernel refusal), lethal
  via debug attach (3 documented monitor kills).

STRATEGIC (honest): to get ALL archives without uptime piggybacking we need
one of: (a) the gap (new dump primitive — the attr-16 region via a different
svc route; 0016's word3=1 trusted mode fails at svc 0x74 for attr-16), or
(b) the ctx+0x28 open semantics reversed from its CALLERS' state (qlaunch's
session class), or (c) offline decryption (es/fs keychain RE — the d9260
key-cache walk shows fs holds RIGHTS-ID->KEY entries in ctx+0x400; if the
key derivation for titlekegs is software-side in fs/es, archives decrypt
offline regardless of console).

## 2026-10-28 — SOLVED: all 57 system archives dumped on a FRESH boot (cmd 10 fsType 6)

THE archive route, decoded from the d49c0 mask analysis + one live A/B:
**fs cmd 10 (OpenFileSystemWithId) with fsType 6 + the archive titleId**
opens system data archives DIRECTLY — no promotion, no license, no fake
program context, no uptime, no carrier lottery. 206's dispatcher
mask-gates type-6 into the host flow (@Host only) for every session
class; cmd 10's WithId dispatch passes type-6 straight to the DATA path.

Route: clone root -> cmd 10 (attr, fsType 6, titleId) -> IFileSystem ->
recursive cmd-9 dir walk (type 0=dir, 1=file) -> cmd-8 open file ->
fileSize + readFile -> sha256 manifest.

Result (session GeodhE, fresh boot, one pass): **50 ok / 0 refused /
7 skipped (pre-banked)** — all 57 archives complete, 39,052 files,
~/dev/switch/dumps/fw23-archives/. The "per-boot budget", "carrier
fatigue", "identity class", "es license", "fake program context",
"uptime/qlaunch warm-state" theories are ALL retired — the entire
10/26-27 refusal corpus was one wrong command ID.

Tool: tools/dump/sysarch-cmd10-batch.cjs (resume-safe: completed
manifests skipped; SYSARCH_COOLDOWN_MS between opens).

## 2026-10-28 (2) — sysmodule updates: NONE; NCA-level structure: complete

Swept storage 0..4 for update-class metas (tools/dump/sysmod-update-sweep.cjs):

- **No system updates exist on this console.** Storage 3 (BuiltInSystem)
  carries ONLY metaType 0x01 base keys — 90 titles, zero 0x81/0x82. The
  system is on base fw23.0.1; there are no system-update NCAs to dump.
- Storage 4 (BuiltInGame): 11 metaType-0x81 update metas — all GAME
  updates (TOTK v720896, MKW v1048576, etc.), every one already banked
  per-game. 0x82 delta keys exist but resolve no Program content
  (delta/bridge metas — no loose-file deliverable).

NCA-level structure sweep (tools/dump/nca-structure-sweep.cjs ->
fw23/nca-structure.json): every storage-3 system title carries exactly
ONE content type — Program (attr 1); zero Control/HtmlDocument/Legal
content in the entire system corpus (sysmodules ship no control.nacp —
that is a games-only content type). Combined with the 57 data archives
(single Data NCA each), the fw23 NCA structure inventory is:

  90 sysprogram titles  -> 90 Program NCAs  (text/rodata/data loose: banked)
   57 sysdata titles    -> 57 Data NCAs    (RomFS loose: banked tonight)
    0 system updates    -> nothing to dump

FIRMWARE-DUMP.txt extended with the 57-archive table (39,052 files) +
the structure section. Raw NCAs on NAND are header-encrypted
(console-unique header key) — decrypted loose files remain the
deliverable per the emulator keyless-loader design.

Remaining goal surface after tonight: none of the dump items. The
repo/docs state is current through 95a8bd3.

## 2026-10-26 (3, GeodhE) — nvservices RomFS / GPU microcode: the program-content wall

Target: the GPU ucode set (`fecs_c.bin`, `gpccs_c.bin`, `gpmu_ucode_*`,
`acr_ucode_*`, encrypted `acr-gsp-*`) — all referenced by nvservices
rodata, all riding the **nvservices Program NCA RomFS**
(`6bf048948127c13bf8006a345649675a`, attr 1, SYSTEM storage).

Empirics tonight (bare RPC session, no prelude):

- **fs cmd 10 cannot open Program content.** Sweep fsType 0..16 x
  {@SystemContent, @SystemContent0, @SystemContent3}: types 3..6 build
  the DATA reader and refuse the Program NCA with **0x2ee002** (reader
  kind mismatch — the reader-chain kind gate), everything else
  0x2ee202; @UserContent 0x202 (not on that storage). The WithId route
  only ever builds data-class readers — same-shaped result as the 206
  type-6 mask decode, but the kind gate is the blocker here.
- **fs 206 type 1 (the program-RomFS route) hits 0x7d202 bare.** The
  game flow clears it with the licensed prelude (es 503 + lr patch +
  CodeFS + RegisterOwnedTemporaryProgramContext + domain-root spoof).
  Pre-req chain problem: the FAH that registers is a GAME v2 FAH — and
  the game context flips the 206 mask byte to the @Host flow, which
  cannot open @SystemContent (the 2026-10-27 decode). fw23 module FAHs
  are v1 and the register rejects them. So @SystemContent type-1 via
  context-spoof is likely structurally blocked; **untested lever: the
  natural-helper 206 in the acquisition hot window** (see below).
- **The V5iho9 loader-poison lesson re-proven the hard way:** my
  `fix-session-identity --pid 154 --force` (+ restore to 8) killed the
  boot's ldr:ro compose — every CodeFS compose after refuses 0x320002
  (bare probe confirmed; the licensed prelude dies at its CodeFS step).
  The restore does NOT un-poison. On the dump boot: **no promotions, no
  identity games — acquire, then immediately run the dump.**
- pm:dmnt pid sweep from the RPC session: works (sm fallback via
  root-native-info); nvservices runs as **pid 154**.

Next-boot procedure (one cheap probe, zero prelude):
`sudo -n ip netns exec switchlab runuser -u nlight -- node
tools/dump/sysprogram-romfs-dump.cjs 0400000000000019` immediately
after acquisition (before ANY other route touches the session). If the
hot window grants bare 206 type-1, the full Level-3 walk + dump runs
in-tool (resume-safe manifest). If it refuses 0x7d202 again, the GPU
ucode needs the context-register FAH question answered first (which FAH
class both registers AND carries @SystemContent rights) — RE work.

## 2026-10-26 (4, vAmE9W clean boot) — the complete GPU-ucode route matrix

Fresh-boot session, every route bare-tested then context-tested:

| Route | Result |
|---|---|
| fs cmd 10 × fsType 0..16 × {@SystemContent, 0, 3, @UserContent} | `0x2ee002` (types 3-6, reader kind gate: DATA readers only) / `0x2ee202` (rest) — **structural** |
| fs 206 type 1 (program RomFS) bare | `0x7d202` |
| fs 206 type 1 under game FAH context | `0x320002` |
| fs 206 type 1 under ns FAH context | `0x320002` |
| fs 206 type 1 under nvservices OWN FAH context | `0x320002` — the v1 sysmodule FAH **registers fine** (the old "v1-ns rejected" note was boot-poisoning, not FAH class), but @SystemContent through 206 is closed for every registered-context class |
| fs cmd 2 (OpenDataFileSystemByCurrentProcess) under promoted sysmodule pid 154 | `0x7d202` — cmd-2 resolves only APPLICATION processes' RomFS (game pid → 0, proven overlay route) |
| fsp-ldr (the trusted loader fs interface) | **sm SAC denial `0x615`** — fsp-ldr is in the loader's service-access list, not our helper class |
| ldr:ro cmd 0 (loader CodeFS) | ExeFS-only view (no RomFS); and poisoned for this boot post-promote anyway |

**Reader-ctor RE confirmation** (fs-live reader chain): the kind byte
(`param_7&1` → `0x5000007`/`0x7000007`, tid-masked ≤ `0x1fff` → system
class `1`) is set by the CALLING PATH, and only the internal boot-time
mount path constructs program-kind readers for system titles — no IPC
surface we can reach carries it.

**The two real remaining routes** (both multi-hour, both brick-safe):

- **(A) fs-process mount-object walk** — fs mounted nvservices' RomFS at
  its boot; the mount object + NCA reader live in fs heap. We hold the
  full fs dump + the reader-chain RE (key cache at ctx+0x400). Find the
  device table → identify nvservices' entry → `domain.copyObject` its
  IFileSystem/IStorage into our session → walk + read through the normal
  handle machinery. Read-only, no console-side arming.
- **(B) RO-replacement payload launch** — launch our own process with a
  sysmodule identity (the launch machinery exists: ro/launch.cjs,
  'start replacement'); inside it the standard sysmodule RomFS mount
  works; stream the tree out over the RPC bridge. Payload dev + test
  cycles, launch-risk discipline applies.

GPU driver CODE is fully banked (§3: nvservices/nvkernel/ngc/vi2/host1x/
gc/tsec/gsvm×4/adraw) — the ucode is what authentic GSP-level emulation
still needs. Emulator boot/render does not need it.

## 2026-10-26 (5) — route (A) live probe: retained-read on the reader heap is lethal

The plan: find nvservices' live RomFS reader object in fs heap
(tid at +0x78, kind 0x1), copyObject its IFileSystem, walk + read.

Offline decode (banked fs heap dump, r-5992ac4000): **25 live reader
objects**, vtable `0x5992298918` (secondary `0x59922a4770` at +0x18),
kind byte at +0x30 (`0x1` = system-program reader, `0x7000007`/`0x5000007`
program/data-ctor flags), **masked title-id at +0x78** (`0x040000000000037`
= ro itself, `0x0400000000000818`, `0x0400000000000313 0061`-ish mask
variants), NCA paths inline (`/Contents/registered/<cid>.nca`). The
boot-time sysmodule mounts construct exactly these.

Live result: **retained-read aimed at the reader heap kills the fs
session** — first attempt 4 MiB chunks (froze console app), retry with
0x100-byte reads ALSO killed the carrier outright (`Memory request timed
out; it was not replayed` → `Console connection is no longer available`,
two boots lost tonight). FSDUMP.md already documented retained-read as
"malloc/heap-only, 2+ min per 64 KiB — bulk fetching froze sessions
repeatedly"; the reader-object region is evidently a no-go for it at ANY
size. Retained-read stays restricted to the proven staged areas.

Route (A) next steps (all rig 0016, the monitor payload — the proven
heap-safe cross-process reader that built the fs dump):
1. rig-0016 heap scan of `0x5992ac4000..0x59931ca000` for the vtable
   pointer → enumerate live reader objects + their tids;
2. RE the mount/device table (FUN_59920d3eb0 / the per-process device
   map) to locate nvservices' IFileSystem handle value;
3. copyObject (domain wire.control(1, objectId)) into our session;
   walk via root-list-romfs (cmd 9) / read via root-read-romfs-file
   (cmd 8) — machinery already proven on the overlay route;
4. dump loop with manifest checkpoints.

Open risk: the copyObject ID space for heap reader objects is unreached
territory — the device-table RE (step 2) is the real work.

## 2026-10-26 (6) — route (B) concretized: fsp-ldr via the monitor policy

Offline decode pass (banked fs heap dump, r-5992ac4000):

- **Reader objects** (NCA-content readers): vtable `0x5992298918`
  (+0x18 secondary `0x59922a4770`), kind at +0x30 — **`0x1` = system-class
  (data archives 08xx + sysprograms 0037/1000), `0x5000007`/`0x7000007` =
  game-class** (straight from FUN_59920d2510's `param_7&1` flag × tid ≤ 0x1fff
  system check). Masked tid at +0x78, NCA path inline.
- **Content-mount table**: 0x180-byte entries at ~`0x5992b4d000`,
  reader ptr at entry+0x148.
- **fs per-process registry**: 0x60-byte linked-list entries, vtable
  `0x5992298d58` (gap), **pid at +0x18, tid at +0x20**, per-process object
  at +0x28 — nvservices' entry (pid 154, tid 0019) → object embeds its
  NCA path inline (`/Contents/registered/95/257c0b6b…ca`).
- **No 0019 reader or key-cache entry in the banked heap** — sysmodule
  RomFS mounts don't ride the reader-object class at all; the key cache
  walk (ctx+0x400, rights-id list) has no 0019 entry either. The raw NCA
  (banked: switch2-1u9ld7/system/Contents/registered/6bf048….nca, 1.5 MB)
  is fully header-encrypted; the crypto lives in the SE, not banked
  memory. Route (A)'s fs-heap object-copy is therefore dead for the ucode
  without deeper RE.

**Route (B) — the loader-trusted interface, from OUR monitor:**

- fsp-ldr exists (fs registers it: FUN_5992011ed0). Its dispatch table
  lives in the rodata GAP (undumpable) — the command IDs must be probed
  live (200-215 sweep with tid input, like the archive sweeps).
- `sm:` GetServiceHandle checks the CALLER's SAC: our RPC helper session
  runs inside the FS process (fs SAC lacks fsp-ldr → tonight's 0x615).
  The MONITOR policy is ours to patch.
- **`tools/npdm/npdm-sac-patch.py`** (new): adds service names to a
  policy NPDM's SAC (ACI0+ACID). SAC entry = `u8(len-1)` + name, NO
  control byte (verified against policy-0037-boot: 6 entries sum 0x29).
  Rebuild preserves the sig prefix + hdr + **FsAccess gap regions
  byte-identical** (ACI0+0x40 size 0x1c holds the masks — zero-padding
  would have destroyed the console-captured maskA), re-places KAC at the
  next 0x10 boundary (byte-identical, verified), fixes META/hdr size
  fields. ACID sig NOT re-signed (the launch path doesn't verify — the
  existing ACID KC/maskA patches prove it).
- **`engine/switch2/ro/payload/policy-0037-fspldr.npdm`** (new, sha
  `f45d2b77e0aad435…4a1d2dba6aee7d8a31409a1`): policy-0037-boot +
  fsp-ldr in both SACs; npdm-tool.py parses clean, svc set unchanged
  (64 svc incl. CallSecureMonitor). Manifest pin updated.
- **Next boot runbook (GPU ucode dump):**
  1. fresh boot → dance → `V=GO2()` (monitor launches under
     policy-0037-fspldr);
  2. executor `OP_GSH("fsp-ldr")` → handle (SAC now grants it);
  3. `OP_CMIF` command sweep 200-215 with tid 0019 → identify
     OpenDataStorageByProgramId → IStorage handle;
  4. IStorage GetSize (cmd 4) + Read loop with a **C-recv descriptor**
     into the monitor ipcArea (needs the one OP_CMIF-recv payload
     addition — spec'd below) → rig-0016 cross-process bulk-copy of the
     monitor ipcArea → PC sha256 + loose-file dump + manifest;
  5. fallback if the sweep finds nothing: same runbook with
     OpenFileSystemWithId-class commands (IFileSystem walk instead).
- **Payload C spec (next session):** `OP_CMIF_RECV` = OP_CMIF + C-recv
  descriptor: cmif word0 |= (2<<16), descriptor words at p[1]=
  {addr>>32|, addr-lo} p[2]=size (monitor ipcArea+0x1000, 0x10000 cap);
  reply parse unchanged (lastData). Exfil: worker-control 0016 against
  the monitor's exported handle (exportHandle machinery), 64 KiB steps.
