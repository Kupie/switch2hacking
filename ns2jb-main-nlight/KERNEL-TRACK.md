# KERNEL-TRACK.md — privilege escalation, kernel R/W, kernel bugs, nvdrv
# (my focus; the mkw dump window belongs to the other agent)

## The asset map (2026-10-27)

**nvkernel (0x040000000000004f)** — the NEW fw23 module hosting gpuk:drv /
gpuk:gsv — NPDM carries **63 svc entries** including the whole
device-address-space class:
QueryMemoryMapping(0x55), CreateDeviceAddressSpace(0x56),
AttachDeviceAddressSpace(0x57), DetachDeviceAddressSpace(0x58),
**MapDeviceAddressSpaceByForce(0x59)**, MapDeviceAddressSpaceAligned(0x5A),
UnmapDeviceAddressSpace(0x5C).
That is the SMMU/GPU mapping family — on HOS1 the exact class behind
kernel physical-memory exploits. nvservices (0x19, nvdrv:s/v/t, nvgem:c,
nvdrvdbg) forwards user ioctls into this. Both modules fully banked
(fw23/ text/rodata/data + NPDM) and in the Ghidra fw23 project.

**The kernel bug surface, concretely**: user-controlled nvdrv ioctl
parameters -> nvservices dispatch -> nvkernel syscalls
(MapDeviceAddressSpaceByForce et al.) -> kernel SMMU mapping decisions.
Validation gaps there = kernel R/W primitives.

## The access route: fs-context HIPC2 (wedge-free, no executor needed)

State recap: the sm deflects the MONITOR's client relationship (7.2q,
empty-frame init + 0xE401 GSH); the executor (0036 donor) wedges on every
recent boot (its buffer init/GSH send never returns — the sm silent-send
class). But the WAVE runs as fs — a client the sm respects — and the
held sm session (root-native sm-get) already opened nvdrv/nvgem sessions
in earlier rounds (they rejected our wrong command probes 0xF601, which
proves the sessions EXISTED). The v4 SDK-pattern sender
(tools/hipc2/hipc2-sdk-client.cjs) builds the frame in the calling
thread's TLS and sends via svc 0x21 — the OS-native pattern, driven by
the wave's rpc.call3. So the nvdrv access problem is NOT access — it is
PROTOCOL: we never sent the right command shapes.

## Offline decode (now, no console)

1. nvservices: the nvdrv:s/v/t + nvgem:c service dispatch — command
   table, per-command handlers, argument shapes (Ghidra fw23 project,
   XrefDecompile/DecompileAddrs from the "nvdrv" registration strings).
2. The ioctl layer: /dev/nvmap-vm6, /dev/nvmap-tsec, /dev/nvhost-dbg-gpu,
   /dev/nvhost-prof-gpu device registries -> per-ioctl handler tables.
3. nvkernel: gpuk:drv/gpuk:gsv interfaces; every caller of
   MapDeviceAddressSpaceByForce; what user-reachable ioctl parameters
   reach it and which fields are NOT validated.

## Window plan (when the console frees up; read-only, no launches)

1. sm-get nvdrv:t / nvgem:c / gpuk:drv via the wave's held sm session
   (proven class).
2. SDK-sender Initialize + the decoded first commands; diff TLS for the
   SFCO replies (the established v4 flow).
3. Open the decoded device nodes, run the ioctl sweep on the
   least-privileged nodes first (nvmap-vm6), NEVER speculative sends to
   unknown-dispatch commands (lesson #8: a non-replying send wedges the
   fs dispatcher = console death risk).
4. Target: reach a MapDeviceAddressSpaceByForce path with controlled
   parameters; record validation behavior.

## Deprioritized / parked
- Executor wedge A/B: fs-context HIPC2 supersedes the executor for
  nvdrv. The executor's remaining value = svc 0x6a cross-process reads
  (superseded for fs by copy-region) + sacrificial-process kernel fuzzing
  (a crashed executor process = a pm crash report, not a console death).
  Keep the v10 A/B for when the console is idle.
- package2 crypto: unchanged long game (no scene keys).
- fsp-pr RegisterProgram: the vtable gap read (copy-region) + the fs
  registry decode remain queued for a window step.

## Decode state after 7.2x (see FIRMWARE_FINDINGS 7.2w-7.2x for details)

DONE offline:
- The kernel surface map: nvservices holds the DAS syscall class itself;
  the ByForce mapper call shape + its tolerated-error set (an nvservices
  crash = a pm report, NOT a console death — fuzzable).
- The shim/registry/lookup layer address map (module registry 0x16d110,
  (fd,cmd) lookup FUN_00047440, the shim FUN_00062a40, the method family
  veneer table 0x212880, the per-device handler arrays).
- The ioctl NR sets from the dispatch trees (0x48xx GPFIFO family,
  0x47xx, 0x44xx, 0x410b) — live-probe ground truth.
- The pid-pinning guard: Initialize and Ioctl MUST come from the same
  process (the wave = fs, both — no issue).

NEXT offline (priority order):
1. cmif command IDs of nvdrv:t (the wire layer above the shim).
2. The validation audit: which ioctls carry {processAddress, size,
   deviceAddress} into FUN_00116b80 → svc 0x59, and what nvservices
   checks (or fails to check) before the kernel call. THE kernel-bug
   candidate list comes out of this.
3. nvkernel gpuk TIPC interfaces (the second surface).

NEXT live (when the console frees; read-only, one variable per boot):
- fs-context GSH(nvdrv:t) via the held sm session + the v4 SDK sender
  (hipc2-sdk-client.cjs); Initialize from the WAVE ONLY (pid-pinning!),
  then the decoded first commands. Never speculative sends (lesson #8).

## Queue state after the full offline pass (7.2ac) — ready for the window

DONE (all committed, review-verified):
- The new-svc family mapped + semantic IDs: 0x80 map/share (attr 0x20,
  nvdrv-reachable on Initialize), 0x85 unmap (64KB), 0x81 query, 0x82
  (handle,start,count) range op, 0x90/0x91 the RM pair (identical
  wrappers in both modules, fatal-abort convention).
- nvmap dispatcher + Alloc/Create/Alloc-40B validation chains: sound.
- SubmitGpfifo (0x4809) branch structure + the entry-count bound.
- The whole 7.2w-7.2ab claim set re-verified against raw bytes.

THE WINDOW PLAN (unchanged, now fully decoded beneath):
1. fs-context GSH(nvdrv:t) via the held sm session (root-native sm-get,
   the wave = fs, both Initialize and Ioctl same-process per pid-pinning).
2. The cmif ID sweep (safe: 0xF601 = clean unknown-command rejection).
3. Initialize (reaches svc 0x80 — the first fw23-new-syscall exercise),
   then the decoded nvmap/device ioctls, one at a time, no speculation.
4. Any nvservices abort = a pm crash report (bounded blast radius) —
   the design property that makes the parameter audit live-safe.

PARKED (package2/kernel-side blocked): svc kernel semantics, the KTN
decryption, the submit-chain deep audit, gpuk TIPC.
