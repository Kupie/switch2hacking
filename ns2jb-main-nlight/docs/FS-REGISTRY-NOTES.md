# fs registry reversing notes (2026-10-24/25, boot k3FMD7 + offline)

## Where things live

- fsp-pr service name string: `fsp-pr` at 0x5992242fac (code rodata)
- Service registrations in fs text 0x59920114b0..0x5992011630:
  - fsp-srv registered w8=3 (max sessions), object DAT_59930c7040-ish table at 0x59920114cc
  - fsp-pr registered **w8=1** (single session!) via sm register (bl 0x599220b5f0)
  - fsp-ldr registered separately (name ref 0x5992011f70)
- fsp-pr service object: DAT_59930c70d8 -> 0x599229d020 (in the 0x5992296000-0x59922a7000
  gap region NOT included in fs-live.elf — need to re-dump or Ghidra rebase)
- fsp-ldr worker FUN_5992011640: dispatch on [lVar10+0x38] (message kind?):
  - ==3: SetCurrentProcess-ish path (per-pid association via FUN_59920fe670 with
    {pid, handle, uVar15})
  - ==2: FUN_599220b900 (session close?)
  - ==1: OpenCode path (FUN_599220b7a0 + registry FUN_599202c730)
- The owned-44553bb000.bin blob is the APP's memory (SPAN_MARKER strings etc),
  NOT fs heap — no registry there.

## Live registry state (in-window reads)

- fs program registry entries reachable via the root-object graph
  (root+0x178/0x1b8/0x2a8): tid + ptr table + INLINE PATH STRINGS
  ('/Contents/registered/<nca>.nca') at +0x48 window of the +0x1b8 entry.
- The +2a8 entry also embeds the RO program id 0x0400000000000037 at +0x90
  (pid 1 class = the RO process registration).
- fs HEAP pointers (registry objects, 0x48d2xxxxxxxx) are OUTSIDE the retained
  read window — cannot chase while resumed. This is the boundary of live
  registry exploration.

## Conclusion

tid+path patching is insufficient (cmd 2 -> 0x1408 'no data fs'); the full
RegisterProgram descriptor (FsAccessControl buffers from NPDM) installs
content-type masks + more state in fs heap objects we cannot reach in-window.
The remaining routes:
1. fsp:pr open via a service-class that fs accepts (stolen-sm open WEDGES app;
   sdk open says unavailable) — pm's OWN session is the legitimate holder.
2. Read the missing 0x5992296000-0x59922a7000 gap (contains fsp-pr vtables)
   via a fresh bulk dump next boot (extend build-fs-elf.py REGIONS).
3. Clone the FULL registration entry by copying the complete heap object
   (needs window retarget = fresh acquisition).

## Registry structure decoded (fs-live reversing, second pass)

- fsp:pr/fsp-ldr are SINGLE-SESSION sm services (w3=1 in their registrations
  at 0x5992011568/0x5992011f84): pm and loader hold them. NO direct open.
- fs program registry = LINKED LIST, node 0x20 bytes:
  {prev@+0, next@+8, pid@+0x10, programId@+0x18(u32)} — insert via
  FUN_59920fe7e0 (rsp-ldr worker), list head at static PTR_LOOP_59922a7030
  {head@+0x30, tail@+0x38} (self-linked when empty; empty in the dump).
- fsp-ldr worker (FUN_5992011640) dispatch: kind==1 open-code path,
  kind==2 session close, kind==3 SetCurrentProcess -> FUN_59920fe670
  (pid->handle assoc list).
- LIVE root-object +0x2a8 node (session boot) chases reveal the
  per-program descriptor: chase(+0x40) = {.., 2, 0, .., .., .., 0x164d6e2,
  0x61} — the trailing 0x61 = the registered dir id (00000061) inline.
  Full descriptor objects are OUT of the retained window (fs heap),
  but the dir-id tail is IN the chased object.

## What remains for the dump

Option A (cleanest): fsp:pr cmd 0 RegisterProgram via a pm-held session —
requires pm:shell command reversing (fw23 pm not yet dumped; boot-partition
like fs; other agent has pm ELF? CHECK) or the fsp-ldr SetCurrentProcess
association trick (loader-gated, likely also single-session).
Option B: in-window node patching — patch the registry node's programId to
MKW + the descriptor tail dir-id; proven INSUFFICIENT (0x1408) because the
data-fs open consults the FAH/FAC content masks in fs heap (out of window).
