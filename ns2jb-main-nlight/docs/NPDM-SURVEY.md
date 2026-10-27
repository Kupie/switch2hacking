# NPDM Capability Survey — Switch 2 (HOS 23)

**Session:** `switch2-y28jUe` (SESSION READY 13:42:28, first full-chain boot with P0.8/P0.9)
**Captured:** 12 of 64 modules before the console froze (retarget budget exhausted)
**Store:** `npdm-captures/` (persistent, survives reboots — later boots fill in the rest)

## The freeze (why we stopped at 12)

The console wedges after a **per-boot budget of ~10–15 distinct-window retargets**
through the corrupted fs session. Tonight's data is consistent:

| Boot | Wedged at |
|------|-----------|
| Vakzep | probe ~13 |
| ZcWqyf | probe 13/13 |
| 1q8QB4 | probe 11/12 |
| **y28jUe survey** | **module ~13** |

JZjsZM's 45-minute "stability" was 20k ops **inside one window** (zero retargets
after the first). The survey's per-module CodeFS opens are one retarget each —
12 modules in, the budget ran out. This is a physics constraint, not a bug to
fix: the fs session is single-threaded through a corrupted state and dies
after a fixed number of window hops.

## Captured so far (12 modules, no debug suite yet)

| Title | Module | NPDM title | SVCs | Debug suite |
|-------|--------|-----------|------|-------------|
| 0400000000000006 | usb.gen2 | usb.gen2 | 63 | — |
| 0400000000000008 | boot2 | boot2.ProdBoot | 49 | — |
| 0400000000000009 | settings | settings | 49 | — |
| 040000000000000A | Bus | Bus | 64 | — |
| 040000000000000B | bluetooth.autog | bluetooth.gen2 | 52 | — |
| 040000000000000C | bcat | bcat | 51 | — |
| 040000000000000E | friends | friends | 49 | — |
| 040000000000000F | nifm | nifm | 49 | — |
| 0400000000000010 | ptm.prod | ptm.prod | 63 | — |
| 0400000000000012 | bsdsocket | bsdsocket | 63 | — |
| 0400000000000013 | hid | hid | 63 | — |
| 0400000000000014 | audio | audio | 63 | — |
| 0400000000000034 | fatal | fatal | 49 | — |
| 0400000000000035 | grc | grc | 51 | — |
| 0400000000000036 | creport | creport | 49 | DebugActiveProcess, GetDebugEvent, GetDebugThreadContext, QueryDebugProcessMemory, ReadDebugProcessMemory, GetDebugThreadParam |
| 0400000000000037 | ro | ro | 55 | — |
| 0400000000000039 | sdb | sdb | 49 | — |
| 0400000000000042 | pgl | pgl | 49 | — |
| 0400000000000045 | omm | omm | 50 | — |
| 040000000000004D | lrp | lrp | 51 | — |
| 0400000000000052 | cmptldr | cmptldr | 51 | — |
| 0400000000000080 | gsvm | gsvm | 49 | — |

**Debug suite holders: creport only (see RESULT above).**

## RESULT: creport has the debug suite (found on the mDZ0xk boot)

The priority capture worked on the first READY session that ran it:

```
creport (0400000000000036): 49 SVCs —
  DebugActiveProcess(0x60) ✓      GetDebugEvent(0x63) ✓
  GetDebugThreadContext(0x67) ✓   QueryDebugProcessMemory(0x69) ✓
  ReadDebugProcessMemory(0x6A) ✓  GetDebugThreadParam(0x6D) ✓
  — no WriteDebugProcessMemory(0x6B), no ContinueDebugEvent(0x64)
```

`fatal`, `sdb`, `lrp`: no debug SVCs. Second round (grc, cmptldr, pgl,
omm, gsvm): no debug SVCs. **No surveyed module has the full union**
(sessions + process-memory + debug) that the current payload binary needs.

## The two-process relay design (decided)

Creport's policy is a pure *client* profile: it lacks the server-side
session SVCs (0x40-0x45) and the process-memory suite (0x73-0x78) the
monitor payload uses, but it **contains every client primitive**
(connect 0x1F, send 0x21, close 0x16, wait 0x18, pid 0x24, sleep 0x0B)
plus the debug suite. So:

1. **RO monitor** (ro policy, unchanged) — hosts `ro:1`/`ro:dmnt`, runs the
   takeover machinery and the rig worker.
2. **creport-payload** (new, launched as a SECOND process under title
   0036's policy) — a pure client: connects to `ro:dmnt` via sm, then loops
   "give me work" → executes `DebugActiveProcess(pid)` /
   `ReadDebugProcessMemory` / `GetDebugThreadContext` → replies.
3. The monitor's rig worker relays PC commands into that session. No
   handle plumbing needed — `DebugActiveProcess` takes a raw PID; PIDs
   come from the monitor side (launch records, GetProcessId on sessions).

The manifest now pins creport's policy:
`policies["0400000000000036"] = 97db2b3d…` (sha256 of the captured NPDM),
so `donor-prepare` accepts it on the next boot without PC edits mid-window.

**Open question the first experiment answers:** does retail gate
`DebugActiveProcess` to *crashed* processes only (pm sets the debug flag on
crash — that is the whole crash-report pipeline)? First rig test: attach
to a live process and read the error code. If live attach is permitted →
cross-process read of everything. If crashed-only → the debug track
becomes deliberate-crash forensics (full register/context dump of any
process we can fault — a precise oracle, far better than the timing side
channels) and the write track needs a different donor.

## Survey store (22 NPDMs, accumulates across boots)


## Capability reference (HOS 23 SVC map, from tonight's captures)

The "interesting" set the decoder flags: `ReadWriteRegister(0x4E)`,
`QueryMemoryMapping(0x55)`, `CreateDeviceAddressSpace(0x56)`,
`AttachDeviceAddressSpace(0x57)`, `DetachDeviceAddressSpace(0x58)`,
`MapDeviceAddressSpaceByForce(0x59)`, `MapDeviceAddressSpaceAligned(0x5A)`,
`UnmapDeviceAddressSpace(0x5C)`. The ro policy (`0x…0037`, our current donor)
has the process-memory suite `0x73-78` but **no** debug suite `0x60-0x6D`.

## What happens next

1. Reboot → `LOAD "TXT:NS2"` → `RUN` → `V=GO2()` (the 3-line dance)
2. On SESSION READY: `node npdm-survey.cjs` (now defaults to the 4 priority
   targets, skips what the store already has, stops before exhausting the
   budget)
3. If creport has the debug suite: pin → relaunch monitor under it → escalate
4. If not: next boot continues down the priority list, one or two per boot
