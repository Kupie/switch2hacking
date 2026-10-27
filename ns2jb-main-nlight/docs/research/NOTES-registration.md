# ns launch-registration reversing notes (manual + codex rounds)

## Registration record structure (decoded from 0x1b5060 by hand)
Call: r(x0=record, x22=ptrA(two u64s), x21=ptrB(one u64), x20=ptrC(one u64))
```
rec[0x00] = u8 1            (valid)
rec[0x08] = 0x3eaa18        (static impl object, client-side)
rec[0x10] = 0
rec[0x28..0x38] = 0
rec[0x40] = 0 (u16)
rec[0x48] = 0x00012345      (magic, u32)
rec[0x50] = A[0]            (u64: program id?)
rec[0x58] = A[1]            (u64)
rec[0x70] = B[0]            (u64)
rec[0x78] = C[0]            (u64)
```
Built at call sites 0x1b6eb8 and 0x1b7078/0x1b723c with string ptr 0x333bc0
(adrp x2 #0x333000 + 0xbc0) and w8 = 0x1770000 stored into [sp+0x18]
(= A[0]?? 0x1770000 = a flags/version-ish constant) — check what 0x333bc0
contains (likely a mount-name string!) and what A[1] is at the call site.

## Send path
0x1b6ecc: bl 0x67950 with x0 = sp+0x18 (the record) — but 0x67950 is an
error wrapper; the real send is the virtual call at 0x67978-0x67984:
`ldr x9, [x15, #0x30]; blr x9` where x15 = [x8] with x8 = [x1+0x10].
NEED: the concrete vtable target (the fs-session impl object type) and the
cmif command id + inline/descriptor layout it assembles for the record.

## Context: why this matters
The full-form OpenFileSystemWithId (cmd 2 with type byte + program id +
attr + two FsPath records + this registration record) is what ns uses to
register-and-open installed-not-running game content at launch. Short-form
cmd-2 payloads are IGNORED by every session class we can create (app-owned
stolen-sm sessions and RO-owned SDK getService sessions all answer
by-current-process). The registration record is the missing piece for the
no-launch MKW RomFS dump.

## Codex round 5 (final): the concrete send

- Vtable: data 0x4038a8; slot +0x30 → 0x1815e0 (wrapper: resolves session
  via 0x181690, then calls marshaller 0x546a0).
- Marshaller 0x546a0 builds a HIPC **domain** message: word0 = 0x280001
  (stp w9,w26 at +0: w9=1|0x28<<16), command id = w26 = [x0+0x10] (a
  per-object constant stored in the fs-session wrapper object), SFCI magic
  + version word at +0x10, token from TLS, then the 0x80-byte registration
  record inline (str x22 at +0x30 = record start; fields at the decoded
  offsets, magic 0x12345 at rec+0x48, A[0]/A[1] at +0x50/+0x58, B[0] at
  +0x70, C[0] following).
- rodata 0x333bc0 = `00 40 0a 00 ...` (u64 0xA4000, the B[0] value the ctor
  stores), adjacent string at 0x333bc8 = `cache1/`.
- The word0 0x280001 domain form + object-id w26 + 0x80-byte inline record
  is the exact wire needed to register program content paths with fs.
  Next-boot experiment: domain-send on the root fs session (our
  app/domain.cjs domain.send is proven on BIS handles) with the record
  fields from the launch-flow call sites (0x1770000, program id from the
  launch, content paths). Determine w26 (object id) empirically or from
  the object constructor.
