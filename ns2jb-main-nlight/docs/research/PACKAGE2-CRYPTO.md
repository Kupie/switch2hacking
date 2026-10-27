# package2 decryption track

Goal: the decrypted fw23 kernel (KTN) + the boot chain from the banked
encrypted artifacts. All material on disk (see STATUS.md §4/§8).

## Inventory
- `~/dev/switch/dumps/fw23-boot/bis-0-full.bin` (32 MB, sha 101c2b4f…) — BOOT0
- `~/dev/switch/dumps/fw23-boot/bis-10-full.bin` (32 MB, sha 09fb8e4f…) — BOOT1
- Layout (both, mirrored): BCT `BCTB` @0x0 (0x84 B + pad); NVDA blob1
  @0x1E000 (~476 KB, encrypted from +4); NVDA blob2 @0x9E000 (~92 KB);
  NVDA blob3 @0xC0000 (~28 KB, **identical across slots**); package2 mass
  @0x103000+ (~4.2 MB, different versions per slot, common 4 KB header).
- fw23 modules (85) incl. tsec 0x8d (the HDCP adapter — the TSEC hardware
  driver, NOT the key engine), nvservices, the live-captured fs binary.

## The chain to break
BCT → (points at) package1 [NVDA container, encrypted] → package1ldr
(runs on the BPMP / in the boot ROM context) → decrypts package2 with
keys derived via TSEC + fuses → the kernel (KTN) + KIPs.

## Working notes
(chronological, newest last)

### 2026-10-25 — the chain fully mapped (community docs + our dumps)

The Switch 2 boot chain (switchbrew "Switch 2:" pages) = decoded against
our dumps, EVERYTHING MATCHES:

| LUN0 offset (our dump) | documented | our parse |
|---|---|---|
| 0x0 | BRBCT ("BCTB") | only 0x84 B live (DigestHash + PublicParams head; sig areas zero — the ptinfo = inside the AES-GCM section) |
| 0x1E000 + 0x20000 | MB1 (BCH + binary) | **MB1B**, 0x74b50 B, load/entry 0x50000000, v7.0.0 |
| 0x9E000 + 0xA0000 | PSC-BL (BCH + binary) | **PSCB**, 0x14500 B, load 0x120000, entry 0x120400 (doc-exact!), v8.0.0 |
| 0xC0000 + 0xC2000 | MB1-BCT (BCH + data) | **MBCT**, 0x46e7 B, load 0x40040000 (doc-exact!); data = **'MM' magic + size 0x46e7** (doc-exact!) |
| 0x103000 | BootConfig | 0x1000 B, one field +0x20 = 0x01000000 (16 MiB package2 capacity) |
| 0x104000 | Package2 | the diverge point across slots = the version-specific p2 start ✓; LUN1 = the A/B copy ✓ |

- The **BCH (NvBootComponentHeader) format is fully documented and PLAINTEXT
  in our dumps** (outer/inner digests, XMSS/RSA sigs, stage IVs/ECIDs, Duk,
  DerStrs, component tables with BinaryMagic/len/load/entry/ver/IV/AuthTag).
- **PSC-BL = the Switch 2's TSEC-successor** (the Platform Security
  Controller bootloader): PSC-ROM → PSC-BL → PSC-FW = the key-derivation
  engine. PSC-BL = AES-GCM with the **SBK** (fuses).
- The BRBCT's FskpTestKey/TzDerStr/SecProvision fields + the fuse map:
  **SecureBootKey[0..255] = fuse words 766-773** (+ tags) — per-console,
  hardware-locked.
- LUN1 = the second slot with a DIFFERENT package2 version (A/B pair).

### The blocker = the keys (three routes)

1. **The fw23 package2 key is per-FIRMWARE (console-independent)** — the
   scene's key dumps (the emulator/CFW key files) should contain the
   fw23 "package2 key" (and/or the master-key chain that derives it).
   **THE ASK: the community for the fw23 package2 key / the keygen file.**
2. The console's SBK (fuse words 766-773): hardware-locked, not
   userland-readable (spl never exposes it). The Switch 1 scene got it
   via TSEC exploitation / physical fuse dumps. The Switch 2 equivalent =
   the PSC exploit research.
3. MB1/PSC-BL decryption (needed for the PSC chain RE): AES-GCM with
   SBK-derived keys — same blocker as 2.

### Next
- Ask the community for the fw23 keys (route 1 = the fastest).
- PSC-FW location hunt: not in LUN0's layout — likely in the firmware
  package titles (0x819-0x81C-class) or loaded by PSC-BL from elsewhere;
  check the Switch 2 TSEC-services pages + the firmware title contents
  (SYSTEM:/Contents registered NCAs).
- Parse the remaining BCH fields (the sig/digest verifications = possible
  offline: the digests hash plaintext areas!!) + the package2 header
  format hunt (the Switch 1 CTR-formula failed → the fw23 p2 header =
  a new format — check the 23.0.0 firmware page + the scene's sources).
