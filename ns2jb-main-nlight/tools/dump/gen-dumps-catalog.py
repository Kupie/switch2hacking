#!/usr/bin/env python3
"""Regenerate docs/DUMPS-CATALOG.md — the complete sha256 catalog of every
non-game dump under ~/dev/switch/dumps/.

Only ORIGINAL dumped bytes are cataloged; derived artifacts (Ghidra ELF
wrappers, dumper meta.json, report files) are excluded from the hash
tables and listed per section. Full sha256 per file, sha256sum -c layout.

Usage: python3 tools/dump/gen-dumps-catalog.py [--check]
  --check  verify every cataloged hash matches the file on disk (no writes)
"""
import os, json, hashlib, datetime, subprocess, sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ROOT = os.path.expanduser('~/dev/switch/dumps')
OUT = os.path.join(REPO, 'docs', 'DUMPS-CATALOG.md')

def sha(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''): h.update(chunk)
    return h.hexdigest()

def fsize(n):
    for u in ['B', 'KiB', 'MiB', 'GiB']:
        if n < 1024 or u == 'GiB': return f'{n:.1f}{u}' if u != 'B' else f'{n}B'
        n /= 1024

def hr(p): return os.path.getsize(p)

def build():
    fw = os.path.join(ROOT, 'fw23')
    # ALL storage-3 system titles (04 + 000000000000.. hex tid; includes 1xxx)
    titles = sorted(d for d in os.listdir(fw)
                    if len(d.split('-')[0]) == 16 and d.split('-')[0].startswith('040000000000')
                    and os.path.isdir(os.path.join(fw, d)))
    arch_root = os.path.join(ROOT, 'fw23-archives')
    arch_dirs = sorted(d for d in os.listdir(arch_root)
                       if os.path.isdir(os.path.join(arch_root, d)))
    arch_rows, arch_total_files, arch_total_size = [], 0, 0
    for d in arch_dirs:
        m = json.load(open(os.path.join(arch_root, d, 'manifest.json')))
        n, s = len(m['files']), sum(f['size'] for f in m['files'])
        arch_rows.append((d, m['version'], m['contentId'], m.get('attributes'),
                          n, s, sha(os.path.join(arch_root, d, 'manifest.json'))))
        arch_total_files += n; arch_total_size += s

    livefs = os.path.join(ROOT, 'fw23-live-fs')
    live_files = sorted(f for f in os.listdir(livefs)
                        if (f.startswith('r-') or f.startswith('owned-'))
                        and os.path.isfile(os.path.join(livefs, f)))
    boot = os.path.join(ROOT, 'fw23-boot')
    bis = os.path.join(ROOT, 'switch2-1u9ld7')

    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
    commit = subprocess.run(['git', 'rev-parse', '--short', 'HEAD'], cwd=REPO,
                             capture_output=True, text=True).stdout.strip()

    L = []; A = L.append
    A('# Switch 2 fw23.0.1 — console-attached dump catalog')
    A('')
    A(f'Generated **{now}** · repo `gitlab.com/nlightcho/ns2jb` @{commit}')
    A('')
    A('Every non-game dump from the lab console, decrypted **on-console** via the')
    A('tethered-jailbreak loader routes (ldr:ro CodeFS / fs cmd 10 / owned root).')
    A('No keys included or needed — the loose decrypted form is the deliverable')
    A('(keyless-loader design). Game dumps are NOT in this catalog.')
    A('')
    A('**Only original dumped bytes are cataloged** — derived artifacts')
    A('(Ghidra ELF wrappers, dumper-generated `meta.json`, report files) are')
    A('excluded from the hash tables and listed per section.')
    A('')
    A('**Contents**')
    A('')
    A('1. [BIS partitions (raw)](#1-bis-partitions-raw)')
    A(f'2. [Live fs sysmodule](#2-live-fs-sysmodule-live-memory-regions)')
    A(f'3. [System programs ({len(titles)} titles)](#3-system-programs-{len(titles)}-titles)')
    A(f'4. [System data archives ({len(arch_dirs)} titles, {arch_total_files:,} files)]'
      f'(#4-system-data-archives-{len(arch_dirs)}-titles-{arch_total_files}-files)')
    A('5. [Full-BIS file trees](#5-full-bis-file-trees)')
    A('6. [Notes](#notes)')
    A('')
    A('---')
    A('')

    # ================= 1. BIS partitions =================
    A('## 1. BIS partitions (raw)')
    A('')
    A('Raw NAND partition images read via the owned root. This is the complete')
    A('raw-partition inventory — **BIS 0, 10, 27, 35 are dumped; 20/30/31 are')
    A('not raw-dumped** (see the table).')
    A('')
    A('| BIS id | name | dump(s) | size |')
    A('|---|---|---|---|')
    A(f'| 0 | bootA | `fw23-boot/bis-0.bin` (trimmed) · `fw23-boot/bis-0-full.bin` ≡ '
      f'`switch2-1u9ld7/bis0-bootA.bin` (full) | {fsize(hr(os.path.join(boot,"bis-0-full.bin")))} full / '
      f'{fsize(hr(os.path.join(boot,"bis-0.bin")))} trimmed |')
    A(f'| 10 | bootB | `fw23-boot/bis-10.bin` (trimmed) · `fw23-boot/bis-10-full.bin` ≡ '
      f'`switch2-1u9ld7/bis10-bootB.bin` (full) | {fsize(hr(os.path.join(boot,"bis-10-full.bin")))} full / '
      f'{fsize(hr(os.path.join(boot,"bis-10.bin")))} trimmed |')
    A(f'| 27 | calibration | `switch2-1u9ld7/bis27-calibration.bin` | {fsize(hr(os.path.join(bis,"bis27-calibration.bin")))} |')
    A(f'| 35 | SD seed | `switch2-1u9ld7/bis35-sdseed.bin` | {fsize(hr(os.path.join(bis,"bis35-sdseed.bin")))} |')
    A('| 20 | user NAND | **not raw-dumped** (encrypted; keys not in scene) | — |')
    A('| 30 | USER (FAT) | **not raw-dumped** — file tree copy instead (§5) | — |')
    A('| 31 | SYSTEM (FAT) | **not raw-dumped** — file tree copy instead (§5) | — |')
    A('')
    A('```')
    for f in sorted(os.listdir(boot)):
        if os.path.isfile(os.path.join(boot, f)):
            A(f'{sha(os.path.join(boot, f))}  fw23-boot/{f}')
    for f in sorted(os.listdir(bis)):
        if f.endswith('.bin'):
            A(f'{sha(os.path.join(bis, f))}  switch2-1u9ld7/{f}')
    A('```')
    A('')
    A('---')
    A('')

    # ================= 2. live fs =================
    A('## 2. Live fs sysmodule (live-memory regions)')
    A('')
    A('The boot-critical `fs` sysmodule (`0400000000000000`), read from **live')
    A('process memory** — it is package2-bound, never NCM-registered, so the')
    A('CodeFS route cannot see it. Execute-only text was flipped RX for the read')
    A(f'and restored after (kernel result 0). **{len(live_files)} region files**:')
    A('')
    A('```')
    for f in live_files:
        A(f'{sha(os.path.join(livefs, f))}  fw23-live-fs/{f}')
    A('```')
    A('')
    A('*Excluded (derived): `fs-live.elf` — analysis ELF reconstructed from these')
    A('regions (`fw-re/build-fs-elf.py`); `FSDUMP.md` — the method write-up.*')
    A('')
    A('**Completeness — package2 modules:** the other boot-critical modules')
    A('(`loader`, `sm`, `pm`) are **not** live-dumped: like `fs` they are')
    A('package2-bound (never NCM-registered), and they exist decrypted only in')
    A('live process memory. Their encrypted package2 container **is** captured')
    A('(§1 raw boot partitions) — but package2 crypto keys are not in the scene')
    A('(T239/tsec RE — see `docs/research/PACKAGE2-CRYPTO.md`), so no decrypted')
    A('loose form exists for them. `fs` was the one live-dumpable module used')
    A('here.')
    A('')
    A('---')
    A('')

    # ================= 3. system programs =================
    # completeness: NCM storage-3 knows 90 titles; local dirs cover the
    # unpacked ones; the rest are meta-only stubs (nothing to dump).
    ncm = json.load(open(os.path.join(fw, 'nca-structure.json')))['titles']
    ncm_by_id = {t['title']: t for t in ncm}
    unpacked = {t.split('-')[0] for t in titles}
    stubs = sorted(set(ncm_by_id) - unpacked)
    A(f'## 3. System programs ({len(titles)} of {len(ncm)} NCM titles)')
    A('')
    A(f'The **complete fw23.0.1 storage-3 inventory is {len(ncm)} NCM titles**:')
    A(f'{len(titles)} unpacked below + {len(stubs)} meta-only stubs (see the')
    A('completeness block after the hash table). The boot-critical `fs` module')
    A('is NOT NCM-registered (package2-bound) — it is dumped from live memory')
    A('in §2.')
    A('')
    A('Per title: **`text.bin` / `rodata.bin` / `data.bin`** (decrypted NSO section')
    A("images via CodeFS) + **`main.npdm`** (the module's real NPDM read from the")
    A('NCA). All paths relative to the dump root — `cd ~/dev/switch/dumps &&')
    A('sha256sum -c` compatible.')
    A('')
    A('```')
    for t in titles:
        d = os.path.join(fw, t)
        A(f'# {t}')
        for f in ['text.bin', 'rodata.bin', 'data.bin', 'main.npdm']:
            p = os.path.join(d, f)
            if os.path.exists(p): A(f'{sha(p)}  fw23/{t}/{f}')
    A('```')
    A('')
    A('*Excluded (derived): `fw23/elf/` — ELF64 wrappers generated from the')
    A('section binaries (`fw-re/make_elf.py`); per-title `meta.json`; top-level')
    A('`FIRMWARE-DUMP.txt` / `nca-structure.json` / `manifest.json` reports.*')
    A('')
    A(f'**Completeness — the {len(stubs)} meta-only titles (NCM-registered, no dump):**')
    A('')
    A('| TITLE | LEDGER STATUS | NCA CONTENT |')
    A('|---|---|---|')
    led = {e['title']: e for e in json.load(open(os.path.join(fw, 'manifest.json')))}
    for t in stubs:
        e = led.get(t, {})
        cids = ', '.join(f'`{v["contentId"]}`' for v in ncm_by_id[t]['contents'].values())
        A(f'| `{t}` | {e.get("status", "?")} | {cids} |')
    A('')
    A('These registered a Program NCA but their CodeFS carries **no main')
    A('module** — placeholder/registration-only entries with nothing to dump.')
    A('(Note: `FIRMWARE-DUMP.txt` says "88 titles" — its generator counted the')
    A('`elf/` placeholder row; the real count is 87 unpacked + these 3 stubs.')
    A('The 57 data archives are NOT storage-3 0x01 titles and are in §4.)')
    A('')
    A('**GPU completeness:** the whole NVIDIA driver stack is among the 87 —')
    A('nvservices (0019, the nvdrv service surface), nvkernel (004f), ngc')
    A('(0050), vi2 (0063), host1x (0065), gc (0062), tsec (008d),')
    A('gsvm/gsv1/gsv3/gsv4 (0080/81/83/84), adraw (0072). The GPU')
    A('**microcode** (`fecs/gpccs/gpmu/acr/gsp` ucode) rides the nvservices')
    A('Program-NCA **RomFS**, which no current route opens (cmd 10 builds only')
    A('data readers; fs 206 type-1 needs the licensed-prelude context) — a')
    A('documented gap, route map in `FINDINGS.md` 2026-10-26 (3).')
    A('')
    A('---')
    A('')

    # ================= 4. archives =================
    A(f'## 4. System data archives ({len(arch_dirs)} titles, {arch_total_files:,} files)')
    A('')
    A('metaType-0x02 system data archives (8xx titles), dumped via fs cmd 10')
    A('(OpenFileSystemWithId) fsType 6 — fresh-boot reproducible, zero refusals.')
    A('')
    A('Each archive ships `archive/` loose RomFS files + `manifest.json`, which')
    A('carries **every per-file sha256, size and path** (the per-file hashes live')
    A('there — not reproduced here). The hashes below are of the manifests.')
    A('')
    A('| TITLE | VERSION | CONTENT ID (NCA) | ATTR | FILES | SIZE | MANIFEST SHA256 |')
    A('|---|---|---|---|---|---|---|')
    for d, ver, cid, attr, n, s, msha in arch_rows:
        A(f'| `{d}` | {ver} | `{cid}` | {attr} | {n} | {fsize(s)} | `{msha[:16]}…` |')
    A(f'| **TOTAL** | | | | **{arch_total_files:,}** | **{fsize(arch_total_size)}** | |')
    A('')
    A('```')
    for d, ver, cid, attr, n, s, msha in arch_rows:
        A(f'{msha}  fw23-archives/{d}/manifest.json')
    A('```')
    A('')
    A('---')
    A('')

    # ================= 5. full-bis trees =================
    A('## 5. Full-BIS file trees')
    A('')
    A('File-level copies of the **BIS 31 (SYSTEM)** and **BIS 30 (USER)** FAT')
    A('partitions (read-only, via the owned root — not raw partition images):')
    A('')
    def tree(p):
        n = s = 0
        for dp, _, fs in os.walk(p):
            for f in fs: s += os.path.getsize(os.path.join(dp, f)); n += 1
        return n, s
    sn, ss = tree(os.path.join(bis, 'system'))
    un, us = tree(os.path.join(bis, 'user'))
    A(f'- `switch2-1u9ld7/system/` — {sn} files, {fsize(ss)}')
    A(f'- `switch2-1u9ld7/user/` — {un} files, {fsize(us)}')
    A('')
    A('`dump-manifest.json` carries every file\'s sha256 + on-NAND allocation size')
    A('(sizes sum to 148GiB — NAND allocation, not local file size; on-disk')
    A('~616MB):')
    A('')
    A('```')
    A(f'{sha(os.path.join(bis, "dump-manifest.json"))}  switch2-1u9ld7/dump-manifest.json')
    A('```')
    A('')
    A('---')
    A('')

    # ================= notes =================
    A('### Notes')
    A('')
    A('- **Verification** — `cd ~/dev/switch/dumps && sha256sum -c <block>`; every')
    A('  hash above is the full file sha256 of the original dumped bytes.')
    A('- **Routes** — system programs via ldr:ro CodeFS; system archives via')
    A('  **fs cmd 10 fsType 6** (the 206 dispatcher mask-gates type-6 into the')
    A('  host flow — data archives are unreachable through 206 by design); live')
    A('  fs via rig `0x524f0016` bulk reads; BIS partitions via the owned root.')
    A('- **Not in this catalog (games)** — `~/dev/switch/roms/<title-id>/`')
    A('  (SmileBASIC `0100c9100b06a000`, TOTK `0100f2c0115b6000`, MKW-dev')
    A('  `0400c3f00006e000`) and `~/dev/ns2emu/reference/` deliverables.')
    A('- **Derived artifacts** (regenerable, not cataloged) — `fw23/elf/`,')
    A('  `fw23-live-fs/fs-live.elf`, per-title `meta.json`,')
    A('  `FIRMWARE-DUMP.txt` / `nca-structure.json` / `manifest.json` reports.')
    A(f'- **Provenance** — route history + decode write-ups: `FINDINGS.md` @{commit}.')
    A(f'- **Regenerate** — `python3 tools/dump/gen-dumps-catalog.py` (repo tool);')
    A(f'  `--check` verifies every hash against disk.')
    return '\n'.join(L) + '\n'

def parse_hashes(text):
    import re
    return re.findall(r'^([0-9a-f]{64})  (.+)$', text, re.M)

def check():
    text = open(OUT).read()
    bad = missing = ok = 0
    for h, rel in parse_hashes(text):
        p = os.path.join(ROOT, rel)
        if not os.path.exists(p):
            missing += 1; print('MISSING', rel); continue
        if sha(p) == h: ok += 1
        else: bad += 1; print('MISMATCH', rel)
    print(f'check: {ok} ok / {bad} mismatch / {missing} missing')
    return bad == 0 and missing == 0

if __name__ == '__main__':
    if '--check' in sys.argv:
        sys.exit(0 if check() else 1)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    open(OUT, 'w').write(build())
    print('WROTE', OUT)
    print('lines:', build().count('\n'))
    # self-check after write
    sys.exit(0 if check() else 1)