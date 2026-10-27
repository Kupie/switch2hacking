#!/usr/bin/env python3
"""Add service names to a staged policy NPDM's SAC (ACI0 + ACID).

Usage: npdm-sac-patch.py <in.npdm> <out.npdm> <service-name> [<name>...]

Structure (verified against policy-0037-boot.npdm, 2026-10-26):
  META @0: aci_off@0x70, aci_size@0x74, acid_off@0x78, acid_size@0x7C
  ACI0 (at aci_off): SAC off/size @+0x28/+0x2c (ACI0-relative),
                     KAC off/size @+0x30/+0x34 (ACI0-relative)
  ACID (at acid_off): sig 0x100 + key 0x100 (+ extra 0x100 on fw23),
                     'ACID' magic found by search; SAC off/size @
                     magic+0x28/+0x2c (SECTION-relative, section start
                     = acid_off), KAC @+0x30/+0x34 (same base)
  SAC entry = u8 (len-1, bit7 = flag observed on ro-family names) + name.
             NO control byte. Section sizes are the sums (verified:
             6 entries -> 0x29).

The patch REBUILDS the file (unlike npdm-svc-patch.py's pure bit-flips):
each SAC grows by the new entries, the KAC is re-placed at the next
0x10 boundary after the SAC, and every size/offset field is fixed. The
file layout stays [META][ACID'][ACI0']. The ACID signature is NOT
re-signed — the launch path does not verify it (the existing KC/maskA
ACID patches prove this).

Refuses to duplicate an already-present name. KAC bytes verified
byte-identical after the rebuild.
"""
import struct, sys, hashlib

def u32(data, o): return struct.unpack_from('<I', data, o)[0]
def w32(data, o, v): struct.pack_into('<I', data, o, v)

def parse_sac(data, off, size):
    entries, at = [], 0
    while at < size:
        b = data[off + at]
        n = (b & 0x7f) + 1
        flag = b >> 7
        at += 1
        name = data[off + at:off + at + n].decode('ascii'); at += n
        entries.append((name, flag))
    assert at == size, f'SAC overrun: {at} != {size}'
    return entries

def build_sac(entries):
    out = bytearray()
    for name, flag in entries:
        assert len(name) <= 0x80 and name.isascii()
        out.append(((len(name) - 1) & 0x7f) | (flag << 7))
        out += name.encode()
    return bytes(out)

def main():
    if len(sys.argv) < 4:
        print(__doc__); sys.exit(2)
    src, dst, names = sys.argv[1], sys.argv[2], [n.lower() for n in sys.argv[3:]]
    data = open(src, 'rb').read()
    aci_off, aci_size = u32(data, 0x70), u32(data, 0x74)
    acid_off, acid_size = u32(data, 0x78), u32(data, 0x7c)
    assert data[aci_off:aci_off + 4] == b'ACI0', 'no ACI0 magic at recorded offset'
    magic = data.find(b'ACID', acid_off, acid_off + 0x400)
    assert magic > 0, 'no ACID magic in the recorded section'
    acid_body = magic - acid_off                       # sig+key+extra prefix

    aci_sac_rel = u32(data, aci_off + 0x28)
    aci_sac_off = aci_off + aci_sac_rel
    aci_sac_size = u32(data, aci_off + 0x2c)
    aci_kac_off, aci_kac_size = u32(data, aci_off + 0x30), u32(data, aci_off + 0x34)
    acid_sac_rel = u32(data, magic + 0x28)
    acid_sac_off = acid_off + acid_sac_rel
    acid_sac_size = u32(data, magic + 0x2c)
    acid_kac_off, acid_kac_size = u32(data, magic + 0x30), u32(data, magic + 0x34)

    aci_sac = parse_sac(data, aci_sac_off, aci_sac_size)
    acid_sac = parse_sac(data, acid_sac_off, acid_sac_size)
    print('ACI0 SAC:', [n for n, _ in aci_sac])
    print('ACID SAC:', [n for n, _ in acid_sac])

    new_aci, new_acid = list(aci_sac), list(acid_sac)
    for name in names:
        for lst, tag in ((new_aci, 'ACI0'), (new_acid, 'ACID')):
            if any(n == name for n, _ in lst):
                print(f'{name}: already present in {tag} — skip')
            else:
                lst.append((name, 0))
    aci_sac_new = build_sac(new_aci)
    acid_sac_new = build_sac(new_acid)

    # KAC re-placement: next 0x10 boundary after the SAC end
    aci_kac_new = (aci_sac_rel + len(aci_sac_new) + 15) & ~15
    acid_kac_new = (acid_sac_rel + len(acid_sac_new) + 15) & ~15
    aci_size_new = (aci_kac_new + aci_kac_size + 15) & ~16 + 0 if False else \
        (aci_kac_new + aci_kac_size + 15) & ~15
    acid_size_new = (acid_kac_new + acid_kac_size + 15) & ~15
    print('ACI0: sac', hex(len(aci_sac_new)), 'kac', hex(aci_kac_off), '->',
        hex(aci_kac_new), '| size', hex(aci_size), '->', hex(aci_size_new))
    print('ACID: sac', hex(len(acid_sac_new)), 'kac', hex(acid_kac_off), '->',
        hex(acid_kac_new), '| size', hex(acid_size), '->', hex(acid_size_new))

    # ---- rebuild ACID section ----
    # [prefix sig+key+extra][hdr 0x40][pad to sac][sac][pad to kac][kac][tail]
    aci_abs = aci_off
    acid_prefix = data[acid_off:magic]
    acid_hdr = data[magic:magic + 0x40]
    acid_kac = data[acid_off + acid_kac_off:acid_off + acid_kac_off + acid_kac_size]
    acid_tail = data[acid_off + acid_kac_off + acid_kac_size:acid_off + acid_size]
    new_acid = bytearray(acid_prefix)
    new_acid += acid_hdr
    # preserve the original gap bytes (hdr-end .. SAC start): the FsAccess
    # mask regions live here (ACID section-rel 0x340..) — zeroing would
    # destroy the console-captured maskA patch. Only NEW growth is padded.
    new_acid += data[magic + 0x40:acid_off + acid_sac_rel]
    assert len(new_acid) == acid_off + acid_sac_rel - acid_off, 'gap mismatch'
    new_acid += acid_sac_new
    new_acid += b'\0' * (acid_kac_new - len(new_acid))
    new_acid += acid_kac
    new_acid += acid_tail
    new_acid += b'\0' * (acid_size_new - len(new_acid))
    assert len(new_acid) == acid_size_new
    w32(new_acid, acid_body + 0x28, acid_sac_rel)
    w32(new_acid, acid_body + 0x2c, len(acid_sac_new))
    w32(new_acid, acid_body + 0x30, acid_kac_new)
    w32(new_acid, acid_body + 0x34, acid_kac_size)

    # ---- rebuild ACI0 section ----
    aci_hdr = data[aci_off:aci_off + 0x40]
    aci_kac = data[aci_off + aci_kac_off:aci_off + aci_kac_off + aci_kac_size]
    aci_tail = data[aci_off + aci_kac_off + aci_kac_size:aci_off + aci_size]
    new_aci = bytearray(aci_hdr)
    # preserve the original gap bytes (hdr-end .. SAC start) — the FsAccess
    # region (ACI0+0x40, size 0x1c per hdr) lives here.
    new_aci += data[aci_off + 0x40:aci_off + aci_sac_rel]
    new_aci += aci_sac_new
    new_aci += b'\0' * (aci_kac_new - len(new_aci))
    new_aci += aci_kac
    new_aci += aci_tail
    new_aci += b'\0' * (aci_size_new - len(new_aci))
    assert len(new_aci) == aci_size_new
    w32(new_aci, 0x28, aci_sac_rel)
    w32(new_aci, 0x2c, len(aci_sac_new))
    w32(new_aci, 0x30, aci_kac_new)
    w32(new_aci, 0x34, aci_kac_size)

    # ---- META patch ----
    assert acid_off == 0x80, f'unexpected ACID offset {hex(acid_off)}'
    meta = bytearray(data[:0x80])
    w32(meta, 0x74, aci_size_new)
    w32(meta, 0x7c, acid_size_new)
    new_aci_off = acid_off + acid_size_new
    w32(meta, 0x70, new_aci_off)

    out = bytes(meta) + bytes(new_acid) + bytes(new_aci)
    open(dst, 'wb').write(out)
    print('wrote', dst, hex(len(out)), 'bytes | aci_off', hex(new_aci_off))

    # ---- verify ----
    v = out
    a_off, a_size = u32(v, 0x70), u32(v, 0x74)
    d_off, d_size = u32(v, 0x78), u32(v, 0x7c)
    assert v[a_off:a_off + 4] == b'ACI0'
    m2 = v.find(b'ACID', d_off, d_off + 0x400)
    assert a_size == aci_size_new and d_size == acid_size_new
    sacs = {
      'ACI0': parse_sac(v, a_off + u32(v, a_off + 0x28), u32(v, a_off + 0x2c)),
      'ACID': parse_sac(v, d_off + u32(v, m2 + 0x28), u32(v, m2 + 0x2c)),
    }
    for tag, sac in sacs.items():
        print(tag, 'verify:', [n for n, _ in sac])
        for name in names:
            assert any(n == name for n, _ in sac), f'{name} missing in {tag}'
    # KAC byte-identical
    for tag, old_kac, sec_off, hdr in (('ACID', acid_kac, d_off, m2),
                                        ('ACI0', aci_kac, a_off, a_off)):
        kac_rel = u32(v, (hdr if tag == 'ACID' else a_off) + 0x30) if tag == 'ACID' \
            else u32(v, a_off + 0x30)
        new_kac = v[sec_off + kac_rel:sec_off + kac_rel + aci_kac_size] \
            if tag == 'ACI0' else v[d_off + u32(v, m2 + 0x30):d_off + u32(v, m2 + 0x30) + acid_kac_size]
        assert old_kac == new_kac, f'{tag} KAC bytes changed!'
    print('KAC verified byte-identical in both sections')
    print('sha256:', hashlib.sha256(out).hexdigest())

if __name__ == '__main__':
    main()