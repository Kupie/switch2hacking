#!/usr/bin/env python3
"""Add SVC permissions to a staged policy NPDM (ACI0 + ACID KAC SVC entries).

Usage: npdm-svc-patch.py <in.npdm> <out.npdm> <svc-hex> [<svc-hex>...]
"""
# The SVC mask lives in KAC "trailing-ones-4" entries (u32): bits [28:5] = a
# 24-bit permission block, bits [31:29] = block index, low 4 bits = 0b1111
# marker (same decoder as npdm-tool.py; verified against the console-captured
# NPDMs). svc -> block (svc // 24), bit (svc % 24).
#
# Only EXISTING entries are patched (pure bit-flips): the tool refuses to
# grow a KAC (no section surgery, no size changes) so the donor-prepare
# sha-pinning stays a byte-exact swap. Both ACI0 (per-process) and ACID
# (signed mirror) are patched, keeping their intersection intact.
#
# Usage: npdm-svc-patch.py <in.npdm> <out.npdm> <svc-hex> [<svc-hex>...]
# Example (read-only debug suite for the RO monitor policy):
#   python3 npdm-svc-patch.py engine/switch2/ro/payload/policy-0037-boot.npdm \
#     engine/switch2/ro/payload/policy-0037-debug.npdm 0x60 0x69 0x6A
import struct, sys, hashlib
import importlib.util

spec = importlib.util.spec_from_file_location('npdm_tool', 'npdm-tool.py')
npdm_tool = importlib.util.module_from_spec(spec)
_saved_argv = sys.argv
sys.argv = ['npdm-tool.py']
spec.loader.exec_module(npdm_tool)
sys.argv = _saved_argv


def kac_ranges(data):
    # (aci_off, aci_size) at META+0x70, (acid_off, acid_size) at META+0x78;
    # KAC offset/size at section+0x30/0x34 (npdm-tool.py parse() layout).
    u32 = lambda o: struct.unpack_from('<I', data, o)[0]
    aci_off, aci_size = u32(0x70), u32(0x74)
    acid_off, acid_size = u32(0x78), u32(0x7C)
    assert data[aci_off:aci_off + 4] == b'ACI0', 'no ACI0 at recorded offset'
    # ACID section starts with sig(0x100)+key(0x100)(+0x100 extra on fw23);
    # the magic sits after them — find it, then read the KAC fields at
    # magic+0x30/0x34 whose VALUES are relative to the section start
    # (npdm-tool.py parse() layout, empirically verified on live fw23).
    magic = data.find(b'ACID', acid_off, acid_off + 0x400)
    assert magic > 0, 'no ACID magic in the recorded section'
    return [(aci_off + u32(aci_off + 0x30), u32(aci_off + 0x34)),
            (acid_off + u32(magic + 0x30), u32(magic + 0x34))]


def patch(data, svcs):
    data = bytearray(data)
    for start, size in kac_ranges(data):
        assert size % 4 == 0, 'KAC size not a word multiple'
        blocks = {}
        for off in range(start, start + size, 4):
            d = struct.unpack_from('<I', data, off)[0]
            t = 0
            v = d
            while v & 1:
                v >>= 1
                t += 1
            if t == 4:
                blocks.setdefault((d >> 29) & 7, []).append(off)
        for svc in svcs:
            block, bit = divmod(svc, 24)
            if block not in blocks:
                raise SystemExit('no SVC KAC entry for block %d (svc 0x%x): '
                                 'KAC growth is refused by this tool' % (block, svc))
            for off in blocks[block]:
                d = struct.unpack_from('<I', data, off)[0]
                struct.pack_into('<I', data, off, d | (1 << (bit + 5)))
    return bytes(data)


def main():
    if len(sys.argv) < 4:
        raise SystemExit(__doc__)
    src, dst, svcs = sys.argv[1], sys.argv[2], [int(s, 16) for s in sys.argv[3:]]
    data = open(src, 'rb').read()
    before = npdm_tool.parse(src)
    patched = patch(data, svcs)
    open(dst, 'wb').write(patched)
    after = npdm_tool.parse(dst)
    added = [s for s in svcs if s not in before['final_svc'] and s in after['final_svc']]
    kept = [s for s in before['final_svc'] if s not in after['final_svc']]
    assert not kept, 'patch dropped existing svcs: %r' % kept
    assert len(patched) == len(data), 'size changed (refused by design)'
    for s in svcs:
        assert s in after['final_svc'], 'svc 0x%x missing after patch' % s
    print('size', len(patched), 'sha256', hashlib.sha256(patched).hexdigest())
    print('final svc count', len(before['final_svc']), '->', len(after['final_svc']),
          '| newly granted:', ['0x%x' % s for s in added])


if __name__ == '__main__':
    main()