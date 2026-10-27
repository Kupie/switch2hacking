#!/usr/bin/env python3
# NSO0 unpacker for the fw23 firmware dump. LZ4 block decompression in pure
# Python (standard block format, no frame). Header layout calibrated
# empirically against captured mains (see fw-dump journal):
#   0x00 NSO0 magic, 0x04 version, 0x08 reserved, 0x0C flags (bits: compress)
#   0x10 text_off, 0x14 text_addr, 0x18 text_size   (decompressed)
#   0x20 ro_off,   0x24 ro_addr,   0x28 ro_size
#   0x30 data_off, 0x34 data_addr, 0x38 data_size, 0x3C bss_size
#   0x40 build_id[0x20], 0x60 text/ro/data compressed sizes
import sys, struct, os, json

def lz4_decompress(src, dest_size):
    dst = bytearray()
    i = 0
    while i < len(src) and len(dst) < dest_size:
        tok = src[i]; i += 1
        lit = tok >> 4
        if lit == 15:
            while True:
                b = src[i]; i += 1; lit += b
                if b != 255: break
        dst += src[i:i+lit]; i += lit
        if len(dst) >= dest_size: break
        if i >= len(src): break
        off = src[i] | (src[i+1] << 8); i += 2
        ml = (tok & 0xF)
        if ml == 15:
            while True:
                b = src[i]; i += 1; ml += b
                if b != 255: break
        ml += 4
        start = len(dst) - off
        if start < 0 or off == 0: raise ValueError('bad lz4 offset')
        for _ in range(ml):
            dst.append(dst[start]); start += 1
    if len(dst) != dest_size: raise ValueError('short decompress: %d != %d' % (len(dst), dest_size))
    return bytes(dst)

def unpack(nso):
    h = struct.unpack('<4sIIII', nso[:20])
    assert h[0] == b'NSO0', 'not NSO0'
    flags = h[3]
    text_off, text_addr, text_size = struct.unpack('<III', nso[0x10:0x1C])
    ro_off, ro_addr, ro_size = struct.unpack('<III', nso[0x20:0x2C])
    data_off, data_addr, data_size = struct.unpack('<III', nso[0x30:0x3C])
    bss_size, = struct.unpack('<I', nso[0x3C:0x40])
    text_c, ro_c, data_c = struct.unpack('<III', nso[0x60:0x6C])
    out = {}
    for name, off, csize, dsize, comp_bit in [
            ('text', text_off, text_c, text_size, 0),
            ('rodata', ro_off, ro_c, ro_size, 2),
            ('data', data_off, data_c, data_size, 4)]:
        blob = nso[off:off+csize]
        if flags & (1 << comp_bit):
            out[name] = lz4_decompress(blob, dsize)
        else:
            assert csize == dsize, name + ' uncompressed mismatch'
            out[name] = blob
    out['meta'] = dict(flags=flags, text_addr=text_addr, ro_addr=ro_addr,
                       data_addr=data_addr, bss_size=bss_size,
                       build_id=nso[0x40:0x60].hex())
    return out

def main():
    src, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    nso = open(src, 'rb').read()
    u = unpack(nso)
    base = u['meta']
    for name in ['text', 'rodata', 'data']:
        open(os.path.join(outdir, name + '.bin'), 'wb').write(u[name])
    json.dump(base, open(os.path.join(outdir, 'meta.json'), 'w'), indent=1)
    print('%s -> %s (text %d, ro %d, data %d, bss %d, flags 0x%x)' % (
        os.path.basename(src), outdir, len(u['text']), len(u['rodata']),
        len(u['data']), base['bss_size'], base['flags']))

if __name__ == '__main__':
    main()