"""Synthetic encoding tests, runnable with python3 -m unittest -v test_xref."""
import contextlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest

from xref import Blob, decode_adrp, decode_bl, main


def adrp(reg, pc, target):
    imm = ((target >> 12) - (pc >> 12)) & ((1 << 21) - 1)
    return 0x90000000 | ((imm & 3) << 29) | ((imm >> 2) << 5) | reg


class XrefTests(unittest.TestCase):
    def make_blob(self, words, ro=None, data=None):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name)
        (path / 'meta.json').write_text(json.dumps(dict(text_addr='0x4000', ro_addr='0x2000', data_addr='0x3000')))
        for name, raw in [('text', struct.pack('<' + 'I' * len(words), *words)),
                          ('rodata', ro or b'Target\0'), ('data', data or b'\0' * 16)]:
            (path / (name + '.bin')).write_bytes(raw)
        return Blob(path)

    def test_signed_page_and_bl(self):
        for target in (0x2000, 0x9000, 0x100004000):
            pc = 0x100004ABC if target > 0xFFFFFFFF else 0x4ABC
            self.assertEqual(decode_adrp(adrp(9, pc, target), pc), (9, target))
        self.assertEqual(decode_bl(0x97FFFFFF, 0x4000), 0x3FFC)
        self.assertIsNone(decode_adrp(0x10000000, 0x4000))

    def test_add_window_and_clobber(self):
        first = adrp(0, 0x4000, 0x2000)
        add = 0x91000001  # add x1,x0,#0
        nop = 0xD503201F
        self.assertEqual(len(self.make_blob([first] + [nop] * 7 + [add]).scan({0x2000})[0x2000]), 1)
        self.assertFalse(self.make_blob([first] + [nop] * 8 + [add]).scan({0x2000})[0x2000])
        for barrier in (0xD2800000, 0x52800000, 0x94000001, 0x14000001):
            self.assertFalse(self.make_blob([first, barrier, add]).scan({0x2000})[0x2000])
        self.assertEqual(len(self.make_blob([adrp(0, 0x4000, 0x1000), 0x91400401]).scan({0x2000})[0x2000]), 1)

    def test_loads(self):
        blob = self.make_blob([adrp(0, 0x4000, 0x3000), 0xF9400001], data=struct.pack('<Q', 0x2000))
        self.assertEqual(blob.scan({0x2000})[0x2000][0].kind, 'ADRP+LDR pointer')
        blob = self.make_blob([adrp(0, 0x4000, 0x2000), 0x39400001])
        self.assertEqual(blob.scan({0x2000})[0x2000][0].kind, 'ADRP+LDR direct')
        literal = 0x58000001 | (((0x3000 - 0x4000) // 4 & 0x7FFFF) << 5)
        blob = self.make_blob([literal], data=struct.pack('<Q', 0x2000))
        self.assertEqual(blob.scan({0x2000})[0x2000][0].kind, 'LDR literal pointer')

    def test_output_and_call_depth(self):
        words = [0x94000002, 0xD65F03C0, 0x94000002, 0xD65F03C0,
                 0x94000002, 0xD65F03C0, 0xD65F03C0]
        blob = self.make_blob(words, ro=b'Target\0Target\0')
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            blob.follow_calls([(0x4000, 0x4008)], 2, 256, {})
        self.assertIn('BL depth 2:', out.getvalue())
        self.assertNotIn('BL depth 3:', out.getvalue())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            main([str(blob.directory), '--strings', 'Target', 'missing'])
        self.assertIn('Absent from rodata.bin.', out.getvalue())
        self.assertEqual(out.getvalue().count('String at '), 2)
        self.assertIn('0x0000000000002007', out.getvalue())


if __name__ == '__main__':
    unittest.main()
