#!/usr/bin/env python3
"""Find string references in little-endian, raw AArch64 section images.

Input directory: text.bin, rodata.bin, data.bin, meta.json. Metadata contains
text_addr, ro_addr, data_addr (integers or decimal/0x-prefixed strings).
Searches are UTF-8 byte substrings, including overlapping/repeated occurrences.

Usage examples:
    python3 xref.py mod-a '%s:/' '%s.nca' 'Contents'
    python3 xref.py mod-b --strings
    python3 xref.py mod-a --strings --min-length 4 '@Host' > report.txt
    python3 xref.py mod-a --depth 2 --max-function-insns 512 'registered'

ADRP and immediate ADD/LDR encodings are decoded by hand. The next eight
instructions are considered, stopping at register clobbers or control transfers.
ADD must use the ADRP register as its source (its destination may differ).
LDR supports unsigned-offset integer loads and true PC-relative literal loads;
both direct string-address loads and 64-bit pointer slots in rodata/data count.
No relocation processing, register-copy propagation, or general dataflow analysis
is performed. Embedded data in text can resemble instructions.

Hit windows include 40 instructions before ADRP (or literal LDR), the complete
pair, and 25 after it. BL targets are followed breadth-first to depth two by
default. Without symbols, function extents are heuristic: linear disassembly
stops at RET, BR, an unconditional B, an invalid word, or a configurable cap.
Consequently alternate basic blocks and indirect calls may be missed. Shared
callees are printed once per report, with subsequent references pointing to them.
Only the standard library and Capstone are required. Input files are read-only.
"""

import argparse
from collections import deque
from dataclasses import dataclass
import json
from pathlib import Path
import re
import struct
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_GRP_INT

MASK64 = (1 << 64) - 1


def signed(value, bits):
    """Sign-extend a bits-wide integer."""
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def decode_adrp(word, pc):
    if word & 0x9F000000 != 0x90000000:
        return None
    imm21 = ((word >> 5) & 0x7FFFF) << 2 | ((word >> 29) & 3)
    return word & 31, ((pc & ~0xFFF) + (signed(imm21, 21) << 12)) & MASK64


def decode_bl(word, pc):
    if word & 0xFC000000 == 0x94000000:
        return (pc + (signed(word & 0x3FFFFFF, 26) << 2)) & MASK64
    return None


@dataclass(frozen=True)
class Hit:
    start: int
    end: int
    target: int
    kind: str
    slot: int = None


class Blob:
    def __init__(self, directory):
        self.directory = Path(directory)
        meta = json.loads((self.directory / 'meta.json').read_text())
        if not isinstance(meta, dict):
            raise ValueError('meta.json must contain an object')
        self.sections = {}
        for name, field in [('text', 'text_addr'), ('rodata', 'ro_addr'),
                            ('data', 'data_addr')]:
            value = meta[field]
            base = int(value, 0) if isinstance(value, str) else value
            if type(base) is not int or not 0 <= base <= MASK64:
                raise ValueError(f'{field} must be an unsigned 64-bit address')
            contents = (self.directory / (name + '.bin')).read_bytes()
            if base + len(contents) > 1 << 64:
                raise ValueError(f'{name} extends past the address space')
            self.sections[name] = (base, contents)
        self.base, self.text = self.sections['text']
        if self.base % 4 or len(self.text) % 4:
            raise ValueError('text base and size must be multiples of four')
        spans = sorted((base, base + len(data), name)
                       for name, (base, data) in self.sections.items() if data)
        for left, right in zip(spans, spans[1:]):
            if left[1] > right[0]:
                raise ValueError(f'overlapping sections: {left[2]} and {right[2]}')
        self.words = tuple(w[0] for w in struct.iter_unpack('<I', self.text))
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.md.detail = True

    def insn(self, index):
        return next(self.md.disasm(self.text[index * 4:index * 4 + 4],
                                   self.base + index * 4, count=1), None)

    def memory(self, address, size):
        for name in ('rodata', 'data'):
            base, data = self.sections[name]
            offset = address - base
            if 0 <= offset and offset + size <= len(data):
                return data[offset:offset + size]
        return None

    def load_hits(self, start, end, address, size, targets, kind):
        raw = self.memory(address, size)
        if raw is None:
            return []
        hits = []
        if address in targets:
            hits.append(Hit(start, end, address, kind + ' direct', address))
        if size == 8 and int.from_bytes(raw, 'little') in targets:
            hits.append(Hit(start, end, int.from_bytes(raw, 'little'),
                            kind + ' pointer', address))
        return hits

    def scan(self, targets):
        """Return hits keyed by searched virtual address; scan text just once."""
        found = {target: [] for target in targets}
        if not targets:
            return found
        for i, word in enumerate(self.words):
            pc = self.base + i * 4
            hits = []
            # Integer LDR Wt/Xt literal (not SIMD, LDRSW, or PRFM).
            if word & 0xBF000000 == 0x18000000:
                address = (pc + (signed((word >> 5) & 0x7FFFF, 19) << 2)) & MASK64
                hits += self.load_hits(i, i, address, 8 if word >> 30 else 4,
                                       targets, 'LDR literal')
            adrp = decode_adrp(word, pc)
            if adrp is not None and adrp[0] != 31:
                reg, page = adrp
                for j in range(i + 1, min(i + 9, len(self.words))):
                    other = self.words[j]
                    rn = (other >> 5) & 31
                    # 64-bit ADD immediate, without flag updates.
                    if other & 0xFF800000 == 0x91000000 and rn == reg:
                        immediate = (other >> 10) & 0xFFF
                        address = (page + (immediate << (12 if other & (1 << 22) else 0))) & MASK64
                        if address in targets and other & 31 != 31:
                            hits.append(Hit(i, j, address, 'ADRP+ADD'))
                    # Unsigned immediate LDR B/H/W/X (zero-extending integer).
                    if other & 0x3FC00000 == 0x39400000 and rn == reg:
                        size = 1 << (other >> 30)
                        address = (page + (((other >> 10) & 0xFFF) * size)) & MASK64
                        hits += self.load_hits(i, j, address, size, targets, 'ADRP+LDR')
                    insn = self.insn(j)
                    if insn is None or any(insn.group(g) for g in
                                           (CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_GRP_INT)):
                        break
                    _, writes = insn.regs_access()
                    names = {insn.reg_name(r) for r in writes}
                    aliases = {f'x{reg}', f'w{reg}'}
                    if reg == 29:
                        aliases.add('fp')
                    if reg == 30:
                        aliases.add('lr')
                    if names & aliases:
                        break
            for hit in hits:
                found[hit.target].append(hit)
        return found

    def print_region(self, start, stop, marks=()):
        calls = []
        for i in range(start, stop):
            pc = self.base + 4 * i
            insn = self.insn(i)
            assembly = f'{insn.mnemonic:<9} {insn.op_str}' if insn else f'.word     0x{self.words[i]:08x}'
            print(f'{">>" if i in marks else "  "} 0x{pc:016x}: {self.words[i]:08x}  {assembly}')
            target = decode_bl(self.words[i], pc)
            if target is not None:
                calls.append((pc, target))
        return calls

    def follow_calls(self, calls, depth, cap, shown):
        queue = deque((source, target, 1) for source, target in calls)
        while queue:
            source, target, level = queue.popleft()
            if level > depth:
                continue
            print(f'\n  BL depth {level}: 0x{source:016x} -> 0x{target:016x}')
            offset = target - self.base
            if offset < 0 or offset >= len(self.text) or offset % 4:
                print('  Target outside text or unaligned; unavailable.')
                continue
            if target in shown:
                print('  Already disassembled above.')
                # Revisit descendants if this path gives a greater remaining depth.
                previous_level, nested = shown[target]
                if level < previous_level:
                    shown[target] = (level, nested)
                    queue.extend((src, dst, level + 1) for src, dst in nested)
                continue
            start = offset // 4
            stop = min(start + cap, len(self.words))
            reason = 'instruction cap' if start + cap < len(self.words) else 'end of text'
            for i in range(start, stop):
                insn = self.insn(i)
                if insn is None or insn.group(CS_GRP_RET) or insn.mnemonic in ('b', 'br', 'braa', 'brab', 'braaz', 'brabz'):
                    stop = i + 1
                    reason = 'invalid word' if insn is None else insn.mnemonic
                    break
            nested = self.print_region(start, stop)
            print(f'  End of heuristic function region: {reason}.')
            shown[target] = (level, nested)
            queue.extend((src, dst, level + 1) for src, dst in nested)


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError('must be at least 1')
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('directory', type=Path)
    parser.add_argument('search', nargs='*', help='UTF-8 substrings to locate')
    parser.add_argument('--strings', action='store_true', help='dump printable ASCII runs in rodata')
    parser.add_argument('--min-length', type=positive, default=1, help='minimum printable run length (default: 1)')
    parser.add_argument('--depth', type=int, default=2, choices=range(0, 11), help='BL traversal depth (default: 2; 0 disables)')
    parser.add_argument('--max-function-insns', type=positive, default=256, help='heuristic function instruction cap (default: 256)')
    args = parser.parse_intermixed_args(argv)
    if not args.search and not args.strings:
        parser.error('supply search strings or --strings')
    if any(not s for s in args.search):
        parser.error('search strings must not be empty')
    try:
        blob = Blob(args.directory)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.error(str(error))
    print(f'Input: {args.directory} (resolved: {args.directory.resolve()})')
    for name, (base, data) in blob.sections.items():
        print(f'{name}: vaddr=0x{base:016x}, size=0x{len(data):x}')
    print(f'Pair lookahead: 8; hit context: 40 before / 25 after; BL depth: {args.depth}')
    print(f'Function boundaries are heuristic; cap={args.max_function_insns} instructions.')
    ro_base, rodata = blob.sections['rodata']
    if args.strings:
        print('\nPrintable ASCII strings:')
        for match in re.finditer(rb'[\x20-\x7e]+', rodata):
            if len(match[0]) >= args.min_length:
                print(f'0x{ro_base + match.start():016x}: {match[0].decode("ascii")!r}')
    occurrences = {}
    for query in dict.fromkeys(args.search):
        needle = query.encode('utf-8')
        offsets = []
        offset = rodata.find(needle)
        while offset != -1:
            offsets.append(ro_base + offset)
            offset = rodata.find(needle, offset + 1)
        occurrences[query] = offsets
    hits = blob.scan({address for addresses in occurrences.values() for address in addresses})
    shown = {}
    for query, addresses in occurrences.items():
        print(f'\n=== Search {query!r} ===')
        if not addresses:
            print('Absent from rodata.bin.')
        for address in addresses:
            print(f'\nString at 0x{address:016x} (rodata+0x{address - ro_base:x}): {len(hits[address])} reference(s)')
            if not hits[address]:
                print('No supported references found.')
            for hit in hits[address]:
                print(f'\n{hit.kind}: 0x{blob.base + hit.start * 4:016x} -> 0x{blob.base + hit.end * 4:016x}')
                if hit.slot is not None:
                    print(f'Load address: 0x{hit.slot:016x}')
                calls = blob.print_region(max(0, hit.start - 40), min(len(blob.words), hit.end + 26), (hit.start, hit.end))
                blob.follow_calls(calls, args.depth, args.max_function_insns, shown)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
