#!/usr/bin/env node
// Exhaustive static-key test: every 4-aligned 16/32B window of the driver-stack
// modules (data+rodata, excluding the blob itself) as an AES-128/256 key against
// the banked tsec blob. Modes: ECB, CBC(iv=0), CTR(nonce=0). Score = entropy of
// the first 4KiB of plaintext (µcode ≈ 5.5-6.9; ciphertext ≈ 7.99; text < 6.5).
// A static key ANYWHERE in these binaries WILL show up here.
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const FW = path.join(__dirname, '..', '..', 'fw23');
const BLOB = fs.readFileSync(path.join(FW, '040000000000008d-tsec.autogen', 'data.bin'))
  .subarray(0x4000, 0x30000);
const TEST = BLOB.subarray(0, 0x1000);

function entropy(buf) {
  const counts = new Array(256).fill(0);
  for (const b of buf) counts[b]++;
  let e = 0;
  for (const c of counts) if (c) { const p = c / buf.length; e -= p * Math.log2(p); }
  return e;
}

const MODES = [
  ['aes-%d-ecb', (algo, key) => crypto.createDecipheriv(algo, key, null)],
  ['aes-%d-cbc', (algo, key) => crypto.createDecipheriv(algo, key, Buffer.alloc(16))],
  ['aes-%d-ctr', (algo, key) => crypto.createDecipheriv(algo, key, Buffer.alloc(16))],
];

const MODULES = [
  ['0400000000000023-am', ['rodata.bin', 'data.bin']],
  ['0400000000000063-vi2', ['rodata.bin', 'data.bin']],
  ['0400000000000019-nvservices', ['rodata.bin', 'data.bin']],
  ['040000000000004f-nvkernel', ['rodata.bin', 'data.bin']],
  ['040000000000008d-tsec.autogen', ['rodata.bin', 'data.bin']],
];

let tested = 0;
const findings = [];
for (const [mod, segs] of MODULES) {
  for (const seg of segs) {
    const file = path.join(FW, mod, seg);
    if (!fs.existsSync(file)) continue;
    const b = fs.readFileSync(file);
    const isTsecData = mod.includes('tsec') && seg === 'data.bin';
    const lo = 0, hi = isTsecData ? 0x4000 : b.length; // skip the blob itself
    for (const bits of [128, 256]) {
      const klen = bits / 8;
      const algo = `aes-${bits}-cbc`;
      for (let o = lo; o + klen <= hi; o += 4) {
        const key = b.subarray(o, o + klen);
        let best = null;
        for (const mode of ['ecb', 'cbc', 'ctr']) {
          const a = `aes-${bits}-${mode}`;
          try {
            const iv = mode === 'ecb' ? null : Buffer.alloc(16);
            const d = crypto.createDecipheriv(a, key, iv);
            const pt = Buffer.concat([d.update(TEST.subarray(0, 256)), d.final()]);
            const e = entropy(pt);
            if (!best || e < best.e) best = {e, mode, pt};
          } catch (_) {}
          tested++;
        }
        if (best && best.e < 6.25) { // random 256B scores ~7.0-7.6; structure < 6.2
          findings.push({mod, seg, off: o, bits, mode: best.mode, entropy: +best.e.toFixed(2),
            key: key.toString('hex'), pt0: best.pt.subarray(0, 32).toString('hex')});
          console.log('HIT', JSON.stringify(findings.at(-1)));
        }
      }
    }
  }
  console.error(`done ${mod}`);
}
console.log(`tested: ${tested} decrypt ops`);
console.log(`findings: ${findings.length}`);