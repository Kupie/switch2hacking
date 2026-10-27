#!/usr/bin/env node
// SCP/FalconOS µcode decryption test harness — 2026-10-27 (7.2ad/7.2ae)
//
// THE TARGET: the ~176KiB high-entropy blob in the banked fw23 tsec
// sysmodule (040000000000008d) at fw23/040000000000008d-tsec.autogen/data.bin
// offset 0x4000 (vaddr 0x31000), behind the "TSEC" header at data+0x3fe4
// {magic, 0x2d000, 0, 0x10000, 0}. Per external intel (leaked siggen code),
// the image is produced with a hardcoded raw key (not the sigenc variant).
//
// Given a candidate key, try the common cipher/mode combinations and score
// the plaintext for RISC-V µcode plausibility. ZERO switch contact — the
// ciphertext is banked offline.
//
// Usage:
//   node tools/scp/scp-decrypt-test.cjs <hexkey> [blobHexFile]
//   (key length selects AES-128/192/256: 32/48/64 hex chars)
//
// Scoring: (a) Shannon entropy of the first 16KiB (µcode ≈ 5.5-6.9, random
// ≈ 7.99); (b) RISC-V major-opcode validity rate on 16-bit instruction
// words (little-endian halfwords; compressed + 32-bit mixes expected);
// (c) printable ASCII run count (firmware strings).
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');

const DATA = path.join(__dirname, '..', '..', 'fw23', '040000000000008d-tsec.autogen', 'data.bin');
const BLOB_OFF = 0x4000, BLOB_END = 0x30000;

function entropy(buf) {
  const counts = new Array(256).fill(0);
  for (const b of buf) counts[b]++;
  let e = 0;
  for (const c of counts) if (c) { const p = c / buf.length; e -= p * Math.log2(p); }
  return e;
}

function score(name, plain) {
  const head = plain.subarray(0, 0x4000);
  const ent = entropy(head);
  // RISC-V opcode plausibility: 16-bit LE halfwords; compressed (q0 % 4 != 3)
  // or 32-bit (q0 % 4 == 3) major opcodes with smallish values.
  let valid = 0, total = 0;
  for (let i = 0; i + 2 <= head.length; i += 2) {
    const hw = head[i] | (head[i + 1] << 8);
    total++;
    const opc = hw & 0x3;
    if (opc === 3) valid += ((hw >> 13) <= 0x7 && (hw >> 2 & 0x1f) > 0) ? 1 : 0;
    else valid += ((hw >> 13) > 0) ? 1 : 0;
  }
  let asciiRuns = 0, run = 0;
  for (const b of head) {
    if (b >= 0x20 && b < 0x7f) { if (++run === 6) asciiRuns++; }
    else run = 0;
  }
  return {name, entropy: +ent.toFixed(3), rvValidity: +(100 * valid / total).toFixed(1), asciiRuns,
    verdict: ent < 7.2 ? 'CANDIDATE — inspect manually' : 'still random'};
}

function tryAes(key, mode, iv, blob) {
  const args = ['enc', `-aes-${key.bits}-${mode}`, '-K', key.hex, '-iv', iv, '-nopad', '-d'];
  try {
    return execFileSync('/usr/bin/openssl', args, {input: blob, maxBuffer: 64 << 20});
  } catch (e) { return null; }
}

function main() {
  const keyHex = (process.argv[2] || '').replace(/[^0-9a-fA-F]/g, '');
  if (![32, 48, 64].includes(keyHex.length))
    throw Error('pass a 32/48/64-hex-char AES key (128/192/256-bit)');
  const bits = keyHex.length * 4;
  const blobFile = process.argv[3];
  const blobFull = blobFile ? fs.readFileSync(blobFile)
    : fs.readFileSync(DATA).subarray(BLOB_OFF, BLOB_END);
  console.log(`blob: ${blobFull.length} bytes (from ${blobFile || 'tsec data.bin+0x4000'}); key: AES-${bits}`);
  const results = [];
  for (const mode of ['ctr', 'cbc', 'ecb']) {
    for (const iv of ['0'.repeat(32), '00000000000000000000000000000001']) {
      if (mode === 'ecb' && iv !== '0'.repeat(32)) continue;
      const out = tryAes({bits, hex: keyHex}, mode, iv, blobFull);
      if (!out) { results.push({name: `aes-${bits}-${mode}${mode === 'ecb' ? '' : ' iv=' + iv.slice(0, 8) + '…'}`, error: 'openssl failed'}); continue; }
      results.push(score(`aes-${bits}-${mode} iv=${iv.slice(0, 16)}…`, out));
    }
  }
  for (const r of results) {
    if (r.error) { console.log(`  ${r.name}: ${r.error}`); continue; }
    console.log(`  ${r.name}: entropy=${r.entropy} rvValidity=${r.rvValidity}% asciiRuns=${r.asciiRuns} => ${r.verdict}`);
  }
  console.log('note: also try the TSEC header fields as nonce {base 0x2d000, 0, 0x10000} if all above stay random.');
}
main();