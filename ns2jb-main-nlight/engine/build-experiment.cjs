#!/usr/bin/env node
// Build side-channel experiment blobs for the RO exec rig.
// ABI: void exp(const u64 args[8], u64 out[8]); entry point is the blob base.
// Blobs are position independent and stack-only: writable globals are
// rejected because the code cave runs RX. `--test` builds an aarch64-linux
// test binary for qemu so experiment logic is validated before upload.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const {execFileSync} = require('node:child_process');
const {sections} = require('./build-payload.cjs');
const check = (ok, message) => {if (!ok) throw Error(message);};
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

// runuser/netns environments have a minimal PATH; resolve zig explicitly.
function zigBin() {
  for (const candidate of [process.env.ZIG, 'zig', path.join(os.homedir(), '.local/bin/zig')]) {
    if (!candidate) continue;
    try {execFileSync(candidate, ['version'], {stdio: 'ignore'}); return candidate;} catch {}
  }
  throw Error('zig 0.15.2 is required (install it or set ZIG=/path/to/zig)');
}

const CAVE_SIZE = 0x2000;

const wrapper = '.section .text.start,"ax",%progbits\n.global _start\n_start:\n    b exp\n';
const script = `ENTRY(_start)
SECTIONS {
    . = 0;
    .text : { KEEP(*(.text.start)) *(.text .text.*) }
    . = ALIGN(0x1000);
    .rodata : { *(.rodata .rodata.*) }
    . = ALIGN(0x1000);
    .data : { *(.data .data.*) }
    /DISCARD/ : { *(.comment .note* .eh_frame*) }
}`;

function buildBlob(source) {
  check(fs.existsSync(source), 'Experiment source not found: ' + source);
  const output = fs.mkdtempSync(path.join(os.tmpdir(), 'switch2-exp-'));
  try {
    const elfFile = path.join(output, 'exp.elf');
    fs.writeFileSync(path.join(output, 'wrapper.S'), wrapper);
    fs.writeFileSync(path.join(output, 'blob.ld'), script);
    execFileSync(zigBin(), ['build-exe', '-target', 'aarch64-freestanding-none', '-O', 'ReleaseSmall', '-fPIC',
      '-fno-stack-protector', '-fno-stack-check', '-fno-sanitize-c', '-fno-compiler-rt', '-fno-unwind-tables',
      '-flld', '--script', path.join(output, 'blob.ld'), '-fentry=_start',
      '-cflags', '-ffreestanding', '-fno-builtin', '--', source, path.join(output, 'wrapper.S'),
      '-femit-bin=' + elfFile], {stdio: 'inherit'});
    const rows = sections(fs.readFileSync(elfFile));
    const named = name => rows.filter(row => row.name === name && row.type === 1);
    const text = named('.text'), rodata = named('.rodata');
    check(text.length === 1 && text[0].size > 0, 'Experiment has no code');
    check(rodata.length <= 1, 'Unexpected rodata layout');
    for (const name of ['.data', '.data.cave', '.sdata', '.bss', '.sbss'])
      check(!rows.some(row => row.name === name && row.size > 0),
        'Experiment uses writable globals (' + name + '); stack and out[] only');
    const base = text[0].address;
    const size = Math.max(text[0].address + text[0].size,
      ...(rodata.length ? [rodata[0].address + rodata[0].size] : [0])) - base;
    check(size <= CAVE_SIZE, 'Experiment image exceeds the code cave: ' + size);
    const image = Buffer.alloc(size);
    for (const row of [...text, ...rodata]) row.bytes.copy(image, row.address - base);
    return image;
  } finally {
    fs.rmSync(output, {recursive: true, force: true});
  }
}

const testMain = `#include <stdio.h>
typedef unsigned long long u64;
extern void exp(const u64 *args, u64 *out);
int main(int argc, char **argv) {
    u64 args[8] = {0}, out[8] = {0};
    for (int i = 0; i + 1 < argc && i < 8; i++) sscanf(argv[i + 1], "%llu", &args[i]);
    exp(args, out);
    for (int i = 0; i < 8; i++) printf("out[%d] = %llu (0x%llx)\\n", i, out[i], out[i]);
    return 0;
}`;

function buildTest(source) {
  const output = fs.mkdtempSync(path.join(os.tmpdir(), 'switch2-exptest-'));
  try {
    const mainFile = path.join(output, 'test-main.c'), elfFile = path.join(output, 'test.elf');
    fs.writeFileSync(mainFile, testMain);
    execFileSync(zigBin(), ['cc', '-target', 'aarch64-linux-musl', '-O2', '-static',
      source, mainFile, '-o', elfFile], {stdio: 'inherit'});
    return elfFile;
  } catch (error) {
    fs.rmSync(output, {recursive: true, force: true});
    throw error;
  }
}

function fnv(bytes) {
  let hash = 0xcbf29ce484222325n;
  for (const byte of bytes) {hash ^= BigInt(byte); hash = BigInt.asUintN(64, hash * 0x100000001b3n);}
  return hash;
}

function main(args = process.argv.slice(2)) {
  const test = args[0] === '--test';
  const source = args[test ? 1 : 0];
  check(source, 'Usage: build-experiment.cjs [--test] <experiments/name.c> [args...]');
  if (test) {
    const elfFile = buildTest(source);
    const run = args.slice(2);
    const {spawnSync} = require('node:child_process');
    let qemu = {error: Error('qemu-aarch64 is not installed'), status: 1};
    for (const name of ['qemu-aarch64', 'qemu-aarch64-static']) {
      qemu = spawnSync(name, [elfFile, ...run], {stdio: 'inherit'});
      if (!qemu.error) break;
    }
    fs.rmSync(path.dirname(elfFile), {recursive: true, force: true});
    if (qemu.error) throw qemu.error;
    process.exitCode = qemu.status ?? 1;
    return;
  }
  const image = buildBlob(source);
  const out = path.join(path.dirname(source), 'build', path.basename(source, '.c') + '.bin');
  fs.mkdirSync(path.dirname(out), {recursive: true});
  fs.writeFileSync(out, image);
  console.log(JSON.stringify({source, out, bytes: image.length, sha256: hash(image),
    fnv64: '0x' + fnv(image).toString(16)}));
}

if (require.main === module) try {main();} catch (error) {console.error(error.message); process.exitCode = 1;}
module.exports = {buildBlob, CAVE_SIZE, fnv};
