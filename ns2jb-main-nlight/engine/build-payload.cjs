#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const {execFileSync} = require('node:child_process');
const check = (ok, message) => {if (!ok) throw Error(message);};
const hash = bytes => crypto.createHash('sha256').update(bytes).digest();

function sections(elf) {
  check(elf.length >= 64 && elf.subarray(0, 6).equals(Buffer.from([127, 69, 76, 70, 2, 1])) &&
    elf.readUInt16LE(18) === 183 && elf.readBigUInt64LE(24) === 0n, 'Expected an AArch64 ELF with entry point zero');
  const integer = at => {
    const value = elf.readBigUInt64LE(at);
    check(value <= BigInt(Number.MAX_SAFE_INTEGER), 'ELF integer exceeds host precision');
    return Number(value);
  };
  const start = integer(40), stride = elf.readUInt16LE(58), count = elf.readUInt16LE(60);
  check(stride === 64 && count > 0 && start + count * stride <= elf.length, 'Invalid ELF section table');
  const rows = Array.from({length: count}, (_, i) => {
    const at = start + i * stride;
    const row = {nameOffset: elf.readUInt32LE(at), type: elf.readUInt32LE(at + 4),
      address: integer(at + 16), offset: integer(at + 24), size: integer(at + 32)};
    check(row.type === 8 || row.offset + row.size <= elf.length, 'ELF section exceeds the file');
    check(![4, 9].includes(row.type) || !row.size, 'The payload contains unresolved relocations');
    return row;
  });
  const strings = rows[elf.readUInt16LE(62)];
  check(strings?.type === 3, 'ELF section names are missing');
  const names = elf.subarray(strings.offset, strings.offset + strings.size);
  for (const row of rows) {
    const end = names.indexOf(0, row.nameOffset);
    check(row.nameOffset < names.length && end >= row.nameOffset, 'Invalid ELF section name');
    row.name = names.toString('utf8', row.nameOffset, end);
    row.bytes = elf.subarray(row.offset, row.offset + row.size);
  }
  return rows;
}

function packageNso(elf) {
  const rows = sections(elf);
  const segments = ['.text', '.rodata', '.data'].map(name => {
    const matches = rows.filter(row => row.name === name);
    check(matches.length === 1 && matches[0].type === 1 && matches[0].size > 0, 'Missing payload section: ' + name);
    return matches[0];
  });
  segments.forEach((row, i) => check(row.address % 4096 === 0 &&
    (i === 2 || row.address + row.size <= segments[i + 1].address), 'Payload sections overlap or are unaligned'));
  const header = Buffer.alloc(0x100), name = Buffer.alloc(16);
  header.write('NSO0'); name.write('main');
  header.writeUInt32LE(0x78, 0x0c);
  header.writeUInt32LE(0x100, 0x1c); header.writeUInt32LE(4, 0x2c);
  header.writeUInt32LE(rows.find(row => row.name === '.bss')?.size || 0, 0x3c);
  hash(Buffer.concat(segments.map(row => row.bytes))).copy(header, 0x40);
  let offset = 0x110;
  segments.forEach((row, i) => {
    header.writeUInt32LE(offset, 0x10 + i * 0x10);
    header.writeUInt32LE(row.address, 0x14 + i * 0x10);
    header.writeUInt32LE(row.size, 0x18 + i * 0x10);
    header.writeUInt32LE(row.size, 0x60 + i * 4);
    hash(row.bytes).copy(header, 0xa0 + i * 0x20);
    offset += row.size;
  });
  return Buffer.concat([header, name, ...segments.map(row => row.bytes)]);
}

function main(args = process.argv.slice(2)) {
  let zig = 'zig', verify = false;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--check') verify = true;
    else if (args[i] === '--zig' && args[i + 1]) zig = args[++i];
    else throw Error('Unknown build argument: ' + args[i]);
  }
  check(execFileSync(zig, ['version'], {encoding: 'utf8'}).trim() === '0.15.2', 'Reproducible builds require Zig 0.15.2');
  const directory = path.join(__dirname, 'switch2/ro/payload');
  const output = fs.mkdtempSync(path.join(os.tmpdir(), 'switch2-payload-'));
  try {
  const build = (elfFile, sources) => execFileSync(zig, ['build-exe', '-target', 'aarch64-freestanding-none', '-O', 'ReleaseSmall', '-fPIC',
    '-fno-stack-protector', '-fno-stack-check', '-fno-sanitize-c', '-fno-compiler-rt', '-fno-unwind-tables',
    '-flld', '--script', path.join(directory, 'layout.ld'), '-fentry=_start',
    '-cflags', '-ffreestanding', '-fno-builtin', '--', ...sources.map(name => path.join(directory, name)),
    '-femit-bin=' + elfFile], {stdio: 'inherit'});
  const elfFile = path.join(output, 'payload.elf');
  build(elfFile, ['main.c', 'process.c', 'start.S']);
  const image = packageNso(fs.readFileSync(elfFile));
  const mainFile = path.join(directory, 'main'), manifestFile = path.join(directory, 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestFile));
  if (verify) check(image.equals(fs.readFileSync(mainFile)), 'Rebuilt payload differs from the shipped image');
  else {
    // Payload images survive application restarts in the donor temporary
    // volume; donor-prepare replaces them only on exact hash match against
    // this history, so keep old identities recorded here.
    const previous = manifest.payloadSha256;
    if (previous && previous !== hash(image).toString('hex'))
      manifest.previousPayloads = [previous, ...(manifest.previousPayloads || [])
        .filter(item => item !== previous)].slice(0, 8);
    fs.writeFileSync(mainFile, image);
    Object.assign(manifest, {payloadBytes: image.length, payloadSha256: hash(image).toString('hex')});
    fs.writeFileSync(manifestFile, JSON.stringify(manifest, null, 2) + '\n');
  }
  // 2026-10-26: the launch's staging ceiling. 20737 bytes passed stage 3
  // live; 20933 failed (the helper launch died after a full acquisition —
  // the '115k ops then death' failure). Guard with margin.
  check(image.length <= 20800, 'The payload (' + image.length +
    ' bytes) exceeds the ~20.8 KB launch ceiling — strip dead rig subs or split the feature.');
  console.log(JSON.stringify({bytes: image.length, sha256: hash(image).toString('hex'), matched: verify}));
  // Second target: the creport-policy debug executor (pure IPC client;
  // donor-prepare stages it as `main` for title 0x0400000000000036).
  // Its sha256 is pinned in manifest.policies["0400000000000036"].payload
  // so the donor verification accepts it exactly like the monitor.
  if (fs.existsSync(path.join(directory, 'executor.c'))) {
    const execElf = path.join(output, 'executor.elf');
    build(execElf, ['executor.c', 'executor-entry.S']);
    const execImage = packageNso(fs.readFileSync(execElf));
    const execFile = path.join(directory, 'executor');
    const policyTitle = '0400000000000036';
    const policies = manifest.policies ||= {};
    const entry = typeof policies[policyTitle] === 'object' && policies[policyTitle] ? policies[policyTitle]
      : (policies[policyTitle] = {npdm: policies[policyTitle] || ''});
    if (verify) check(execImage.equals(fs.readFileSync(execFile)), 'Rebuilt executor differs from the shipped image');
    else {
      fs.writeFileSync(execFile, execImage);
      Object.assign(entry, {payload: hash(execImage).toString('hex'), payloadBytes: execImage.length});
    }
    console.log(JSON.stringify({executorBytes: execImage.length,
      executorSha256: hash(execImage).toString('hex'), policyTitle, matched: verify}));
  }
  if (!verify) fs.writeFileSync(manifestFile, JSON.stringify(manifest, null, 2) + '\n');
  } finally {fs.rmSync(output, {recursive: true, force: true});}
}

module.exports = {sections, packageNso};
if (require.main === module) try {main();} catch (error) {console.error(error.message); process.exitCode = 1;}
