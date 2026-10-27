#!/usr/bin/env node
// SYSTEM PROGRAM ROMFS DUMP — fs 206 (OpenDataStorageByPath) type 1 on the
// title's own @SystemContent NCA.
//
// Route map (2026-10-26, GeodhE boot):
//   - fs cmd 10 CANNOT open Program content: every fsType 0..16 x scheme
//     (@SystemContent[0|3], @UserContent) refuses 0x2ee002/0x2ee202 (the
//     WithId DATA reader is all it ever builds — reader kind mismatch).
//   - fs 206 type 1 = the program-RomFS route (game-proven). BARE it hits
//     the rights gate 0x7d202. The licensed-prelude route (es 503 dance +
//     lr patch + CodeFS + context + domain spoof) needs ldr:ro cmd 0 —
//     which only grants in the HOT WINDOW after acquisition and is
//     POISONED for the rest of the boot by ANY fix-session-identity --pid
//     promotion (FINDINGS.md V5iho9: 0x320002 for everything afterwards).
//     NEVER promote on the dump boot — run this bare probe FIRST.
//   - pm:dmnt pid sweep works from the RPC session (sm fallback).
//
// Clean-stop: SIGINT finishes the current file and closes handles. Never
// SIGKILL mid-RPC (kills the carrier).
//
// Usage: node tools/dump/sysprogram-romfs-dump.cjs <16-hex tid> [--types t1,t2]
'use strict';
const fsSync = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const latest = JSON.parse(fsSync.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json')));
const engine = path.join(latest.directory, 'switch2');
const {Session, u32, u64, check} = require(path.join(engine, 'app', 'session.cjs'));
const domain = require(path.join(engine, 'app', 'domain.cjs'));
const filesystem = require(path.join(engine, 'app', 'filesystem.cjs'));
const {paths} = require(path.join(engine, 'memory', 'paths.cjs'));

const NCA_STRUCTURE = path.join(require('node:os').homedir(), 'dev/switch/dumps/fw23/nca-structure.json');
const OUTROOT = process.env.OUTROOT ||
  path.join(require('node:os').homedir(), 'dev/switch/dumps/fw23-program-romfs');
const CHUNK = 0x40000;               // probe-safe 256 KiB

const success = (r, l) => {if (r.result) throw Error(l + ': 0x' + (Number(r.result) >>> 0).toString(16)); return r;};
const canonical = v => '0x' + (Number(v) & 0x3fffff).toString(16);
const pad16 = v => v.toString(16).padStart(16, '0');

let stopping = false;
const stopSignals = () => {if (stopping) return; stopping = true;
  console.log('stop requested — finishing current file and closing cleanly...');};
process.on('SIGINT', stopSignals);
process.on('SIGTERM', stopSignals);
const STOP = Symbol('clean-stop');

(async () => {
  const argv = process.argv.slice(2);
  const tidRaw = argv.find(x => /^[0-9a-fA-F]{16}$/.test(x));
  check(tidRaw, 'usage: sysprogram-romfs-dump.cjs <16-hex tid>');
  const TID = tidRaw.toLowerCase();
  const types = (argv.find(x => x.startsWith('--types'))?.split('=')[1] || '1,4,5,3,6').split(',').map(Number);

  const ncm = JSON.parse(await fsp.readFile(NCA_STRUCTURE));
  const entry = ncm.titles.find(t => t.title === TID);
  check(entry, 'tid not in nca-structure.json');
  const program = entry.contents.Program;
  check(program, 'no Program content for ' + TID);
  const CID = program.contentId, ATTR = program.attributes;
  console.log('target:', TID, '| Program NCA', CID, '| attr', ATTR);

  // ---- session (NO identity promotion — see header) ----
  const s = new Session('sysromfs-' + Date.now(), 0x2100000);
  s.record = async () => {};
  await s.initialize();
  s.bulkDownloads = true;
  const handles = [];
  const track = h => {handles.push(h); return h;};
  try {
    // ---- 206 type sweep on @SystemContent (MUST be the first IPC on the
    // fresh boot — the acquisition hot window may be the only grant
    // source; open NOTHING else before it) ----
    const proof = JSON.parse(await fsp.readFile(path.join(engine, 'ro', 'root', 'current-root.json')));
    const root = track(domain.oneHandle(success(await domain.send(s, 'clone root', proof.rootHandle,
      domain.wire.control(2)), 'clone root')));
    const pathApi = paths(s, domain);
    const contentPath = '@SystemContent://registered/' + CID + '.nca';
    let storage = null, usedType = null;
    for (const type of types) {
      if (stopping) break;
      const pb = Buffer.alloc(0x301);
      pb.write(contentPath);
      const input = Buffer.alloc(8);
      input[0] = ATTR;
      input.writeUInt32LE(type, 4);
      const reply = await pathApi.raw(root, 206, pb, input);
      if (reply.result) {console.log('== 206 type', type, '== REFUSED', canonical(reply.result)); continue;}
      console.log('== 206 type', type, '== OPENED (IStorage)');
      storage = track(domain.oneHandle(reply)); usedType = type;
      break;
    }
    check(storage, 'no 206 type opened ' + TID + ' RomFS');

    // informational pid sweep (AFTER the 206 attempt — never before)
    try {
      const pmDmnt = await s.openService('pm:dmnt');
      const suffix = TID.slice(-8);
      for (let pid = 1; pid <= 260; pid++) {
        const input = Buffer.alloc(16);
        input.writeBigUInt64LE(BigInt(pid), 0);
        input.writeBigUInt64LE(BigInt(pid), 8);
        const reply = await s.ipc('GetProcessInfo', pmDmnt, 7, input).catch(() => null);
        if (!reply || reply.result) continue;
        const data = Buffer.from(reply.data, 'hex');
        const programId = data.readBigUInt64LE(0) || data.readBigUInt64LE(8) || 0n;
        if (!programId) continue;
        const pid16 = pad16(programId);
        if (pid16.endsWith(suffix)) console.log('target process pid:', pid, '(' + pid16 + ')');
      }
      await s.close(pmDmnt).catch(() => {});
    } catch (e) {console.log('(pid sweep skipped:', e.message.slice(0, 60) + ')');}

    const size = Number(await domain.storageSize(s, storage));
    console.log('storage size:', size, '(' + (size / 1024 / 1024).toFixed(1) + ' MiB)');

    // ---- RomFS level-3 walk (same invariants as game-dump) ----
    const header = await filesystem.readStorage(s, storage, 0, 0x50);
    const h = Array.from({length: 10}, (_, i) => header.readBigUInt64LE(i * 8));
    check(h[0] === 0x50n, 'unexpected RomFS header size: 0x' + h[0].toString(16));
    const sizeN = BigInt(size);
    for (let i = 1; i < 9; i += 2) check(h[i] + h[i + 1] <= sizeN, 'RomFS section ' + i + ' exceeds storage');
    check(h[9] <= sizeN, 'RomFS data offset exceeds storage');
    console.log('romfs header ok | data offset', Number(h[9]));

    const readTable = async (offset, len) => {
      check(Number.isSafeInteger(offset) && len >= 0 && offset + len <= size, 'table range');
      const parts = [];
      for (let at = 0; at < len; at += 0x10000) {
        const take = Math.min(0x10000, len - at);
        parts.push(await filesystem.readStorage(s, storage, offset + at, take));
      }
      return Buffer.concat(parts);
    };
    const dirs = await readTable(Number(h[3]), Number(h[4]));
    const files = await readTable(Number(h[7]), Number(h[8]));

    const NONE = 0xffffffff, tree = [], stack = [{offset: 0, dirPath: '', parent: 0}];
    const seenDirs = new Set([0]), seenFiles = new Set();
    while (stack.length) {
      const dir = stack.pop();
      const d = dirs.subarray(dir.offset, dir.offset + 24);
      check(dir.offset === 0 || d.readUInt32LE(0) === dir.parent, 'directory parent mismatch');
      let at = d.readUInt32LE(8);
      while (at !== NONE) {
        check(!seenDirs.has(at), 'directory cycle'); seenDirs.add(at);
        const e = dirs.subarray(at, at + 24);
        const len = e.readUInt32LE(20);
        check(len <= 0x300 && at + 24 + len <= dirs.length, 'directory entry bounds');
        const name = dirs.subarray(at + 24, at + 24 + len).toString('utf8');
        check(name && !/[\\/]/.test(name) && name !== '.' && name !== '..', 'directory name');
        const dirPath = dir.dirPath + '/' + name;
        tree.push({path: dirPath, type: 'directory'});
        stack.push({offset: at, dirPath, parent: dir.offset});
        at = e.readUInt32LE(4);
      }
      at = d.readUInt32LE(12);
      while (at !== NONE) {
        check(!seenFiles.has(at), 'file cycle'); seenFiles.add(at);
        const e = files.subarray(at, at + 32);
        check(e.readUInt32LE(0) === dir.offset, 'file parent mismatch');
        const len = e.readUInt32LE(28);
        check(len <= 0x300 && at + 32 + len <= files.length, 'file entry bounds');
        const name = files.subarray(at + 32, at + 32 + len).toString('utf8');
        check(name && !/[\\/]/.test(name) && name !== '.' && name !== '..', 'file name');
        tree.push({path: dir.dirPath + '/' + name, type: 'file',
          offset: Number(e.readBigUInt64LE(8)), size: Number(e.readBigUInt64LE(16))});
        at = e.readUInt32LE(4);
      }
    }
    const totalFiles = tree.filter(x => x.type === 'file');
    console.log('romfs tree:', tree.filter(x => x.type === 'directory').length, 'dirs /',
      totalFiles.length, 'files | total data', totalFiles.reduce((a, b) => a + b.size, 0), 'bytes');

    // ---- dump with manifest checkpoints (resume-safe) ----
    const outDir = path.join(OUTROOT, TID);
    const manifestPath = path.join(outDir, 'manifest.json');
    let manifest;
    try {manifest = JSON.parse(await fsp.readFile(manifestPath));} catch {}
    manifest = manifest || {title: TID, contentId: CID, attributes: ATTR,
      via: 'fs 206 OpenDataStorageByPath type ' + usedType + ' @SystemContent, pid-promoted identity',
      started: new Date().toISOString(), files: []};
    const done = new Map(manifest.files.map(f => [f.path, f]));
    const dataOffset = Number(h[9]);
    const ranges = [[Number(h[1]), Number(h[1]) + Number(h[2])], [Number(h[3]), Number(h[3]) + Number(h[4])],
      [Number(h[5]), Number(h[5]) + Number(h[6])], [Number(h[7]), Number(h[7]) + Number(h[8])]];
    const flush = async () => {await fsp.mkdir(outDir, {recursive: true});
      await fsp.writeFile(manifestPath, JSON.stringify(manifest, null, 2));};
    let n = 0, bytesDone = 0;
    const t0 = Date.now();
    const dirsMade = new Set();
    for (const entry of totalFiles) {
      if (stopping) break;
      const prior = done.get(entry.path);
      if (prior && prior.size === entry.size && prior.sha256) {n++; continue;}
      const extentStart = dataOffset + entry.offset;
      check(extentStart + entry.size <= size, 'file extent exceeds storage: ' + entry.path);
      check(!entry.size || ranges.every(([start, end]) =>
        extentStart + entry.size <= start || extentStart >= end), 'extent overlaps metadata: ' + entry.path);
      const file = path.join(outDir, 'romfs', entry.path);
      if (!dirsMade.has(path.dirname(file))) {await fsp.mkdir(path.dirname(file), {recursive: true});
        dirsMade.add(path.dirname(file));}
      const hash = crypto.createHash('sha256');
      const out = await fsp.open(file, 'w');
      try {
        for (let at = 0; at < entry.size; at += CHUNK) {
          if (stopping) break;
          const take = Math.min(CHUNK, entry.size - at);
          const chunk = await filesystem.readStorage(s, storage, extentStart + at, take);
          hash.update(chunk);
          await out.write(chunk, 0, take, at);
        }
      } finally {await out.close();}
      if (stopping) break;
      const sha = hash.digest('hex');
      manifest.files = manifest.files.filter(f => f.path !== entry.path);
      manifest.files.push({path: entry.path, size: entry.size, sha256: sha});
      done.set(entry.path, {size: entry.size, sha256: sha});
      bytesDone += entry.size; n++;
      if (n % 10 === 0) {
        await flush();
        const rate = bytesDone / Math.max(1, (Date.now() - t0) / 1000);
        console.log('  romfs:', n, '/', totalFiles.length, 'files,',
          (bytesDone / 1024 / 1024).toFixed(1), 'MiB,', (rate / 1024).toFixed(0), 'KiB/s');
      }
    }
    if (!stopping) {
      manifest.completed = new Date().toISOString();
      await flush();
      console.log('ROMFS DONE:', n, 'files,', (bytesDone / 1024 / 1024).toFixed(1), 'MiB ->', outDir);
    } else console.log('STOPPED at', n, 'files — re-run to resume');
  } finally {
    for (const h of [...handles].reverse()) await s.close(h).catch(() => {});
    await s.cleanup().catch(() => {});
  }
})().catch(e => {console.error('FAILED:', e.stack || e.message); process.exitCode = 1;});