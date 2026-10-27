#!/usr/bin/env node
// SYSMODULE ROMFS OVERLAY DUMP — fs cmd 2 (OpenDataFileSystemByCurrentProcess)
// on the target sysmodule's promoted pid: the console ALREADY mounts every
// sysmodule's RomFS at its boot; cmd 2 hands back that mounted IFileSystem.
// No fs 206/10 path-rights check can block this — the mount exists.
//
// Route map (2026-10-26): the GPU microcode (fecs/gpccs/gpmu/acr/gsp) rides
// the nvservices Program-NCA RomFS. fs cmd 10 builds data readers only
// (kind gate 0x2ee002); fs 206 type-1 hits 0x7d202 bare and 0x320002 under
// every registered context (game/ns/nvservices — temporary contexts cannot
// open @SystemContent through 206). The OVERLAY route (proven on games for
// the active-composed view) bypasses both: promote the root identity to the
// sysmodule pid, fs cmd 2 -> mounted RomFS IFileSystem, walk + read via the
// memory controller (root-list-romfs / root-read-romfs-file).
//
// Cost: the promote poisons the boot's ldr:ro compose (FINDINGS.md V5iho9) —
// do NOT run loader/CodeFS routes after this on the same boot. The tool
// restores the helper pid (oracle-verified) at exit.
//
// Clean-stop: SIGINT finishes the current file. Never SIGKILL mid-RPC.
//
// Usage: node tools/dump/sysmodule-romfs-overlay.cjs <16-hex tid>
'use strict';
const fsSync = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const {execFile} = require('node:child_process');
const latest = JSON.parse(fsSync.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json')));
const engine = path.join(latest.directory, 'switch2');
const {Session, check} = require(path.join(engine, 'app', 'session.cjs'));
const fsMemory = require(path.join(engine, 'tools', 'fs-memory.cjs'));

const OUTROOT = process.env.OUTROOT ||
  path.join(require('node:os').homedir(), 'dev/switch/dumps/fw23-program-romfs');
const READ_CHUNK = 0x40000;             // root-read-romfs-file cap
const READ_HEX_LIMIT = 0x40000;

const identityTool = path.join(__dirname, '..', 'memory', 'fix-session-identity.cjs');
const promote = pid => new Promise(resolve =>
  execFile('node', [identityTool, '--pid', String(pid), '--force'],
    {cwd: path.join(__dirname, '..', '..')}, error => resolve(error)));
const pad16 = v => v.toString(16).padStart(16, '0');

let stopping = false;
const stopSignals = () => {if (stopping) return; stopping = true;
  console.log('stop requested — finishing current file and closing cleanly...');};
process.on('SIGINT', stopSignals);
process.on('SIGTERM', stopSignals);

(async () => {
  const argv = process.argv.slice(2);
  const tidRaw = argv.find(x => /^[0-9a-fA-F]{16}$/.test(x));
  check(tidRaw, 'usage: sysmodule-romfs-overlay.cjs <16-hex tid>');
  const TID = tidRaw.toLowerCase();

  // pm:dmnt sweep for the target sysmodule pid
  const s = new Session('sysmodromfs-' + Date.now(), 0x2100000);
  s.record = async () => {};
  await s.initialize();
  s.bulkDownloads = true;
  let targetPid = null;
  const memory = await fsMemory.connect();
  const identityOracle = async () => {
    const info = await memory.request({command: 'root-info'});
    const r = await memory.request({command: 'root-native-ipc', handle: info.clones[0], id: 2, hex: ''});
    return Number(r.canonicalResult ?? r.result ?? 0);
  };
  const openService = async name => {
    try {return await s.openService(name);}
    catch (e) {
      // sm fallback (console's own sm session) — the game-dump pattern
      const state = await memory.request({command: 'root-native-info'});
      const sm = (state.services || []).find(x => x.sm)?.sm;
      check(sm, 'no sm handle in root-native-info');
      const packet = Buffer.alloc(256);
      packet.writeUInt32LE(0x11); packet.writeUInt32LE(2, 4); packet.write(name, 8);
      await s.write(s.base, packet);
      await s.call('send', s.base, 4096, sm);
      const reply = await s.readOwned(s.base, 256);
      let at = 8, count = 0, handle = null;
      if (reply.readUInt32LE(4) >>> 31) {
        const special = reply.readUInt32LE(at); at += 4;
        if (special & 1) at += 8;
        count = (special >>> 5) & 15;
        if (count) {handle = reply.readUInt32LE(at); at += 4; s.handles.add(handle);}
      }
      const result = reply.readUInt32LE(at);
      check(!result && count === 1 && handle > 0,
        'SM could not open ' + name + ': 0x' + (result & 0x3fffff).toString(16));
      return handle;
    }
  };
  try {
    const pmDmnt = await openService('pm:dmnt');
    const suffix = TID.slice(-8);
    for (let pid = 1; pid <= 260 && !stopping; pid++) {
      const input = Buffer.alloc(16);
      input.writeBigUInt64LE(BigInt(pid), 0);
      input.writeBigUInt64LE(BigInt(pid), 8);
      const reply = await s.ipc('GetProcessInfo', pmDmnt, 7, input).catch(() => null);
      if (!reply || reply.result) continue;
      const data = Buffer.from(reply.data, 'hex');
      const programId = data.readBigUInt64LE(0) || data.readBigUInt64LE(8) || 0n;
      if (!programId) continue;
      if (pad16(programId).endsWith(suffix)) {targetPid = pid; break;}
    }
    await s.close(pmDmnt).catch(() => {});
    check(targetPid, 'pid sweep found no process for ' + TID + ' (is the sysmodule running?)');
    console.log('target:', TID, '| pid', targetPid, '| oracle before: 0x' +
      (await identityOracle()).toString(16));

    // promote root identity to the sysmodule pid
    await promote(targetPid);
    console.log('promoted to pid', targetPid, '| oracle after: 0x' +
      (await identityOracle()).toString(16));

    // fs cmd 2 on the root clone -> mounted RomFS IFileSystem
    const info = await memory.request({command: 'root-info'});
    const r2 = await memory.request({command: 'root-native-ipc', handle: info.clones[0], id: 2, hex: ''});
    const canonical = Number(r2.canonicalResult ?? r2.result ?? -1) >>> 0;
    check(canonical === 0, 'fs cmd 2 refused: 0x' + canonical.toString(16));
    const fsHandle = (r2.moves || [])[0];
    check(fsHandle, 'fs cmd 2 returned no filesystem handle');
    console.log('mounted RomFS IFileSystem handle:', fsHandle);

    // recursive walk via the controller
    const walk = async dir => {
      const r = await memory.request({command: 'root-list-romfs', handle: fsHandle, path: dir});
      const out = [];
      for (const entry of r.entries || []) {
        const full = (dir === '/' ? '' : dir) + '/' + entry.name;
        if (Number(entry.type) === 0) out.push(...await walk(full));
        else if (Number(entry.type) === 1) out.push({path: full, size: Number(entry.size)});
        else console.log('  (skip type', entry.type, full + ')');
      }
      return out;
    };
    const files = await walk('/');
    console.log('romfs tree:', files.length, 'files | total',
      files.reduce((a, b) => a + b.size, 0), 'bytes');

    // dump with a resume-safe manifest
    const outDir = path.join(OUTROOT, TID);
    const manifestPath = path.join(outDir, 'manifest.json');
    let manifest;
    try {manifest = JSON.parse(await fsp.readFile(manifestPath));} catch {}
    manifest = manifest || {title: TID, via: 'fs cmd 2 OpenDataFileSystemByCurrentProcess (pid-promoted overlay route)',
      started: new Date().toISOString(), files: []};
    const done = new Map(manifest.files.map(f => [f.path, f]));
    let n = 0, bytesDone = 0;
    const t0 = Date.now();
    const flush = async () => {await fsp.mkdir(outDir, {recursive: true});
      await fsp.writeFile(manifestPath, JSON.stringify(manifest, null, 2));};
    for (const entry of files) {
      if (stopping) break;
      const prior = done.get(entry.path);
      if (prior && prior.size === entry.size && prior.sha256) {n++; continue;}
      console.log('  +', entry.path, '(' + entry.size + ')');
      const file = path.join(outDir, 'romfs', entry.path);
      await fsp.mkdir(path.dirname(file), {recursive: true});
      const hash = crypto.createHash('sha256');
      const out = await fsp.open(file, 'w');
      try {
        for (let at = 0; at < entry.size; at += READ_CHUNK) {
          if (stopping) break;
          const take = Math.min(READ_CHUNK, entry.size - at);
          const read = await memory.request({command: 'root-read-romfs-file',
            handle: fsHandle, path: entry.path, offset: at, length: take});
          const bytes = Buffer.from(read.bytes || read.data || '', 'hex');
          check(bytes.length === take, 'romfs read returned ' + bytes.length + ' of ' + take + ': ' + entry.path);
          hash.update(bytes);
          await out.write(bytes, 0, take, at);
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
        console.log('  romfs:', n, '/', files.length, 'files,',
          (bytesDone / 1024 / 1024).toFixed(1), 'MiB,', (rate / 1024).toFixed(0), 'KiB/s');
      }
    }
    if (!stopping) {
      manifest.completed = new Date().toISOString();
      await flush();
      console.log('ROMFS DONE:', n, 'files,', (bytesDone / 1024 / 1024).toFixed(1), 'MiB ->', outDir);
    } else {
      await flush();
      console.log('STOPPED at', n, 'files — re-run to resume');
    }
  } finally {
    for (const h of [...s.handles]) await s.close(h).catch(() => {});
    await s.cleanup().catch(() => {});
    console.log('restoring helper identity...');
    await promote(8);
    console.log('helper identity restored | oracle 0x' + (await identityOracle()).toString(16));
  }
})().catch(e => {console.error('FAILED:', e.stack || e.message); process.exitCode = 1;});