#!/usr/bin/env node
// General-purpose installed-game dumper — any title, base + updates + DLC,
// RomFS + ExeFS sections, no launch, no app switch. The content is opened
// read-only exactly as the system would open it.
//
// Route (all live-validated on fw23; see FINDINGS.md "THE DUMP ROUTE"):
//   ncm OpenContentMetaDatabase(storage) -> ListContentMeta (binary range walk)
//     metaType 0x80 base | 0x81 updates | 0x82 dlc (keyed by app id)
//   db 6/3/24 GetLatestContentMetaKey / GetContentIdByType / GetContentInfoByType
//   storage 8/20 GetPath / GetRightsId  ->  es 503 PrepareTitleKeyByRightsId
//   fs 206 OpenDataStorageByPath(path, [attr, u32 type]) -> decrypted RomFS IStorage
//     (type 1 = program-NCA romfs, 6 = data/DLC romfs)
//   ExeFS: fs 618 GetProgramIdByPath -> ldr:ro cmd 0 OpenCodeFileSystem on the
//     cloned loader root, [attributes, storage, title u64] -> CodeFS IFileSystem.
// Updates open with BOTH the patch and base licenses prepared (joint rights).
//
// Usage (netns-wrapped, live READY session):
//   sudo -n ip netns exec switchlab runuser -u nlight -- node tools/dump/game-dump.cjs \
//     [app-id] [--out DIR] [--probe] [--content base|update|dlc|all] [--section romfs|exefs|all]
//   Default app: 0400c3f00006e000 (Mario Kart World). Defaults: content all, section romfs.
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
const fsMemory = require(path.join(engine, 'tools', 'fs-memory.cjs'));

const STORAGES = [4, 5];          // BuiltInUser, SdCard (gamecard not enumerated)
const TYPE_APPLICATION = 0x80, TYPE_UPDATE = 0x81, TYPE_DLC = 0x82;
const CONTENT_PROGRAM = 1, CONTENT_DATA = 2;
const FS_TYPE_ROMFS = 1, FS_TYPE_DATA_ROMFS = 6;
const CHUNK = 0x40000;            // verified small-chunk default (probe/save-safe)
const BULK_CHUNK = 0x400000;      // 4 MiB when --bulk (Session spans 8 MiB)
// Manifest checkpoint interval, CHUNKS per flush. Each flush rewrites the
// WHOLE manifest (O(entries) — 64 MB at TOTK's 304k files), so the interval is
// the manifest-IO amplification knob: data:manifest bytes written == the
// multiplier. 8 chunks (32 MiB) amplified 2:1 on NVMe and showed up as phantom
// "54 MiB/s write bursts"; 32 chunks (128 MiB) = 4x less I/O, and a crash
// still loses at most one 128 MiB pack file prefix (re-hashed on resume).
const PARTIAL_CHECKPOINT_EVERY = 32;

const readJson = file => fsp.readFile(file, 'utf8').then(JSON.parse);

// Clean-stop: SIGINT/SIGTERM finish the current chunk, close handles, exit.
// A hard kill mid-RPC abandons an in-flight retained-session request and
// kills the carrier (live-proven 2026-10-25: watchdog SIGTERM -> the
// retained endpoint died with the session). Never kill -9 this tool.
let stopping = false;
const stopSignals = () => {
  if (stopping) return;
  stopping = true;
  console.log('stop requested — finishing current chunk and closing cleanly...');
};
process.on('SIGINT', stopSignals);
process.on('SIGTERM', stopSignals);
const hex = b => Buffer.from(b).toString('hex');
const pad16 = v => v.toString(16).padStart(16, '0');

function resultError(label, value) {
  const raw = Number(value) >>> 0, canonical = raw & 0x3fffff;
  const names = {0xe05: 'ContentMetaNotFound', 0x7d802: 'NcaExternalKeyNotFound',
    0x235e02: 'InvalidNcaId', 0x320002: 'PermissionDenied', 0x21005: 'SdMetaDatabaseNotActive'};
  const error = new Error(label + ': result 0x' + raw.toString(16) + ' (' +
    (names[canonical] || 'unknown') + ')');
  error.nativeResult = {raw, canonical};
  return error;
}
const {packet} = require(path.join(__dirname, '..', '..', 'engine', 'shared', 'ipc.cjs'));

// Static receive-buffer descriptor baked into the packet (the 'fixedOutput'
// class). IContentStorage GetPath (cmd 8) accepts ONLY this descriptor shape
// from our context: a map-alias receive (s.ipc {receive mode 0}) kills the
// calling session (transport 0xf601; the retained root survives).
function fixedOutput(command, input, address, size) {
  const bytes = packet(command, input);
  const words = bytes.readUInt32LE(4) & 0x3ff;
  const at = 8 + words * 4;
  bytes.writeUInt32LE((bytes.readUInt32LE(4) | (3 << 10)) >>> 0, 4);
  bytes.writeUInt32LE(address >>> 0, at);
  bytes.writeUInt32LE((Math.floor(address / 2 ** 32) | (size << 16)) >>> 0, at + 4);
  return bytes;
}

const success = (reply, label) => {
  if (reply.result) throw resultError(label, reply.result);
  return reply;
};

// ---- rig bulk read (the fs-dump fast path: 0016 + owned-fetch) ----
// 3 console-native calls per 64 KiB instead of ~50 per 256 KiB (the slide):
// 0016 bulk-copies the session receive buffer into the worker's area at
// s.base+0x1800000 (worker-control's fixed 0016 output), owned-fetch then
// reads it PC-side. The RPC Session must be >= 0x2100000 bytes (fast mode).
class RigBulkReader {
  constructor(a, storageHandle, receiveBuffer, maxChunk = 0x10000) {
    this.a = a; this.storage = storageHandle; this.receive = receiveBuffer;
    this.maxChunk = maxChunk;
    const s = a.s;
    check(s.base && s.bytes >= 0x2100000, 'RPC session too small for the rig receive area (need 33 MiB+)');
    this.fetchAt = s.base + 0x1800000;
  }
  async read(offset, size) {
    check(size > 0 && size <= this.maxChunk, 'rig bulk read range');
    const reply = await this.a.s.ipc('ReadStorage', this.storage, 0,
      Buffer.concat([u64(offset), u64(size)]),
      {receive: [{address: this.receive, size, mode: 1}]});
    check(!reply.result, 'ReadStorage failed: ' + reply.result);
    const rig = await this.a.client.request(0x524f0016, this.a.fsProcHandle,
      [0, this.receive, size, 1]);
    check(rig.result === 0, 'rig bulk copy failed: 0x' + rig.result.toString(16));
    const fetched = await this.a.memory.request({command: 'root-native-owned-fetch',
      address: this.fetchAt, length: size});
    const bytes = Buffer.from(fetched.hex, 'hex');
    check(bytes.length === size, 'owned fetch returned ' + bytes.length + ' of ' + size);
    return bytes;
  }
}

class Attachment {
  constructor() {this.handles = [];}
  track(handle) {this.handles.push(handle); return handle;}
  async service(name) {
    if (this[name]) return this[name];
    const memory = await fsMemory.connect();
    const state = await memory.request({command: 'root-native-info'});
    const sm = (state.services || []).find(x => x.sm)?.sm;
    let handle;
    try {
      handle = await this.s.openService(name);
    } catch (error) {
      const packet = Buffer.alloc(256);
      packet.writeUInt32LE(0x11); packet.writeUInt32LE(2, 4); packet.write(name, 8);
      await this.s.write(this.s.base, packet);
      await this.s.call('send', this.s.base, 4096, sm);
      const reply = await this.s.readOwned(this.s.base, 256);
      let at = 8, count = 0;
      if (reply.readUInt32LE(4) >>> 31) {
        const special = reply.readUInt32LE(at); at += 4;
        if (special & 1) at += 8;              // pid area precedes descriptors
        count = (special >>> 5) & 15;
        if (count) {handle = reply.readUInt32LE(at); at += 4; this.s.handles.add(handle);}
      }
      const result = reply.readUInt32LE(at);
      check(!result && count === 1 && handle > 0,
        'SM could not open ' + name + ': 0x' + (result & 0x3fffff).toString(16));
    }
    return this[name] = this.track(handle);
  }
  async attach(bulk = false, fast = false) {
    this.memory = await fsMemory.connect();
    if (fast) {
      // Fast path: the RO process client (ro:dmnt via monitor sm) + the fs
      // process handle for 0016 bulk copies.
      const {Client} = require(path.join(engine, 'process', 'client.cjs'));
      this.client = await new Client().open();
      const {exportHandle} = require(path.join(engine, 'ro', 'export-handle.cjs'));
      const fsProc = await exportHandle(this.memory, 0xffff8001, 'FS process for rig bulk');
      this.fsProcHandle = fsProc.handle;
      console.log('fast path | rig pid', this.client.pid, '| fs proc', this.fsProcHandle);
    }
    const current = await readJson(path.join(engine, 'current-acquisition.json'));
    const proof = await readJson(path.join(engine, 'ro', 'root', 'current-root.json'));
    const s = this.s = new Session('game-dump-' + Date.now(), fast ? 0x2100000 : 0x800000);
    s.record = async () => {};
    await s.initialize();
    s.bulkDownloads = bulk;   // 4 MiB readStorage chunks via the RPC transfer
    this.root = this.track(domain.oneHandle(success(await domain.send(
      s, 'Clone held promoted FS root', proof.rootHandle, domain.wire.control(2)), 'Clone root')));
    // loader root clone (for ldr:ro OpenCodeFileSystem)
    const roDir = path.join(engine, 'ro');
    const loaderFile = fsSync.readdirSync(roDir).filter(f => f.endsWith('-loader-root-copy.json')).pop();
    check(loaderFile, 'No loader-root evidence in the run dir');
    const loader = await readJson(path.join(roDir, loaderFile));
    check(loader.report === proof.report, 'Loader evidence is from a different report');
    this.loader = this.track(domain.oneHandle(success(await domain.send(
      s, 'Clone held loader root', loader.copy.handle, domain.wire.control(2)), 'Clone loader root')));
    this.pathApi = paths(s, domain);
    return this;
  }
  fastReader(storageHandle) {
    check(this.client && this.fsProcHandle, 'fast path not armed');
    return new RigBulkReader(this, storageHandle, this.s.base + 0x6000);
  }
  async close() {
    if (this.client) {await this.client.close().catch(() => {}); this.client = null;}
    if (!this.s) return;
    for (const handle of this.handles.reverse()) {
      try {await this.s.close(handle);} catch {}
    }
    try {await this.s.cleanup();} catch {}
  }
}

// ---- session identity (the budget-safe promote/restore machinery) ----

// The cmd-2 strength oracle: 0x1408 helper/full-trust, 0x0 app, 0x7d202 ns.
async function identityOracle() {
  const memory = await fsMemory.connect();
  const info = await memory.request({command: 'root-info'});
  const r = await memory.request({command: 'root-native-ipc', handle: info.clones[0], id: 2, hex: ''});
  return Number(r.canonicalResult ?? r.result ?? 0);
}

// pm:dmnt id-7 sweep: map pids to program ids (dual-offset parse; the reply
// layout was observed with the program id at either end of the 16-byte data).
async function sweepProgramIds(a) {
  const pmDmnt = await a.service('pm:dmnt');
  const rows = [];
  for (let pid = 140; pid <= 220; pid++) {
    const input = Buffer.alloc(16);
    input.writeBigUInt64LE(BigInt(pid), 0);
    input.writeBigUInt64LE(BigInt(pid), 8);
    const reply = await a.s.ipc('GetProcessInfo', pmDmnt, 7, input).catch(() => null);
    if (!reply || reply.result) continue;
    const data = Buffer.from(reply.data, 'hex');
    const programId = data.readBigUInt64LE(0) || data.readBigUInt64LE(8) || 0n;
    if (programId) rows.push({pid, programId: programId.toString(16).padStart(16, '0')});
  }
  if (!rows.length) throw Error('pid sweep found no program ids');
  return rows;
}

// Promote the root-session identity via the proven tool (compare-verified
// heap writes; no sm budget). Tolerate its known benign compare-write race —
// the oracle is the judge.
async function promoteIdentity(pid) {
  const {execFile} = require('node:child_process');
  const tool = path.join(__dirname, '..', 'memory', 'fix-session-identity.cjs');
  await new Promise((resolve, reject) =>
    execFile('node', [tool, '--pid', String(pid), '--force'],
      {cwd: path.join(__dirname, '..', '..')}, error => resolve(error)));
  return identityOracle();
}

// ---- active-overlay extraction (the console's own composed view) ----

// Promote the root session to the RUNNING app's pid, then fs cmd 2 opens the
// app's ACTIVE data RomFS (the update-composed view the console itself serves
// — update files replace same-path base files). Walk it, hash every file,
// compare with the dumped base tree, and write differing/new files into an
// overlay directory. Restores the helper identity after.
async function runOverlay(a, appId, outRoot) {
  const rows = await sweepProgramIds(a);
  const suffix = appId.slice(-8);
  const app = rows.find(r => r.programId.endsWith(suffix));
  check(app, 'app pid not found in the sweep (is ' + appId + ' running?)');
  console.log('== overlay: app pid', app.pid, '(' + app.programId + ') ==');
  const oracle = await promoteIdentity(app.pid);
  console.log('promoted (oracle 0x' + oracle.toString(16) + ')');
  try {
    const memory = await fsMemory.connect();
    const info = await memory.request({command: 'root-info'});
    const r2 = await memory.request({command: 'root-native-ipc', handle: info.clones[0], id: 2, hex: ''});
    const canonical = Number(r2.canonicalResult ?? r2.result ?? -1) >>> 0;
    check(canonical === 0, 'cmd 2 refused: 0x' + canonical.toString(16));
    const handle = (r2.moves || [])[0];
    check(handle, 'cmd 2 returned no filesystem handle');
    console.log('active data RomFS handle:', handle);
    // walk
    const manifest = {title: appId, view: 'active-composed', started: new Date().toISOString(), files: []};
    const walk = async dir => {
      const r = await memory.request({command: 'root-list-romfs', handle, path: dir});
      for (const entry of r.entries || []) {
        const full = (dir === '/' ? '' : dir) + '/' + entry.name;
        if (Number(entry.type) === 0) {await walk(full); continue;}   // 0=dir 1=file
        // read in 0x40000 chunks via the controller
        const parts = [];
        let offset = 0;
        for (;;) {
          const read = await memory.request({command: 'root-read-romfs-file', handle,
            path: full, offset, length: 0x40000});
          const bytes = Buffer.from(read.bytes || read.data || '', 'hex');
          parts.push(bytes);
          if (bytes.length < 0x40000) break;
          offset += bytes.length;
        }
        const fileBytes = Buffer.concat(parts);
        manifest.files.push({path: full, size: fileBytes.length,
          sha256: crypto.createHash('sha256').update(fileBytes).digest('hex')});
      }
    };
    await walk('/');
    console.log('active tree:', manifest.files.length, 'files');
    // compare with the base dump
    const baseManifestFile = path.join(outRoot, 'base', 'manifest.json');
    const baseFiles = fsSync.existsSync(baseManifestFile) ? JSON.parse(fsSync.readFileSync(baseManifestFile)).files : [];
    const baseMap = new Map(baseFiles.map(f => [f.path, f]));
    const overlayDir = path.join(outRoot, 'active-overlay');
    let same = 0, changed = 0, added = 0;
    for (const file of manifest.files) {
      const base = baseMap.get(file.path);
      if (!base) {added++; console.log('  +', file.path, '(' + file.size + ')');}
      else if (base.sha256 !== file.sha256) {changed++; console.log('  ~', file.path, '(' + base.size + ' -> ' + file.size + ')');}
      else {same++; continue;}
      const disk = path.join(overlayDir, file.path.replace(/^\//, ''));
      await fsp.mkdir(path.dirname(disk), {recursive: true});
      // re-read the file (we did not keep bytes) — chunked
      const parts = [];
      let offset = 0;
      for (;;) {
        const read = await memory.request({command: 'root-read-romfs-file', handle,
          path: file.path, offset, length: 0x40000});
        const bytes = Buffer.from(read.bytes || read.data || '', 'hex');
        parts.push(bytes);
        if (bytes.length < 0x40000) break;
        offset += bytes.length;
      }
      await fsp.writeFile(disk, Buffer.concat(parts));
    }
    console.log('overlay: ' + same + ' identical, ' + changed + ' changed, ' + added + ' new -> ' + overlayDir);
    await fsp.mkdir(overlayDir, {recursive: true});
    await fsp.writeFile(path.join(overlayDir, 'manifest.json'), JSON.stringify(manifest, null, 2));
  } finally {
    const restored = await promoteIdentity(8);
    console.log('identity restored (oracle 0x' + restored.toString(16) + ')');
  }
}

async function s_close_exefs(a, handle) {
  await a.s.close(handle);
  a.handles = a.handles.filter(h => h !== handle);
}

// ---- content discovery ----

async function listKeys(a, db, metaType, title, min = 0n, max = 0xffffffffffffffffn, found = new Map()) {
  const input = Buffer.alloc(32);
  input[0] = metaType;
  input.writeBigUInt64LE(BigInt('0x' + title), 8);
  input.writeBigUInt64LE(min, 16);
  input.writeBigUInt64LE(max, 24);
  const address = a.s.base + 0x6000, capacity = 32;
  const reply = success(await a.s.ipc('ListContentMeta', db, 5, input,
    {receive: [{address, size: capacity * 16, mode: 0}]}), 'ListContentMeta');
  const total = reply.data.readInt32LE(), count = reply.data.readInt32LE(4);
  const bytes = await a.s.readOwned(address, capacity * 16);
  for (let i = 0; i < count; i++) {
    const key = bytes.subarray(i * 16, (i + 1) * 16);
    const id = pad16(key.readBigUInt64LE());
    const version = key.readUInt32LE(8);
    if (!found.has(id) || version > found.get(id).version) found.set(id, {id, version, metaType: key[12]});
  }
  if (total <= count) return [...found.values()];
  if (min === max) {
    const latestKey = success(await a.s.ipc('GetLatestContentMetaKey', db, 6,
      u64(id)), 'GetLatestContentMetaKey');
    found.set(pad16(min), {id: pad16(min), version: latestKey.data.readUInt32LE(8), metaType});
    return [...found.values()];
  }
  const mid = (min + max) / 2n;
  await listKeys(a, db, metaType, title, min, mid, found);
  await listKeys(a, db, metaType, title, mid + 1n, max, found);
  return [...found.values()];
}

async function resolveContent(a, key, storage, contentType) {
  const ncm = await a.service('ncm');
  const db = a.track(domain.oneHandle(success(
    await a.s.ipc('OpenContentMetaDatabase', ncm, 5, Buffer.from([storage])), 'OpenContentMetaDatabase')));
  try {
    if (key.metaType === TYPE_UPDATE || key.metaType === TYPE_DLC) {
      // update/dlc: ownership check (GetOwnerApplicationId) — proven shape
      const verify = Buffer.alloc(16);
      verify.writeBigUInt64LE(BigInt('0x' + key.id), 0);
      verify.writeUInt32LE(key.version, 8);
      verify[12] = key.metaType;
      success(await a.s.ipc('Verify content ownership', db, 22, verify), 'GetOwnerApplicationId');
    }
    const input = Buffer.alloc(24);
    input[0] = contentType;
    const keyBytes = Buffer.alloc(16);
    keyBytes.writeBigUInt64LE(BigInt('0x' + key.id), 0);
    keyBytes.writeUInt32LE(key.version, 8);
    keyBytes[12] = key.metaType;
    keyBytes.copy(input, 8);
    let contentId;
    try {
      contentId = hex(success(await a.s.ipc('GetContentIdByType', db, 3, input), 'GetContentIdByType').data.subarray(0, 16));
    } catch (error) {
      if (error.nativeResult?.canonical === 0xe05) throw Error('no ' + {1: 'Program', 2: 'Data', 3: 'Control'}[contentType] + ' content under key ' + key.id + ' v' + key.version);
      throw error;
    }
    const info = success(await a.s.ipc('GetContentInfoByType', db, 24, input), 'GetContentInfoByType').data;
    const attributes = info[21] & 15;
    const store = a.track(domain.oneHandle(success(
      await a.s.ipc('OpenContentStorage', ncm, 4, Buffer.from([storage])), 'OpenContentStorage')));
    try {
      const pathAddress = a.s.base + 0x5000, pathSize = 0x300;
      success(await domain.send(a.s, 'Resolve content path', store,
        fixedOutput(8, Buffer.from(contentId, 'hex'), pathAddress, pathSize)), 'Resolve content path');
      const bytes = await a.s.readOwned(pathAddress, pathSize);
      const contentPath = bytes.subarray(0, bytes.indexOf(0)).toString('utf8');
      const rights = success(await a.s.ipc('GetRightsId', store, 20,
        Buffer.concat([Buffer.from(contentId, 'hex'), Buffer.from([attributes])])), 'GetRightsId').data;
      return {key, storage, contentType, contentId, contentPath, attributes,
        rightsId: hex(rights.subarray(0, 16)), generation: rights[16]};
    } finally {await a.s.close(store); a.handles = a.handles.filter(h => h !== store);}
  } finally {await a.s.close(db); a.handles = a.handles.filter(h => h !== db);}
}

async function linkedAccounts(a) {
  const account = await a.service('acc:su');
  const address = a.s.base + 0x3600, bytes = 8 * 16;
  await a.s.write(address, Buffer.alloc(bytes));
  const packet = fixedOutput(2, Buffer.alloc(2), address, bytes);
  packet.writeUInt16LE(bytes, 40);
  success(await domain.send(a.s, 'List local users', account, packet), 'List local users');
  const output = await a.s.readOwned(address, bytes);
  const accounts = [];
  for (let at = 0; at < bytes; at += 16) {
    const user = output.subarray(at, at + 16);
    if (user.every(b => !b)) continue;
    const opened = await a.s.ipc('Open account manager', account, 102, user);
    if (opened.result) continue;
    const manager = a.track(domain.oneHandle(opened));
    try {
      const linked = await a.s.ipc('Get linked account identity', manager, 120);
      if (linked.result) continue;
      const id = Buffer.from(linked.data.subarray(0, 8));
      if (id.some(b => b) && !accounts.some(other => other.equals(id))) accounts.push(id);
    } finally {await a.s.close(manager); a.handles = a.handles.filter(h => h !== manager);}
  }
  return accounts;
}

async function prepareLicense(a, source) {
  if (!source || Buffer.from(source.rightsId, 'hex').every(b => !b)) return false;
  const es = await a.service('es');
  const prepare = () => a.s.ipc('Prepare installed title license', es, 503, Buffer.alloc(0),
    {send: [{address: a.s.base + 0x5200, size: 16, mode: 0}, {address: a.s.base + 0x5300, size: 4, mode: 0}]});
  const writeLicenseArgs = () => {
    const generation = Buffer.alloc(4); generation.writeUInt32LE(source.generation);
    return Promise.all([a.s.write(a.s.base + 0x5200, Buffer.from(source.rightsId, 'hex')),
      a.s.write(a.s.base + 0x5300, generation)]);
  };
  await writeLicenseArgs();
  let reply = await prepare();
  let canonical = Number(reply.result) & 0x3fffff;

  if (canonical === 0x1491 || canonical === 0x691) {
    // Owned-content context: register the application, ask for title rights on
    // all accounts, evaluate, retry; then individual-account selection.
    if (!a.licenseContext || !a.s.handles.has(a.licenseContext.handle)) {
      const opened = success(await a.s.ipc('Create export rights context', es, 2001),
        'Create export rights context');
      a.licenseContext = {handle: a.track(domain.oneHandle(opened)),
        applications: new Set(), accountSelected: false};
    }
    const context = a.licenseContext.handle;
    const rightsApplication = source.rightsId.slice(0, 16);  // es looks up the first 8 bytes
    await a.s.write(a.s.base + 0x3200, u64('0x' + rightsApplication));
    if (!a.licenseContext.applications.has(rightsApplication)) {
      success(await a.s.ipc('Select export title rights', context, 2, Buffer.alloc(0),
        {send: [{address: a.s.base + 0x3200, size: 8, mode: 0}]}), 'Select export title rights');
      a.licenseContext.applications.add(rightsApplication);
    }
    const selectAccounts = () => a.s.ipc('Request export title account rights', context, 17,
      Buffer.from([1]), {send: [{address: a.s.base + 0x3200, size: 8, mode: 0},
        {address: a.s.base + 0x3400, size: 8, mode: 0}]}).then(r =>
        (check(!r.result, 'Request account rights failed'), r));
    await selectAccounts();
    success(await a.s.ipc('Evaluate export title rights', context, 3), 'Evaluate export title rights');
    await writeLicenseArgs();
    reply = await prepare();
    canonical = Number(reply.result) & 0x3fffff;
    if ((canonical === 0x1491 || canonical === 0x691) && !a.licenseContext.accountSelected) {
      const accounts = await linkedAccounts(a);
      check(accounts.length, 'no linked accounts found for the owned-content context');
      await a.s.write(a.s.base + 0x3400, Buffer.concat(accounts));
      success(await a.s.ipc('Select export account rights', context, 1, Buffer.from([0]),
        {send: [{address: a.s.base + 0x3400, size: accounts.length * 8, mode: 0}]}),
        'Select export account rights');
      a.licenseContext.accountSelected = true;
      await selectAccounts();
      success(await a.s.ipc('Evaluate selected account rights', context, 3),
        'Evaluate selected account rights');
      await writeLicenseArgs();
      reply = await prepare();
      canonical = Number(reply.result) & 0x3fffff;
    }
  }
  const rightsBytes = Buffer.from(source.rightsId, 'hex');
  const originalRequired = rightsBytes.length >= 16 && rightsBytes.readBigUInt64LE(8) & (1n << 52n);
  check(canonical === 0,
    'License preparation failed: 0x' + (Number(reply.result) >>> 0).toString(16) +
    (originalRequired || canonical === 0x691 ?
      ' (update-class content: the es standalone license does not apply; updates need the original-content resolver path — not yet implemented)' : ''));
  return true;
}

// ---- section opens ----

async function openRomfs(a, source, type) {
  const pathBuffer = Buffer.alloc(0x301);
  pathBuffer.write(source.contentPath);
  const input = Buffer.alloc(8);
  input[0] = source.attributes;
  input.writeUInt32LE(type, 4);
  const reply = success(await a.pathApi.raw(a.root, 206, pathBuffer, input), 'OpenDataStorageByPath');
  return a.track(domain.oneHandle(reply));
}

async function openCodefs(a, source, title) {
  // fs 618: resolve the runtime program id from the program NCA path
  const pathBuffer = Buffer.alloc(0x301);
  pathBuffer.write(source.contentPath);
  const identity = success(await a.pathApi.raw(a.root, 618, pathBuffer,
    Buffer.from([source.attributes])), 'GetProgramIdByPath');
  const runtimeId = identity.data.readBigUInt64LE(0);
  check(runtimeId > 0n, 'runtime program id resolution failed');
  // ldr:ro cmd 0 OpenCodeFileSystem on the cloned loader root
  const input = Buffer.alloc(16);
  input[0] = source.attributes;
  input[1] = source.storage;
  input.writeBigUInt64LE(runtimeId, 8);
  const address = a.s.base + 0x4000;
  const reply = success(await a.s.ipc('Open game CodeFS', a.loader, 0, input,
    {receive: [{address, size: 0x1a4, mode: 0}]}), 'Open game CodeFS');
  return a.track(domain.oneHandle(reply));
}

// ---- raw NCA dump (the standard emulator format) ----
// The Switch-1-emulator-standard flow (Ryujinx/LibHac): the loader selects
// base + patch + control NCAs and LAYERS them at open (OpenStorageWithPatch)
// — no composed image is ever materialized. The standard deliverable per
// game is therefore the raw NCA files. This reads an NCA's full IStorage
// (fs 206 type 1 on its @UserContent path) in 256 KiB chunks with the same
// manifest/checkpoint machinery.
async function dumpRawNca(a, source, outDir, label) {
  const pathBuffer = Buffer.alloc(0x301);
  pathBuffer.write(source.contentPath);
  const input = Buffer.alloc(8);
  input[0] = source.attributes;
  input.writeUInt32LE(1, 4);
  const reply = success(await a.pathApi.raw(a.root, 206, pathBuffer, input), 'nca mount ' + label);
  const storage = domain.oneHandle(reply);
  const size = Number(await domain.storageSize(a.s, storage));
  console.log('  nca ' + label + ':', source.contentId, '| size:', size, '(', (size / 1024 ** 2).toFixed(1), 'MiB )');
  const file = path.join(outDir, label + '.nca');
  const manifestFile = path.join(outDir, 'manifest-' + label + '.json');
  const manifest = fsSync.existsSync(manifestFile) ? JSON.parse(fsSync.readFileSync(manifestFile)) :
    {section: 'nca', label, contentId: source.contentId, contentPath: source.contentPath,
     size, started: new Date().toISOString(), parts: [], complete: false};
  let done = 0;
  for (const part of manifest.parts) done += part.size;
  done -= done % CHUNK;
  const handle = await fsp.open(file, done ? 'r+' : 'w');
  const hash = crypto.createHash('sha256');
  try {
    // hash the banked prefix locally
    if (done > 0) {
      const prefix = await fsp.open(file, 'r');
      try {
        for (let at = 0; at < done; at += 0x100000) {
          const take = Math.min(0x100000, done - at);
          const buffer = Buffer.alloc(take);
          check((await prefix.read(buffer, 0, take, at)).bytesRead === take, 'nca prefix read failed');
          hash.update(buffer);
        }
      } finally {await prefix.close();}
    }
    let since = 0;
    for (let at = done; at < size; at += CHUNK) {
      if (stopping) throw STOP;
      const take = Math.min(CHUNK, size - at);
      const bytes = await filesystem.readStorage(a.s, storage, at, take);
      hash.update(bytes);
      await handle.write(bytes, 0, take, at);
      done += take; since += take;
      if (since >= 32 * 1024 * 1024 || at + take >= size) {
        manifest.parts.push({offset: at - (since - take), size: since});
        manifest.complete = at + take >= size;
        manifest.sha256 = manifest.complete ? hash.digest('hex') : null;
        await fsp.writeFile(manifestFile, JSON.stringify(manifest, null, 2));
        since = 0;
      }
    }
  } finally {await handle.close();}
  if (!manifest.complete) {
    manifest.complete = true;
    manifest.sha256 = hash.digest('hex');
    await fsp.writeFile(manifestFile, JSON.stringify(manifest, null, 2));
  }
  console.log('  nca ' + label + ': done', size, 'bytes sha', manifest.sha256.slice(0, 16));
  await a.s.close(storage); a.handles = a.handles.filter(h => h !== storage);
}

// ---- romfs (IStorage) ----

async function romfsHeader(a, storage, size) {
  const header = await filesystem.readStorage(a.s, storage, 0, 0x50);
  const h = Array.from({length: 10}, (_, i) => header.readBigUInt64LE(i * 8));
  check(h[0] === 0x50n, 'unexpected RomFS header size: 0x' + h[0].toString(16));
  // Section order is builder-dependent (MKW's metadata sits ~90 MB in, with
  // data on both sides): only require each extent to fit the storage.
  const sizeN = BigInt(size);
  for (let i = 1; i < 9; i += 2) {
    check(h[i] + h[i + 1] <= sizeN, 'RomFS section ' + i + ' exceeds storage');
  }
  check(h[9] <= sizeN, 'RomFS data offset exceeds storage');
  return h;
}

async function readTable(a, storage, offset, size, storageSize) {
  check(Number.isSafeInteger(offset) && size >= 0 && offset + size <= storageSize, 'table range');
  // Some storages fault on large single reads (the 0xba5ee002 class on the
  // update RomFS): read in 64 KiB steps, retry each step smaller on failure.
  const parts = [];
  const step = Math.min(CHUNK, 0x10000);
  for (let at = 0; at < size; at += step) {
    const take = Math.min(step, size - at);
    parts.push(await filesystem.readStorage(a.s, storage, offset + at, take));
  }
  return Buffer.concat(parts);
}

function parseRomfs(dirs, files) {
  const NONE = 0xffffffff, output = [], stack = [{offset: 0, dirPath: '', parent: 0}];
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
      output.push({path: dirPath, type: 'directory'});
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
      output.push({path: dir.dirPath + '/' + name, type: 'file',
        offset: Number(e.readBigUInt64LE(8)), size: Number(e.readBigUInt64LE(16))});
      at = e.readUInt32LE(4);
    }
  }
  return output;
}

async function dumpRomfs(a, storage, storageSize, outDir) {
  const h = await romfsHeader(a, storage, storageSize);
  const dirs = await readTable(a, storage, Number(h[3]), Number(h[4]), storageSize);
  const files = await readTable(a, storage, Number(h[7]), Number(h[8]), storageSize);
  const tree = parseRomfs(dirs, files);
  await fsp.mkdir(outDir, {recursive: true});
  await fsp.writeFile(path.join(outDir, 'romfs-file-list.json'),
    JSON.stringify({size: storageSize, header: h.map(v => v.toString()), tree}, null, 2));
  const totalFiles = tree.filter(x => x.type === 'file');
  const manifestFile = path.join(outDir, 'manifest.json');
  const manifest = fsSync.existsSync(manifestFile) ? JSON.parse(fsSync.readFileSync(manifestFile)) :
    {section: 'romfs', started: new Date().toISOString(), files: []};
  manifest.partial = manifest.partial || {};
  // In-memory manifest bookkeeping: a Map (the array scan per file was
  // O(files) — 138k string compares per write at this scale).
  const filesMap = new Map(manifest.files.map(f => [f.path, f]));
  const done = filesMap;
  const dataOffset = Number(h[9]);
  const ranges = [[Number(h[1]), Number(h[1]) + Number(h[2])], [Number(h[3]), Number(h[3]) + Number(h[4])],
    [Number(h[5]), Number(h[5]) + Number(h[6])], [Number(h[7]), Number(h[7]) + Number(h[8])]];
  for (const entry of totalFiles) {
    const extentStart = dataOffset + entry.offset, extentEnd = extentStart + entry.size;
    check(extentEnd <= storageSize, 'file extent exceeds storage: ' + entry.path);
    check(!entry.size || ranges.every(([start, end]) => extentEnd <= start || extentStart >= end),
      'file extent overlaps metadata: ' + entry.path);
  }
  let n = 0, bytesDone = 0, manifestDirty = false, lastFlush = Date.now();
  const t0 = Date.now();
  const flush = async () => {
    manifest.files = [...filesMap.values()];
    await fsp.writeFile(manifestFile, JSON.stringify(manifest, null, 2));
    manifestDirty = false; lastFlush = Date.now();
  };
  const recordFile = async (entry, sha) => {
    delete manifest.partial[entry.path];
    filesMap.set(entry.path, {path: entry.path, size: entry.size, offset: entry.offset, sha256: sha});
    manifestDirty = true;
    bytesDone += entry.size;
    if (++n % 20 === 0 || (Date.now() - lastFlush) > 5000) await flush();
  };
  // COALESCED SMALL-FILE READS: sort the small files by data offset and read
  // one 256 KiB window per contiguous group — one slide round + one console
  // sha per ~100 files instead of per file (small files dominate the count).
  const WINDOW = a.s.bulkDownloads ? Math.min(BULK_CHUNK, CHUNK) : CHUNK;
  const smalls = totalFiles.filter(e => e.size > 0 && e.size <= WINDOW &&
    !(manifest.partial[e.path] && manifest.partial[e.path].done > 0)).sort((x, y) => x.offset - y.offset);
  const groups = [];
  let g = null;
  for (const e of smalls) {
    if (!g || (e.offset + e.size) - g.start > WINDOW || e.offset - g.end > 0x10000) {
      g = {start: e.offset, end: e.offset + e.size, files: []};
      groups.push(g);
    }
    g.files.push(e);
    g.end = Math.max(g.end, e.offset + e.size);
  }
  console.log('  coalesced: ' + smalls.length + ' small files into ' + groups.length + ' read windows');
  const dirsMade = new Set();
  for (const group of groups) {
    if (stopping) throw STOP;
    // Skip windows whose every file is already dumped (manifest skip) —
    // the window read below is the bulk cost; never pay it for done groups.
    if (group.files.every(e => done.has(e.path) && done.get(e.path).size === e.size)) continue;
    const span = group.end - group.start;
    let buffer = null;
    try {buffer = await filesystem.readStorage(a.s, storage, dataOffset + group.start, span);}
    catch (error) {console.log('  window read failed (' + error.message.slice(0, 50) + ') — per-file fallback');}
    for (const entry of group.files) {
      if (stopping) throw STOP;
      if (done.has(entry.path) && done.get(entry.path).size === entry.size) continue;
      const file = path.join(outDir, 'romfs', entry.path);
      const dir = path.dirname(file);
      if (!dirsMade.has(dir)) {await fsp.mkdir(dir, {recursive: true}); dirsMade.add(dir);}
      const hash = crypto.createHash('sha256');
      let bytes = null, parts = null;
      if (buffer) {
        bytes = buffer.subarray(entry.offset - group.start, entry.offset - group.start + entry.size);
        hash.update(bytes);
      } else {
        parts = [];
        for (let at = 0; at < entry.size; at += CHUNK) {
          const take = Math.min(CHUNK, entry.size - at);
          const b = await filesystem.readStorage(a.s, storage, dataOffset + entry.offset + at, take);
          parts.push(b); hash.update(b);
        }
      }
      const handle = await fsp.open(file, 'w');   // single-window file: no .part staging
      try {
        if (bytes) await handle.write(bytes);
        else for (const b of parts) await handle.write(b);
      } finally {await handle.close();}
      await recordFile(entry, hash.digest('hex'));
      if (n % 20 === 0) {
        const rate = bytesDone / Math.max(1, (Date.now() - t0) / 1000);
        console.log('  romfs: ' + n + ' files, ' + (bytesDone / 1024 ** 2).toFixed(1) +
          ' MiB, ' + (rate / 1024).toFixed(0) + ' KiB/s');
      }
    }
  }
  // Large files (and partial-resumed stragglers): chunked path + .part staging.
  const inGroup = new Set();
  for (const grp of groups) for (const f of grp.files) inGroup.add(f.path);
  const rest = totalFiles.filter(e => !inGroup.has(e.path));
  // Byte meter for the large-file phase (the small-file loop prints its own):
  // one line every 15 s so a silent-but-healthy multi-GiB pack file never looks
  // like a stall (the 2026-10-26 lesson: monitor killed a good run).
  let lastRestLog = Date.now();
  const restStartBytes = bytesDone;
  console.log('  romfs rest: ' + rest.length + ' large files');
  for (const entry of rest) {
    if (stopping) throw STOP;
    if (done.has(entry.path) && done.get(entry.path).size === entry.size) continue;
    const file = path.join(outDir, 'romfs', entry.path);
    await fsp.mkdir(path.dirname(file), {recursive: true});
    const part = file + '.part';
    let at = 0;
    const hash = crypto.createHash('sha256');
    const partialRecord = manifest.partial[entry.path];
    if (partialRecord && await fsp.stat(part).then(s => s.size > 0, () => false)) {
      const actual = (await fsp.stat(part)).size;
      at = Math.min(partialRecord.done, actual);
      if (at > 0) {
        // hash the banked prefix locally, then continue from the checkpoint
        const prefix = await fsp.open(part, 'r');
        try {
          for (let read = 0; read < at; read += BULK_CHUNK) {
            const take = Math.min(BULK_CHUNK, at - read);
            const buffer = Buffer.alloc(take);
            check((await prefix.read(buffer, 0, take, read)).bytesRead === take, 'partial prefix read failed');
            hash.update(buffer);
          }
        } finally {await prefix.close();}
      }
    }
    const handle = await fsp.open(part, at ? 'r+' : 'w');
    let chunk = a.s.bulkDownloads ? BULK_CHUNK : CHUNK;
    try {
      let sinceCheckpoint = 0;
      // Fast path (--fast): the RigBulkReader's 3-call/64KiB transfer instead
      // of the slide's ~50-call/256KiB (see RigBulkReader). Falls back to the
      // slide path on any rig error.
      const fastReader = a.fastReader && a.fastReaderFor === storage ? a.fastReader : null;
      let fastChunk = fastReader ? fastReader.maxChunk : chunk;
      for (; at < entry.size; at += fastChunk) {
        if (stopping) {await handle.close(); throw STOP;}
        const take = Math.min(fastChunk, entry.size - at);
        let bytes;
        try {
          if (fastReader) {
            try {
              bytes = await fastReader.read(dataOffset + entry.offset + at, take);
            } catch (fastError) {
              console.log('  fast read failed — falling back to the slide path:', fastError.message.slice(0, 60));
              a.fastReader = null;
              bytes = await filesystem.readStorage(a.s, storage, dataOffset + entry.offset + at, Math.min(CHUNK, take));
            }
          } else {
            bytes = await filesystem.readStorage(a.s, storage, dataOffset + entry.offset + at, take);
          }
        } catch (error) {
          // bulk transfer failure: fall back to the proven 256 KiB shape once
          if (!a.s.bulkDownloads || take <= CHUNK) throw error;
          console.log('  bulk read failed (' + error.message.slice(0, 60) + ') — falling back to 256 KiB');
          a.s.bulkDownloads = false; chunk = CHUNK;
          bytes = await filesystem.readStorage(a.s, storage, dataOffset + entry.offset + at, Math.min(CHUNK, take));
        }
        hash.update(bytes);
        await handle.write(bytes, 0, take, at);
        bytesDone += take;
        sinceCheckpoint += take;
        if (Date.now() - lastRestLog > 15000) {
          const rate = (bytesDone - restStartBytes) / 1024 / ((Date.now() - t0) / 1000);
          console.log('  romfs rest: ' + (entry.path.length > 48 ? '…' + entry.path.slice(-48) : entry.path) +
            ' ' + (at / 1024 / 1024).toFixed(1) + '/' + (entry.size / 1024 / 1024).toFixed(0) +
            ' MiB | total ' + (bytesDone / 1024 / 1024).toFixed(0) + ' MiB | ' + (rate / 1024).toFixed(0) + ' KiB/s');
          lastRestLog = Date.now();
        }
        if (sinceCheckpoint >= PARTIAL_CHECKPOINT_EVERY * chunk || at + take >= entry.size) {
          manifest.partial[entry.path] = {done: at + take, size: entry.size, offset: entry.offset};
          await flush();
          sinceCheckpoint = 0;
        }
      }
    } finally {await handle.close();}
    await fsp.rename(part, file);
    await recordFile(entry, hash.digest('hex'));
  }
  if (manifestDirty) await flush();
  console.log('  romfs: done (' + n + ' new, ' + totalFiles.length + ' total, ' +
    filesMap.size + ' in manifest)');
}

// ---- exefs (CodeFS IFileSystem) ----

async function walkCodefs(a, handle, dirPath, outDir, manifest, done) {
  const entries = await filesystem.listDirectory(a.s, handle, dirPath);
  for (const entry of entries) {
    const entryPath = (dirPath === '/' ? '' : dirPath) + '/' + entry.name;
    if (entry.type === 'directory') {
      await walkCodefs(a, handle, entryPath, outDir, manifest, done);
      continue;
    }
    if (done.has(entryPath) && done.get(entryPath).size === entry.size) continue;
    const file = path.join(outDir, 'exefs', entryPath);
    await fsp.mkdir(path.dirname(file), {recursive: true});
    // IFileSystem cmd 8 OpenFile: path staged, u32 mode 1 (read) — the same
    // path-staging shape as the proven listDirectory (cmd 9) path
    const opened = success(await a.pathApi.normal(handle, 8, entryPath, u32(1)), 'Open exefs file');
    const fileHandle = a.track(domain.oneHandle(opened));
    try {
      const size = Number(await filesystem.fileSize(a.s, fileHandle));
      const hash = crypto.createHash('sha256');
      const out = await fsp.open(file, 'w');
      try {
        for (let at = 0; at < size; at += CHUNK) {
          const take = Math.min(CHUNK, size - at);
          const bytes = await filesystem.readFile(a.s, fileHandle, at, take);
          hash.update(bytes);
          await out.write(bytes);
        }
      } finally {await out.close();}
      manifest.files = manifest.files.filter(f => f.path !== entryPath);
      manifest.files.push({path: entryPath, size, sha256: hash.digest('hex')});
      await fsp.writeFile(path.join(outDir, 'manifest-exefs.json'), JSON.stringify(manifest, null, 2));
    } finally {await a.s.close(fileHandle); a.handles = a.handles.filter(h => h !== fileHandle);}
  }
}

// ---- driver ----

const TRANSPORT_RE = /transport 0x|timed out|not replayed|no longer available|ECONN|ENOENT.*memory\.sock/i;
const STOP = Symbol('clean-stop');

async function verifyManifests(outRoot) {
  console.log('== verify pass (local disk) ==');
  let checked = 0;
  const manifests = [];
  const walk = async dir => {
    for (const item of await fsp.readdir(dir, {withFileTypes: true})) {
      if (item.isDirectory()) {
        // content subtrees hold their own copies of manifests — those are
        // data files, not dump manifests; only walk the packaging levels
        if (item.name === 'romfs' || item.name === 'exefs') continue;
        await walk(path.join(dir, item.name));
      }
      else if (item.name === 'manifest.json' || item.name === 'manifest-exefs.json')
        manifests.push(path.join(dir, item.name));
    }
  };
  await walk(outRoot).catch(() => {});
  const bad = [];
  for (const manifestFile of manifests) {
    const manifest = JSON.parse(await fsp.readFile(manifestFile, 'utf8'));
    const base = path.dirname(manifestFile);
    const section = path.basename(manifestFile) === 'manifest-exefs.json' ? 'exefs' : 'romfs';
    for (const file of manifest.files || []) {
      const disk = path.join(base, section, file.path.replace(/^\//, ''));
      const hash = crypto.createHash('sha256');
      const handle = await fsp.open(disk, 'r');
      try {
        for (let at = 0; at < file.size; at += 4 * 1024 * 1024) {
          const take = Math.min(4 * 1024 * 1024, file.size - at);
          const buffer = Buffer.alloc(take);
          check((await handle.read(buffer, 0, take, at)).bytesRead === take, 'short read: ' + file.path);
          hash.update(buffer);
        }
      } finally {await handle.close();}
      if (hash.digest('hex') !== file.sha256) bad.push(disk);
      checked++;
      if (checked % 500 === 0) console.log('  verified ' + checked + '...');
    }
  }
  check(!bad.length, 'sha256 mismatches: ' + bad.join(', '));
  console.log('verified ' + checked + ' files, all hashes match.');
}

async function main() {
  const argv = process.argv.slice(2);
  const appId = (argv.find(x => /^0?x?[0-9a-fA-F]{16}$/.test(x)) || '0400c3f00006e000').replace(/^0x/, '').toLowerCase();
  const probe = argv.includes('--probe');
  const verifyOnly = argv.includes('--verify');
  const bulk = argv.includes('--bulk');
  const wantedContentExplicit = argv.includes('--content');
  const wantedContent = wantedContentExplicit ? argv[argv.indexOf('--content') + 1] : 'all';
  const wantedSection = argv.includes('--section') ? argv[argv.indexOf('--section') + 1] : 'all';
  const archive = argv.includes('--archive') ? argv[argv.indexOf('--archive') + 1].replace(/^0x/, '').toLowerCase() : null;
  const control = argv.includes('--control');
  const overlay = argv.includes('--overlay');
  const fast = argv.includes('--fast');   // rig 0016 bulk + owned-fetch
  const wantedNca = argv.includes('--nca');   // raw NCA dump (standard emulator format)
  const outRoot = path.resolve(argv.includes('--out') ? argv[argv.indexOf('--out') + 1] :
    path.join(require('node:os').homedir(), 'dev', 'switch', 'roms', appId));
  console.log('target:', appId, '| content:', wantedContent, '| section:', wantedSection,
    bulk ? '| bulk' : '', probe ? '| PROBE' : '-> ' + outRoot);

  if (verifyOnly) {await verifyManifests(outRoot); return;}

  const MAX_ATTACH = 6, BACKOFF_MS = 15000;
  let a = null;
  for (let attempt = 1; ; attempt++) {
    try {
      a = await new Attachment().attach(bulk, fast);
      console.log('attached | root:', a.root, '| loader:', a.loader);
      break;
    } catch (error) {
      if (attempt >= MAX_ATTACH) throw Error('attach failed after ' + attempt + ' attempts: ' + error.message +
        ' — if the console session is wedged, reboot + re-dance, then rerun; the manifest resumes.');
      console.log('attach failed (' + error.message.slice(0, 80) + ') — retry ' + attempt + '/' + MAX_ATTACH);
      await new Promise(r => setTimeout(r, BACKOFF_MS));
    }
  }
  let lastError = null;
  for (let round = 1; ; round++) {
    try {
      if (overlay) await runOverlay(a, appId, outRoot);
      await runAllJobs(a, {appId, probe, wantedContent, wantedContentExplicit, wantedSection, outRoot, archive, control, wantedNca});
      break;
    } catch (error) {
      if (error === STOP) {lastError = null; console.log('STOPPED CLEANLY — resume-safe (rerun the same command).'); break;}
      lastError = error;
      const retryable = TRANSPORT_RE.test(error.message || '');
      if (!retryable || round >= 5) break;
      console.log('transport failure (' + error.message.slice(0, 90) + ') — re-attaching and resuming, round ' + round);
      await a.close().catch(() => {});
      await new Promise(r => setTimeout(r, BACKOFF_MS));
      a = await new Attachment().attach(bulk, fast);
      console.log('re-attached | root:', a.root);
    }
  }
  await a.close().catch(() => {});
  if (lastError) throw lastError;
  if (stopping) {console.log('STOPPED — resume with the same command.'); return;}
  if (!probe) await verifyManifests(outRoot);
  console.log(probe ? 'PROBE COMPLETE.' : 'DUMP COMPLETE + VERIFIED.');
}

// System data archives (e.g. TimeZoneBinary 010000000000080e): the content
// lives in the BuiltInSystem (3) or user (4/5) meta DBs as Data-type content;
// its RomFS opens through the same fs-206 route with the data type.
async function resolveArchive(a, title) {
  const ncm = await a.service('ncm');
  // System data archives (the 8xx titles) register under metaType 0x02 keys
  // in the BuiltInSystem database; system programs under 0x01. Scan 0x02.
  let db = null;
  try {
    db = a.track(domain.oneHandle(success(
      await a.s.ipc('OpenContentMetaDatabase', ncm, 5, Buffer.from([3])), 'OpenContentMetaDatabase')));
    const keys = await listKeys(a, db, 0x02, '0000000000000000');
    const key = keys.find(k => k.id === title);
    check(key, 'archive ' + title + ' not in the system content list');
    return await resolveContent(a, key, 3, CONTENT_DATA);
  } finally {
    if (db) {await a.s.close(db); a.handles = a.handles.filter(h => h !== db);}
  }
}

// control.nacp: the control NCA opens as fsType 3 via cmd 10; /control.nacp
// is a plain file inside it.
async function dumpControl(a, appTitle, source, outDir) {
  const pathBuffer = Buffer.alloc(0x301);
  pathBuffer.write(source.contentPath);
  const input = Buffer.alloc(16);
  input[0] = source.attributes;
  input.writeUInt32LE(3, 4);
  input.writeBigUInt64LE(BigInt('0x' + appTitle), 8);
  const opened = success(await a.pathApi.raw(a.root, 10, pathBuffer, input), 'Open control metadata');
  const control = a.track(domain.oneHandle(opened));
  try {
    const file = success(await a.pathApi.normal(control, 8, '/control.nacp', u32(1)), 'Open control.nacp');
    const handle = a.track(domain.oneHandle(file));
    try {
      const size = Number(await filesystem.fileSize(a.s, handle));
      const bytes = await filesystem.readFile(a.s, handle, 0, size);
      await fsp.mkdir(outDir, {recursive: true});
      await fsp.writeFile(path.join(outDir, 'control.nacp'), bytes);
      console.log('  control.nacp:', size, 'bytes ->', path.join(outDir, 'control.nacp'));
      return size;
    } finally {await a.s.close(handle); a.handles = a.handles.filter(h => h !== handle);}
  } finally {await a.s.close(control); a.handles = a.handles.filter(h => h !== control);}
}

async function runAllJobs(a, {appId, probe, wantedContent, wantedContentExplicit, wantedSection, outRoot, archive, control, wantedNca}) {
  const phaseErrors = [];
  try {
    if (control) {
      console.log('== control.nacp for ' + appId + ' ==');
      // path queries first (natural identity): ns:am2 cmd 21 fails under a
      // promoted ns identity (registry class 0x9a02).
      // resolve the application key on user storage, then its Control content
      const ncm = await a.service('ncm');
      for (const storage of STORAGES) {
        let db = null;
        try {
          db = a.track(domain.oneHandle(success(
            await a.s.ipc('OpenContentMetaDatabase', ncm, 5, Buffer.from([storage])), 'OpenContentMetaDatabase')));
          let key;
          try {
            const latest = success(await a.s.ipc('GetLatestContentMetaKey', db, 6, u64('0x' + appId)),
              'GetLatestContentMetaKey');
            key = {id: appId, version: latest.data.readUInt32LE(8), metaType: latest.data[12]};
          } catch (error) {
            if (error.nativeResult?.canonical === 0xe05) continue;
            throw error;
          }
          // NOTE: use the DISCOVERED key verbatim (id+version+metaType from
          // the NCM list). Never synthesize {version: 0} keys: the base app
          // key often has no content records, and GetContentIdByType then
          // falls through to the update's NCA (the 4.4.9-in-base-exefs bug).
          const source = await resolveContent(a, key, storage, 3);   // Control content type
          console.log('  control NCA:', source.contentId, source.contentPath, '| attr', source.attributes);
          try {
            await dumpControl(a, appId, source, path.join(outRoot, 'base'));
          } catch (error) {
            if (error.nativeResult?.canonical !== 0x320002 || a.promoted) throw error;
            console.log('  control mount gated — will retry under the ns promotion');
            a.controlRetry = {appId, source};
          }
          a.controlDelivered = true;
          break;
        } catch (error) {
          if (error.nativeResult?.canonical === 0x21005 || error.nativeResult?.canonical === 0x20a05) continue;
          throw error;
        } finally {
          if (db) {await a.s.close(db); a.handles = a.handles.filter(h => h !== db);}
        }
      }
      if (!a.controlDelivered && !a.controlRetry) {
        throw Error('application ' + appId + ' not found for control content');
      }
    }
    if (archive) {
      console.log('== archive ' + archive + ' ==');
      const source = await resolveArchive(a, archive);
      console.log('  content:', source.contentId, source.contentPath, '| attr', source.attributes);
      console.log('  license:', await prepareLicense(a, source));
      // System archive opens: try fs type 1 FIRST (d37211c: system archive
      // NCAs are program-class content), then the data-class type 6 with the
      // ns promotion fallback (the Oct-25 17:01Z tzdata route). Carriers
      // differ in which one gates; take whichever opens.
      let storage;
      try {
        storage = await openRomfs(a, source, FS_TYPE_ROMFS);
        console.log('  opened as program class (fs type 1)');
      } catch (t1) {
        console.log('  type-1 refused: 0x' + ((t1.nativeResult?.canonical ?? t1.nativeResult?.raw ?? 0) >>> 0).toString(16), '— trying data class');
      }
      if (!storage) try {
        storage = await openRomfs(a, source, FS_TYPE_DATA_ROMFS);
      } catch (error) {
        if (error.nativeResult?.canonical !== 0x320002) throw error;
        console.log('  fsaccess gate — promoting the session identity to ns...');
        const rows = await sweepProgramIds(a);
        const ns = rows.find(r => r.programId.endsWith('0000001f'));
        check(ns, 'ns pid not found in the sweep');
        const oracle = await promoteIdentity(ns.pid);
        console.log('  promoted (oracle 0x' + oracle.toString(16) + ')');
        a.promoted = true;
        storage = await openRomfs(a, source, FS_TYPE_DATA_ROMFS);
      }
      const size = Number(await domain.storageSize(a.s, storage));
      console.log('  romfs IStorage:', storage, '| size:', size);
      const header = await filesystem.readStorage(a.s, storage, 0, 0x50);
      check(header.readBigUInt64LE(0) === 0x50n, 'unexpected RomFS header');
      console.log('  romfs header valid');
      if (!probe) {
        await dumpRomfs(a, storage, size, path.join(outRoot, 'archive-' + archive));
        await a.s.close(storage); a.handles = a.handles.filter(h => h !== storage);
      }
      console.log('archive phase done.');
    } else if (probe) {
      console.log('archive probe only.');
    }
    // control mount retry under the ns promotion (paths were queried natural)
    if (a.controlRetry) {
      const {appId: retryApp, source} = a.controlRetry;
      console.log('== control.nacp retry under ns for ' + retryApp + ' ==');
      await dumpControl(a, retryApp, source, path.join(outRoot, 'base'));
      a.controlRetry = null;
    }
    // restore the helper identity before the content stream (type-1 mounts as
    // ns risk the launch-auth block class)
    if (a.promoted) {
      const helper = 8;
      const oracle = await promoteIdentity(helper);
      console.log('identity restored (oracle 0x' + oracle.toString(16) + ')');
      a.promoted = false;
    }
    if (wantedContent === 'none') {console.log('content phase skipped.'); return;}
    if ((archive || control) && !wantedContentExplicit) {
      console.log('delivery phases complete (no content stream requested).');
      return;
    }
    // Standard per-game ledger: declared before all phases use it.
    const ledger = {game: appId, started: new Date().toISOString(), sections: {}};
    const sectionStatus = (label, section, value) => {
      (ledger.sections[label] ||= {})[section] = value;
      console.log('  [' + label + '][' + section + '] ' + (typeof value === 'string' ? value : JSON.stringify(value)));
    };
    // discovery
    const ncm = await a.service('ncm');
    const discovered = {base: null, updates: [], dlc: []};
    ledger.discovery = discovered;
    for (const storage of STORAGES) {
      let db = null;
      try {
        db = a.track(domain.oneHandle(success(
          await a.s.ipc('OpenContentMetaDatabase', ncm, 5, Buffer.from([storage])), 'OpenContentMetaDatabase')));
        if (!discovered.base) {
          const baseKeys = await listKeys(a, db, TYPE_APPLICATION, appId);
          if (baseKeys.length) {
            check(baseKeys.length === 1, 'multiple application keys for ' + appId);
            check(baseKeys[0].metaType === TYPE_APPLICATION, 'base key metaType mismatch');
            discovered.base = {...baseKeys[0], storage};
          }
        }
        for (const key of await listKeys(a, db, TYPE_UPDATE, appId)) {
          check(key.metaType === TYPE_UPDATE, 'update key metaType mismatch');
          discovered.updates.push({...key, storage});
        }
        for (const key of await listKeys(a, db, TYPE_DLC, appId)) discovered.dlc.push({...key, storage});
      } catch (error) {
        if (error.nativeResult?.canonical !== 0x21005) throw error;  // SD/gamecard DB not active = skip
      } finally {if (db) {await a.s.close(db); a.handles = a.handles.filter(h => h !== db);}}
      if (discovered.base && discovered.updates.length && discovered.dlc.length) break;
    }
    check(discovered.base, 'application ' + appId + ' not found in any storage');
    console.log('content: base v' + discovered.base.version +
      (discovered.updates.length ? ' | updates: ' + discovered.updates.map(k => k.id + ' v' + k.version + ' (s' + k.storage + ')').join(', ') : '') +
      (discovered.dlc.length ? ' | dlc: ' + discovered.dlc.map(k => k.id + ' v' + k.version + ' (s' + k.storage + ')').join(', ') : ''));

    // selection
    // ---- raw NCA phase (the standard emulator format) ----
    // LibHac/Ryujinx layers base+patch NCAs at open (OpenStorageWithPatch):
    // the standard deliverable is the NCA files themselves. Dump every
    // content NCA of base + updates (program/data/control), each into
    // <outRoot>/nca/<label>-<contenttype>.nca with its own manifest.
    if (wantedNca) {
      const ncaJobs = [];
      ncaJobs.push({key: discovered.base, label: 'base'});
      for (const key of discovered.updates) ncaJobs.push({key, label: 'update-v' + key.version});
      for (const job of ncaJobs) {
        for (const [typeName, contentType] of [['program', CONTENT_PROGRAM], ['data', CONTENT_DATA], ['control', 3]]) {
          const sectionId = job.label + '-' + typeName;
          try {
            const source = await resolveContent(a, job.key, job.key.storage, contentType);
            console.log('== nca ' + sectionId + ' ==');
            await dumpRawNca(a, source, path.join(outRoot, 'nca'), sectionId);
            sectionStatus(job.label, 'nca-' + typeName, 'ok ' + source.contentId);
          } catch (error) {
            // control/data may be absent per key (0xe05 not-found) — record, continue
            sectionStatus(job.label, 'nca-' + typeName, (String(error.message).match(/no .* content|0xe05/i) ?
              'absent' : 'error: ' + error.message.slice(0, 100)));
          }
        }
      }
    }

    const jobs = [];
    if (wantedContent === 'all' || wantedContent === 'base')
      jobs.push({label: 'base', key: discovered.base, contentType: CONTENT_PROGRAM, fsType: FS_TYPE_ROMFS, section: wantedSection});
    if (wantedContent === 'all' || wantedContent === 'update')
      for (const key of discovered.updates)
        jobs.push({label: 'update-v' + key.version, key, contentType: CONTENT_PROGRAM, fsType: FS_TYPE_ROMFS, original: discovered.base, section: wantedSection});
    if (wantedContent === 'all' || wantedContent === 'dlc')
      for (const key of discovered.dlc)
        jobs.push({label: 'dlc-' + key.id.slice(-6) + '-v' + key.version, key, contentType: CONTENT_DATA, fsType: FS_TYPE_DATA_ROMFS, section: wantedSection});

    // Resolved-source cache (per run dir): a transport bounce re-attaches and
    // re-runs this phase; resolving again would burn fresh ncm budget. Mount
    // with the saved source first; re-license only on NcaExternalKeyNotFound.
    const stateFile = path.join(outRoot, 'resolve-state.json');
    const loadState = () => fsSync.existsSync(stateFile) ? JSON.parse(fsSync.readFileSync(stateFile)) : {};
    const saveState = state => fsp.writeFile(stateFile, JSON.stringify(state, null, 2));
    const state = loadState();
    // Update-key control content: the update NCA set carries its own Control
    // (the base control.nacp lies about version/cache for updated titles —
    // the active control is the update's. Resolve type-3 content on the
    // update key, mount via cmd 10 (fsType 3), read /control.nacp.
    async function dumpUpdateControl(a, updateKey, appId, outDir) {
      const source = await resolveContent(a, updateKey, updateKey.storage, 3);
      console.log('  update control NCA:', source.contentId, source.contentPath, '| attr', source.attributes);
      // cmd 10 OpenFileSystemWithId: id = the OWNING APPLICATION tid (base
      // app id), NOT the update tid and NOT the content id — update-class
      // content resolves under its app's registration (live-proven: base
      // tid + type 3 opens the 4.4.9 update control; update tid -> 0x235e02).
      const pathBuffer = Buffer.alloc(0x301);
      pathBuffer.write(source.contentPath);
      const mountInput = Buffer.alloc(16);
      mountInput[0] = source.attributes;
      mountInput.writeUInt32LE(3, 4);
      mountInput.writeBigUInt64LE(BigInt('0x' + appId), 8);
      try {
        const opened = success(await a.pathApi.raw(a.root, 10, pathBuffer, mountInput), 'mount update control');
        const control = a.track(domain.oneHandle(opened));
        try {
          const file = success(await a.pathApi.normal(control, 8, '/control.nacp', u32(1)), 'open update control.nacp');
          const handle = a.track(domain.oneHandle(file));
          try {
            const size = Number(await filesystem.fileSize(a.s, handle));
            const nacp = await filesystem.readFile(a.s, handle, 0, size);
            await fsp.mkdir(outDir, {recursive: true});
            await fsp.writeFile(path.join(outDir, 'control.nacp'), nacp);
            const ver = nacp.toString('latin1').match(/\d+\.\d+\.\d+/);
            console.log('  update control.nacp:', size, 'bytes, version', ver ? ver[0] : '?', '->', path.join(outDir, 'control.nacp'));
          } finally {await a.s.close(handle); a.handles = a.handles.filter(h => h !== handle);}
        } finally {await a.s.close(control); a.handles = a.handles.filter(h => h !== control);}
        return;
      } catch (error) {
        // cmd-10 as the natural identity may hit the fsaccess gate for control
        // content of updates; cmd 206 type 6 (data-class mount) is the fallback.
        if (error.nativeResult?.canonical !== 0x320002) throw error;
        console.log('  cmd-10 gated — trying fs 206 data-class mount');
        const input = Buffer.alloc(8);
        input[0] = source.attributes;
        input.writeUInt32LE(FS_TYPE_DATA_ROMFS, 4);
        const reply = success(await a.pathApi.raw(a.root, 206, pathBuffer, input), 'mount update control via 206');
        const control = a.track(domain.oneHandle(reply));
        try {
          const size = Number(await domain.storageSize(a.s, control));
          // data-class mount returns IStorage over the control NCA romfs; the
          // control.nacp sits at the romfs data start in control NCAs — parse
          // the romfs tables and read /control.nacp properly
          const header = await filesystem.readStorage(a.s, control, 0, 0x50);
          check(header.readBigUInt64LE(0) === 0x50n, 'unexpected control romfs header');
          const dirs = await readTable(a, control, Number(header.readBigUInt64LE(24)), Number(header.readBigUInt64LE(32)), size);
          const files = await readTable(a, control, Number(header.readBigUInt64LE(56)), Number(header.readBigUInt64LE(64)), size);
          const tree = parseRomfs(dirs, files);
          const entry = tree.find(e => e.type === 'file' && e.path === '/control.nacp');
          check(entry, 'control.nacp not found in control romfs');
          const dataOffset = Number(header.readBigUInt64LE(72));
          const nacp = await filesystem.readStorage(a.s, control, dataOffset + entry.offset, entry.size);
          await fsp.mkdir(outDir, {recursive: true});
          await fsp.writeFile(path.join(outDir, 'control.nacp'), nacp);
          const ver = nacp.toString('latin1').match(/\d+\.\d+\.\d+/);
          console.log('  update control.nacp (via 206):', entry.size, 'bytes, version', ver ? ver[0] : '?', '->', path.join(outDir, 'control.nacp'));
        } finally {await a.s.close(control); a.handles = a.handles.filter(h => h !== control);}
      }
    }

    // Standard per-game ledger: every section records ok/blocked/error; one
    // failing section never kills the attach (budget) or the other sections.
    for (const job of jobs) {
      console.log('== ' + job.label + ' (' + job.contentType + ') ==');
      // base jobs: the base key may have no content records (the update owns
      // them). A 0xe05/ContentMetaNotFound here is a clean 'not present' —
      // skip the job rather than resolving another key's content.
      let source = state[job.label];
      let licensed = false;
      if (source) {
        // saved source: the mount itself is the license probe — leave
        // licensed=false so a 0x7d802 re-licenses (es key registration does
        // NOT persist across processes on this fw).
        console.log('  saved source:', source.contentPath, '| attr', source.attributes);
      } else {
        source = await resolveContent(a, job.key, job.key.storage, job.contentType);
        state[job.label] = source;
        await saveState(state);
        licensed = await prepareLicense(a, source);
        sectionStatus(job.label, 'content', {contentId: source.contentId, contentPath: source.contentPath});
        if (job.original) {
          const baseSource = await resolveContent(a, job.original, job.original.storage, CONTENT_PROGRAM);
          console.log('  base license (joint rights):', await prepareLicense(a, baseSource));
        }
        console.log('  content:', source.contentId, source.contentPath, '| attr', source.attributes,
          '| rights', source.rightsId.slice(0, 16), 'g' + source.generation);
        console.log('  license prepared:', licensed);
      }

      const mountOrLicense = async () => {
        try {
          return await openRomfs(a, source, job.fsType);
        } catch (error) {
          if (error.nativeResult?.canonical !== 0x7d802 || licensed) throw error;
          console.log('  key not registered — preparing license...');
          licensed = await prepareLicense(a, source);
          return openRomfs(a, source, job.fsType);
        }
      };

      if (job.key.metaType === TYPE_UPDATE) {
        try {
          await dumpUpdateControl(a, job.key, appId, path.join(outRoot, job.label));
          sectionStatus(job.label, 'control', 'ok');
        } catch (error) {
          sectionStatus(job.label, 'control', 'error: ' + error.message.slice(0, 120));
        }
      }
      if (wantedSection === 'all' || wantedSection === 'romfs') {
        try {
          const storage = await mountOrLicense();
          if (a.client && a.fsProcHandle) {
            try {
              const probe = await a.client.request(0x524f0016, a.fsProcHandle,
                [0, a.s.base + 0x6000, 0x1000, 1]);
              check(probe.result === 0, 'rig 0016 refused: 0x' + probe.result.toString(16));
              a.fastReader = a.fastReader(storage);
              a.fastReaderFor = storage;
              console.log('  fast path armed:', a.fastReader.maxChunk / 1024, 'KiB chunks');
            } catch (error) {
              // 0016 maps the SOURCE pages — type 3/4 (module) only; session
              // heap (type 5) is refused 0xd401 (the JrcXEE wall). The fast
              // path cannot serve heap-buffered RomFS reads: slide only.
              console.log('  fast path unavailable (', error.message.slice(0, 60), ') — slide path');
              a.fastReader = null;
            }
          }
          const size = Number(await domain.storageSize(a.s, storage));
          console.log('  romfs IStorage:', storage, '| size:', size, '(' + (size / 1024 ** 3).toFixed(3) + ' GiB)');
          const header = await filesystem.readStorage(a.s, storage, 0, 0x50);
          check(header.readBigUInt64LE(0) === 0x50n, 'unexpected RomFS header');
          console.log('  romfs header valid');
          if (probe) {await a.s.close(storage); a.handles = a.handles.filter(h => h !== storage); sectionStatus(job.label, 'romfs', 'probe-ok'); continue;}
          await dumpRomfs(a, storage, size, path.join(outRoot, job.label));
          await a.s.close(storage); a.handles = a.handles.filter(h => h !== storage);
          sectionStatus(job.label, 'romfs', 'ok');
        } catch (error) {
          const msg = error.message || String(error);
          if (/Storage read failed|read failed/i.test(msg) && job.key.metaType === TYPE_UPDATE) {
            // Known fw23 limitation: update NCAs expose only a partial delta
            // view through fs 206 (the composed tree is base+delta; only the
            // delta prefix is readable). The composed romfs comes from the
            // RUNNING-APP overlay (cmd 2) — see active-overlay/.
            sectionStatus(job.label, 'romfs', 'blocked: update delta view (composed romfs via active-overlay only)');
          } else {
            sectionStatus(job.label, 'romfs', 'error: ' + msg.slice(0, 150));
          }
        }
      }
      if (wantedSection === 'all' || wantedSection === 'exefs') {
        try {
          const codefs = await openCodefs(a, source, job.key.id);
          console.log('  CodeFS:', codefs);
          if (probe) {await a.s.close(codefs); a.handles = a.handles.filter(h => h !== codefs); sectionStatus(job.label, 'exefs', 'probe-ok'); continue;}
          const outDir = path.join(outRoot, job.label);
          const manifestFile = path.join(outDir, 'manifest-exefs.json');
          const manifest = fsSync.existsSync(manifestFile) ? JSON.parse(fsSync.readFileSync(manifestFile)) :
            {section: 'exefs', started: new Date().toISOString(), files: []};
          await walkCodefs(a, codefs, '/', outDir, manifest, new Map(manifest.files.map(f => [f.path, f])));
          await fsp.writeFile(manifestFile, JSON.stringify(manifest, null, 2));
          console.log('  exefs: done (' + manifest.files.length + ' files)');
          await s_close_exefs(a, codefs);
          sectionStatus(job.label, 'exefs', 'ok (' + manifest.files.length + ' files)');
        } catch (error) {
          sectionStatus(job.label, 'exefs', 'error: ' + (error.message || String(error)).slice(0, 150));
        }
      }
    }
    ledger.completed = new Date().toISOString();
    await fsp.mkdir(outRoot, {recursive: true});
    await fsp.writeFile(path.join(outRoot, 'game.json'), JSON.stringify(ledger, null, 2));
    console.log('game ledger -> ' + path.join(outRoot, 'game.json'));
    console.log('jobs complete.');
  } finally {
    // handles closed by the supervisor; keep the attach alive across jobs
  }
}
main().catch(e => {console.error('FAILED:', e.stack || e.message); process.exitCode = 1;});
