#!/usr/bin/env node
// MKW update RomFS (composed view) via the OunceCake route:
//   license base (es 503 + account dance) -> lr RegisterOwnedPatchLocation ->
//   composed CodeFS (ldr:ro cmd 0) -> read /main.npdm -> fs 810 program-index
//   map -> copyProgramRegistry (pair-swap) -> RegisterOwnedTemporaryProgramContext
//   (fake owner, game's own npdm access controls) -> spoof fresh fsp-srv domain
//   root owner fields -> fs cmd 200 (OpenDataStorageByCurrentProcess) ->
//   composed RomFS IStorage -> stream image + hash per-file extents ->
//   manifest-composed + manifest-delta vs base + LayeredFS overlay tree.
//
// Memory reads go through root-native-owned-fetch (the wave session's fast
// alias read, <=64 KiB per call); writes through the retained channel
// (expected + replacement, verified readback). Resume-safe: the image streams
// to romfs.img.part with a checkpoint at file-extent boundaries; SIGINT stops
// cleanly; rerun the same command to resume.
const path = require('node:path');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const crypto = require('node:crypto');

const latest = JSON.parse(fs.readFileSync(path.join(require('node:os').homedir(),
  'dev/ns2jb/latest-session.json')));
const SESSION = latest.session || path.basename(latest.directory.rstrip ? latest.directory : latest.directory);
const engine = path.join(latest.directory, 'switch2');
const {Session, live, u32, u64, check} = require(path.join(engine, 'app', 'session.cjs'));
const domain = require(path.join(engine, 'app', 'domain.cjs'));
const filesystem = require(path.join(engine, 'app', 'filesystem.cjs'));
const {paths} = require(path.join(engine, 'memory', 'paths.cjs'));
const fsMemory = require(path.join(engine, 'tools', 'fs-memory.cjs'));

const TITLE_ARG = process.argv.find(x => /^0?x?[0-9a-fA-F]{16}$/.test(x));
const BASE_TITLE = BigInt(TITLE_ARG ? '0x' + TITLE_ARG.replace(/^0x/, '') : '0400c3f00006e000');
let BASE_CONTENT_ID = null;   // resolved at runtime via NCM (program content id)
const TITLE_HEX = BASE_TITLE.toString(16).padStart(16, '0');
const OUT = path.join(require('node:os').homedir(),
  'dev/switch/roms', TITLE_HEX, 'update-romfs-composed');
const CHUNK = 0x400000;                   // 4 MiB bulk readStorage chunks (Session spans 33 MiB)

const success = (r, l) => {if (r.result) throw Error(l + ': 0x' + (Number(r.result) >>> 0).toString(16)); return r;};
const idBytes = v => {const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return b;};
const hex64 = v => '0x' + v.toString(16);

function packet(command, input) {
  const bytes = Buffer.alloc(256);
  bytes.writeUInt32LE(4);
  bytes.writeUInt32LE(Math.ceil((32 + input.length) / 4), 4);
  bytes.write('SFCI', 16);
  bytes.writeUInt32LE(command, 24);
  input.copy(bytes, 32);
  return bytes;
}
function fixedOutput(command, input, address, size) {
  const bytes = packet(command, input);
  const words = bytes.readUInt32LE(4) & 0x3ff;
  const at = 8 + words * 4;
  bytes.writeUInt32LE((bytes.readUInt32LE(4) | (3 << 10)) >>> 0, 4);
  bytes.writeUInt32LE(address >>> 0, at);
  bytes.writeUInt32LE((Math.floor(address / 2 ** 32) | (size << 16)) >>> 0, at + 4);
  return bytes;
}
function pathRequest(command, input, address, length = 0x301) {
  const bytes = packet(command, input);
  const pointer = BigInt(address);
  bytes.writeUInt32LE(4 | (1 << 16));
  bytes.writeUInt32LE(
    Number((BigInt(length) << 16n) | (((pointer >> 36n) & 7n) << 6n) | (((pointer >> 32n) & 15n) << 12n)), 8);
  bytes.writeUInt32LE(Number(pointer & 0xffffffffn), 12);
  return bytes;
}

// Heap memory channel: the retained two-cache interface (memory.read /
// memory.pointer / memory.write) — the SAME channel ro/layout.cjs validates the
// domain table with at acquisition. NO TIMEOUTS anywhere: a killed or timed-out
// mid-RPC client wedges the carrier (two freezes on 2026-10-26, both from
// retained reads of MODULE-TEXT addresses — the slide cannot alias RO pages
// and hangs the fs worker). Heap reads inside the recorded window are FAST
// (39 ms for a 0x30 row). Module-text reads MUST use fs-region-read (the
// boot-proven read-helper -> scratch -> session-fetch path). Never retained-
// read text; never bulk retained-read (60 s tool socket deadline).
const fastMemory = memory => ({
  read: memory.read.bind(memory),
  write: memory.write.bind(memory),
  u32: memory.u32.bind(memory),
  u64: memory.u64.bind(memory),
  pointer: memory.pointer.bind(memory),
});

// ---- access controls from the composed main.npdm (OunceCake accessControls) ----
function accessControls(bytes, title) {
  const region = (at, size) => bytes.subarray(at, at + size);
  const aci = region(bytes.readUInt32LE(0x70), bytes.readUInt32LE(0x74));
  const acid = region(bytes.readUInt32LE(0x78), bytes.readUInt32LE(0x7c));
  const header =
    acid.toString('ascii', 0x200, 0x204) === 'ACID' ? 0x200 :
    acid.length >= 0x340 && acid.toString('ascii', 0x300, 0x304) === 'ACID' ? 0x300 : -1;
  check(header > 0, 'ACID header not found in main.npdm');
  const control = (parent, field) => {
    const at = parent.readUInt32LE(field), size = parent.readUInt32LE(field + 4);
    return Buffer.from(parent.subarray(at, at + size));
  };
  const fah = control(aci, 0x20);
  const fac = control(acid, header + 0x20);
  check(fah.length >= 0x1c && fac.length >= 0x2c, 'Access control sizes too small');
  return {fah, fac};
}

(async () => {
  const stopping = {flag: false};
  const STOP = Symbol('stop');
  process.on('SIGINT', () => {if (stopping.flag) process.exit(1); stopping.flag = true;});
  await fsp.mkdir(OUT, {recursive: true});

  const s = new Session('mkwupdromfs-' + Date.now(), 0x2100000);
  s.bulkDownloads = true;                       // 4 MiB readStorage via the RPC transfer path
  s.record = async () => {};
  await s.initialize();
  const memory = await fsMemory.connect();
  const mem = fastMemory(memory);
  const nativeInfo = await memory.request({command: 'root-native-info'});
  const smHandle = (nativeInfo.services || []).find(x => x.sm)?.sm;
  check(smHandle, 'No sm handle in the monitor services');
  const openService = async name => {
    try {
      const handle = await s.openService(name);
      if (handle > 0) return handle;
    } catch (e) {}
    const pkt = Buffer.alloc(256);
    pkt.writeUInt32LE(0x11); pkt.writeUInt32LE(2, 4); pkt.write(name, 8);
    await s.write(s.base, pkt);
    const transport = await s.call('send', s.base, 4096, smHandle);
    check(!transport, 'sm transport failed for ' + name);
    const reply = await s.readOwned(s.base, 256);
    let at = 8, count = 0, handle;
    if (reply.readUInt32LE(4) >>> 31) {
      const special = reply.readUInt32LE(at); at += 4;
      count = (special >>> 5) & 15;
      if (count) {handle = reply.readUInt32LE(at); at += 4; s.handles.add(handle);}
    }
    const result = reply.readUInt32LE(at) >>> 0;
    check(!result && count === 1 && handle > 0,
      'sm open ' + name + ': 0x' + (result & 0x3fffff).toString(16));
    return handle;
  };
  const openDomain = async label => {
    const handle = await openService('fsp-srv');
    success(await s.ipc(label + ' SetCurrentProcess', handle, 1, u64(0), {pid: true}),
      label + ' SetCurrentProcess');
    const reply = success(await domain.send(s, label + ' ConvertToDomain', handle,
      domain.wire.control(0)), label + ' ConvertToDomain');
    return {label, handle, root: reply.data.readUInt32LE()};
  };

  const layout = JSON.parse(await fsp.readFile(
    path.join(engine, 'ro', SESSION + '-layout.json')));
  check(layout.rootVptr && layout.table && layout.count === 16384, 'Layout unusable');
  const text = layout.rootVptr - 0x2b1420;
  console.log('layout | rootVptr:', hex64(layout.rootVptr), '| text:', hex64(text));

  // ---- fast-memory pre-flight ----
  const t0 = Date.now();
  const probeRow = await mem.read(layout.table, 0x30);
  check(probeRow.length === 0x30, 'Table probe failed');
  console.log('memory pre-flight | table row ok in', Date.now() - t0, 'ms |',
    'entry +0x28:', hex64(probeRow.readBigUInt64LE(0x28)));

  // ---- resolve the base PROGRAM content id via NCM (title arg) ----
  {
    const ncm0 = await openService('ncm');
    const db0 = domain.oneHandle(success(await s.ipc('OpenContentMetaDatabase', ncm0, 5, Buffer.from([4])),
      'Open DB'));
    try {
      const latest = success(await s.ipc('GetLatestContentMetaKey', db0, 6, idBytes(BASE_TITLE)),
        'GetLatestContentMetaKey');
      const key = Buffer.from(latest.data.subarray(0, 16));
      const typeInput = Buffer.alloc(24);
      typeInput[0] = 1;                    // ContentType::Program
      key.copy(typeInput, 8);
      BASE_CONTENT_ID = success(await s.ipc('GetContentIdByType', db0, 3, typeInput), 'GetContentIdByType')
        .data.subarray(0, 16).toString('hex');
      console.log('base program content id:', BASE_CONTENT_ID);
    } finally {await s.close(db0);}
    check(BASE_CONTENT_ID && BASE_CONTENT_ID.length === 32, 'program content id resolution failed');
  }

  // ---- 1. license the base ----
  console.log('licensing: opening ncm...');
  const ncm = await openService('ncm');
  console.log('ncm:', ncm);
  const storeReply = success(await s.ipc('OpenContentStorage', ncm, 4, Buffer.from([4])), 'OpenContentStorage');
  const store = domain.oneHandle(storeReply);
  let rights, generation;
  try {
    // attributes come from GetContentInfoByType (db cmd 24) — attr!=1 rights lookups
    // fail 0x1fb402 on TOTK (title-specific NCA attributes); game-dump's shape.
    const db1 = domain.oneHandle(success(await s.ipc('OpenContentMetaDatabase', ncm, 5, Buffer.from([4])),
      'Open DB for info'));
    let attr = 1;
    try {
      const latest = success(await s.ipc('GetLatestContentMetaKey', db1, 6, idBytes(BASE_TITLE)),
        'GetLatestContentMetaKey');
      const key = Buffer.from(latest.data.subarray(0, 16));
      const infoInput = Buffer.alloc(24);
      infoInput[0] = 1;
      key.copy(infoInput, 8);
      const info = success(await s.ipc('GetContentInfoByType', db1, 24, infoInput), 'GetContentInfoByType').data;
      attr = info[21] & 15;
      console.log('base program attributes:', attr);
    } finally {await s.close(db1);}
    const rightsInput = Buffer.concat([Buffer.from(BASE_CONTENT_ID, 'hex'), Buffer.from([attr])]);
    const rr = success(await s.ipc('GetContentRightsId', store, 20, rightsInput), 'GetContentRightsId');
    rights = Buffer.from(rr.data.subarray(0, 16));
    generation = rr.data[16] ?? 0;
  } finally {await s.close(store);}
  check(!rights.equals(Buffer.alloc(16)), 'No rights id on the base content');
  console.log('base rights:', rights.toString('hex'), '| gen:', generation);
  const es = await openService('es');
  const prep = async () => {
    await s.write(s.base + 0x5200, rights);
    await s.write(s.base + 0x5300, u32(generation));
    return s.ipc('Prepare installed title license', es, 503, Buffer.alloc(0),
      {send: [{address: s.base + 0x5200, size: 16, mode: 0}, {address: s.base + 0x5300, size: 4, mode: 0}]});
  };
  let lic = await prep();
  let ctxHandle = null;
  if ([0x1491, 0x691].includes(Number(lic.result) & 0x3fffff)) {
    const opened = success(await s.ipc('Create export rights context', es, 2001), 'es 2001');
    ctxHandle = domain.oneHandle(opened);
    const rightsApp = Buffer.alloc(8);
    rightsApp.writeBigUInt64LE(rights.readBigUInt64BE(), 0);
    await s.write(s.base + 0x3200, rightsApp);
    success(await s.ipc('Select export title rights', ctxHandle, 2, Buffer.alloc(0),
      {send: [{address: s.base + 0x3200, size: 8, mode: 0}]}), 'ctx 2');
    const selectAccounts = () => s.ipc('Request account rights', ctxHandle, 17, Buffer.from([1]),
      {send: [{address: s.base + 0x3200, size: 8, mode: 0}, {address: s.base + 0x3400, size: 8, mode: 0}]});
    success(await selectAccounts(), 'ctx 17');
    success(await s.ipc('Evaluate', ctxHandle, 3), 'ctx 3');
    lic = await prep();
    if ([0x1491, 0x691].includes(Number(lic.result) & 0x3fffff)) {
      const acc = await openService('acc:su');
      const address = s.base + 0x3600, bytes = 8 * 16;
      await s.write(address, Buffer.alloc(bytes));
      const listPacket = fixedOutput(2, Buffer.alloc(2), address, bytes);
      listPacket.writeUInt16LE(bytes, 40);
      success(await domain.send(s, 'List local users', acc, listPacket), 'ListUsers');
      const output = await s.readOwned(address, bytes);
      const accounts = [];
      for (let at = 0; at < bytes; at += 16) {
        const user = output.subarray(at, at + 16);
        if (user.equals(Buffer.alloc(16))) continue;
        const opened2 = await s.ipc('Open account', acc, 102, user);
        if (opened2.result) continue;
        const mgr = domain.oneHandle(opened2);
        try {
          const linked = await s.ipc('Get linked', mgr, 120);
          if (!linked.result) {
            const id = Buffer.from(linked.data.subarray(0, 8));
            if (!id.equals(Buffer.alloc(8)) && !accounts.some(o => o.equals(id))) accounts.push(id);
          }
        } finally {await s.close(mgr);}
      }
      check(accounts.length, 'No linked accounts found');
      await s.write(s.base + 0x3400, Buffer.concat(accounts));
      success(await s.ipc('Select account rights', ctxHandle, 1, Buffer.from([0]),
        {send: [{address: s.base + 0x3400, size: accounts.length * 8, mode: 0}]}), 'ctx 1');
      success(await selectAccounts(), 'ctx 17b');
      success(await s.ipc('Evaluate 2', ctxHandle, 3), 'ctx 3b');
      lic = await prep();
    }
  }
  check(!lic.result, 'Base license failed: 0x' + (Number(lic.result) >>> 0).toString(16));
  console.log('BASE LICENSE OK');

  // ---- 2. lr original + registered resolvers, register the patch ----
  const proof = JSON.parse(await fsp.readFile(path.join(engine, 'ro', 'root', 'current-root.json')));
  const root = domain.oneHandle(success(await domain.send(s, 'clone root', proof.rootHandle,
    domain.wire.control(2)), 'clone root'));
  const pathApi = paths(s, domain);
  const lr = await openService('lr');
  const original = domain.oneHandle(success(await s.ipc('Open original resolver', lr, 0, Buffer.from([4])), 'lr 0'));
  const registered = domain.oneHandle(success(await s.ipc('Open registered resolver', lr, 1), 'lr 1'));
  const readLocation = async (resolver, programId, label) => {
    const address = s.base + 0x3800, size = 0x300;
    const reply = await domain.send(s, 'Resolve ' + label, resolver,
      fixedOutput(0, idBytes(programId), address, size));
    if ([0x408, 0x1408].includes(Number(reply.result) & 0x3fffff)) return null;
    check(!reply.result, 'Resolve ' + label + ': 0x' + (Number(reply.result) >>> 0).toString(16));
    const b = await s.readOwned(address, size);
    const end = b.indexOf(0);
    return {contentPath: b.subarray(0, end).toString('utf8'),
      attributes: reply.data.subarray(0, 16).toString('hex')};
  };
  const baseLoc = await readLocation(original, BASE_TITLE, 'base');
  check(baseLoc, 'Base location not resolved');
  const UPDATE_TITLE = BASE_TITLE | 0x800n;   // update tid = base | 0x800
  const patchLoc = await readLocation(original, UPDATE_TITLE, 'update');
  check(patchLoc, 'Update location not resolved');
  console.log('base loc:', baseLoc.contentPath);
  console.log('patch loc:', patchLoc.contentPath);

  const pathBuffer = Buffer.alloc(0x301);
  pathBuffer.write(patchLoc.contentPath);
  const identity = success(await pathApi.raw(root, 618, pathBuffer, Buffer.from([1])), '618');
  const runtimeId = identity.data.readBigUInt64LE(0);
  check(runtimeId > 0n, 'Runtime id resolution failed');
  console.log('runtime id:', hex64(runtimeId));
  // ---- armed-state bookkeeping (see below) ----
  // The route arms console state (patch location + fake program context)
  // that only section 9 disarms. A run that dies mid-way leaves it armed,
  // and same-boot retries ACCUMULATE it (GzUvcX: three armed contexts wedged
  // the fs worker on the third composed open). So: record every armed piece
  // in dump-state.json at the moment it arms, and REMOVE the stale pieces
  // (by the recorded values) before arming new ones.
  const statePath = path.join(OUT, 'dump-state.json');
  const readState = async () => fs.existsSync(statePath) ?
    JSON.parse(await fsp.readFile(statePath)) : {};
  const writeState = async extra => {
    const state = {...await readState(), ...extra, at: new Date().toISOString()};
    await fsp.writeFile(statePath, JSON.stringify(state, null, 2));
  };
  const armState = await readState();
  // stale patch cleanup (same runtime id -> the same location re-registers)
  if (armState.patch && armState.runtimeId === runtimeId.toString()) {
    await s.ipc('Remove stale owned patch location', registered, 2, idBytes(runtimeId))
      .then(() => console.log('stale patch removed'))
      .catch(() => console.log('stale patch remove refused (tolerated)'));
  }
  const regInput = Buffer.alloc(32);
  idBytes(runtimeId).copy(regInput, 0);
  idBytes(BASE_TITLE).copy(regInput, 8);
  Buffer.from(patchLoc.attributes, 'hex').copy(regInput, 16);
  const pathAddr = s.base + 0x4000;
  const filename = Buffer.alloc(0x300);
  filename.write(patchLoc.contentPath);
  await s.write(pathAddr, filename);
  success(await domain.send(s, 'Register owned patch location', registered,
    pathRequest(1, regInput, pathAddr, 0x300)), 'Register patch');
  console.log('PATCH REGISTERED');
  await writeState({patch: true, runtimeId: runtimeId.toString(), imageOffset: 0, hashed: 0});

  // ---- 5. program registry: interface copy via capture scan ----
  // (registry-manager walk skipped — same build-specific-offset reason; the
  // pair-swap below needs only the DOMAIN TABLE, which is heap and captured.)

  // find the registry interface entry: scan the ACQUISITION CAPTURE offline
  // (free) for rows with ptr(+0x28) == rootVptr + 0x5888, then verify the ONE
  // candidate live (a 0x30 retained read — 39 ms). Never bulk-read the table:
  // a 768 KiB slide read would outlive the tool's 60 s deadline -> carrier wedge.
  const captureInfo = layout.range;
  const captureBytes = await fsp.readFile(captureInfo.outputFile);
  check(captureBytes.length === captureInfo.length &&
    crypto.createHash('sha256').update(captureBytes).digest('hex') === captureInfo.sha256,
    'Acquisition capture hash differs');
  const captureTable = captureBytes.subarray(layout.table - captureInfo.address,
    layout.table - captureInfo.address + layout.count * 0x30);
  const candidates = [];
  for (let at = 0; at + 0x30 <= captureTable.length; at += 0x30) {
    if (captureTable.readBigUInt64LE(at + 0x28) !== BigInt(layout.rootVptr) + 0x5888n) continue;
    candidates.push({entry: layout.table + at, domain: Number(captureTable.readBigUInt64LE(at + 0x18)),
      object: Number(captureTable.readBigUInt64LE(at + 0x20)),
      pair: captureTable.subarray(at + 0x20, at + 0x30).toString('hex')});
  }
  check(candidates.length >= 1, 'No registry interface row found in the capture');
  let source = null;
  for (const cand of candidates) {
    const live = await mem.read(cand.entry, 0x30);      // fast retained verify
    if (live.readBigUInt64LE(0x28) !== BigInt(layout.rootVptr) + 0x5888n) continue;
    if (live.readBigUInt64LE(0x18) !== BigInt(cand.domain) ||
        live.readBigUInt64LE(0x20) !== BigInt(cand.object)) continue;
    source = {...cand, pair: live.subarray(0x20).toString('hex')};
    break;
  }
  check(source, 'Registry interface entry not found in the domain table');
  const ifaceHeader = await mem.read(source.object, 0x18);
  console.log('registry interface | entry:', hex64(source.entry), '| identity:',
    ifaceHeader.subarray(0, 16).toString('hex'), '| refs:', ifaceHeader.readUInt32LE(16));

  // pair-swap: expose the registry interface through an auxiliary domain slot
  const auxiliary = await openDomain('Owned registry reference');
  let swapped = false, registryHandle = null;
  try {
    const auxEntry = layout.table + (auxiliary.root - 1) * 0x30;
    const b = await mem.read(auxEntry, 0x30);
    const originalPair = b.subarray(0x20);
    swapped = true;
    await mem.write(auxEntry + 0x20, originalPair, Buffer.from(source.pair, 'hex'));
    let copied = null;
    try {
      copied = success(await domain.send(s, 'Copy existing native program registry',
        auxiliary.handle, domain.wire.control(1, u32(auxiliary.root))), 'Copy registry');
    } finally {
      // restore the auxiliary slot (expected = what we wrote, replacement = original)
      const current = await mem.read(auxEntry + 0x20, 16);
      if (!current.equals(originalPair)) await mem.write(auxEntry + 0x20, current, originalPair);
      swapped = false;
    }
    registryHandle = domain.oneHandle(copied);
    console.log('REGISTRY SESSION:', registryHandle);
  } finally {
    if (swapped) {
      const auxEntry = layout.table + (auxiliary.root - 1) * 0x30;
      const current = await mem.read(auxEntry + 0x20, 16);
      const b = await mem.read(auxEntry, 0x30);
      await mem.write(auxEntry + 0x20, current, b.subarray(0x20)).catch(() => {});
    }
    await s.close(auxiliary.handle).catch(() => {});
  }
  if (!registryHandle) throw Error('Registry copy failed');

  // ---- 5.5 stale context cleanup (armed by a previous failed run) ----
  if (armState.owner) {
    const stale = BigInt(armState.owner);
    await s.ipc('Remove stale owned temporary program context', registryHandle, 1, u64(stale))
      .then(() => console.log('stale context removed | owner:', hex64(stale)))
      .catch(() => console.log('stale context remove refused (tolerated)'));
    await writeState({owner: null, imageOffset: 0, hashed: 0});
  }


  // ---- 3. composed CodeFS + /main.npdm policy ----
  const roDir = path.join(engine, 'ro');
  const loaderFile = fs.readdirSync(roDir).filter(f => f.endsWith('-loader-root-copy.json')).pop();
  const loaderEv = JSON.parse(await fsp.readFile(path.join(roDir, loaderFile)));
  const loader = domain.oneHandle(success(await domain.send(s, 'clone loader', loaderEv.copy.handle,
    domain.wire.control(2)), 'clone loader'));
  const patchAttrs = parseInt(patchLoc.attributes.slice(0, 2), 16);
  const mountInput = Buffer.alloc(16);
  mountInput[0] = patchAttrs; mountInput[1] = 4;
  mountInput.writeBigUInt64LE(runtimeId, 8);
  const codeReply = await s.ipc('Open composed CodeFS', loader, 0, mountInput,
    {receive: [{address: s.base + 0x5000, size: 0x1a4, mode: 0}]});
  check(!codeReply.result, 'Composed CodeFS refused: 0x' + (Number(codeReply.result) >>> 0).toString(16));
  const codefs = domain.oneHandle(codeReply);
  console.log('COMPOSED CODEFS:', codefs);
  const npdmOpen = success(await pathApi.normal(codefs, 8, '/main.npdm', u32(1)), 'open main.npdm');
  const npdmHandle = domain.oneHandle(npdmOpen);
  let policy;
  try {
    const size = Number((await s.ipc('npdm size', npdmHandle, 4)).data.readBigUInt64LE());
    check(size > 0x100 && size < 0x10000, 'npdm size odd: ' + size);
    const parts = [];
    for (let at = 0; at < size; at += 0x8000) {
      const take = Math.min(0x8000, size - at);
      const rr = await s.ipc('npdm read', npdmHandle, 0, Buffer.concat([u64(0), u64(at), u64(take)]),
        {receive: [{address: s.base + 0x6000, size: take, mode: 1}]});
      success(rr, 'npdm read');
      parts.push(await s.readOwned(s.base + 0x6000, take));
    }
    policy = Buffer.concat(parts);
    console.log('main.npdm:', policy.length, 'bytes');
  } finally {await s.close(npdmHandle);}
  const {fah: gameFah, fac: gameFac} = accessControls(policy, runtimeId);
  let fah = gameFah, fac = gameFac;
  if (process.env.ARCHIVE_NPDM) {
    // FAH-source override: register the context with another program's
    // access controls (the ns FAH carries system-content data rights that
    // the game FAH lacks — the 2026-10-27 decode: the spoofed context
    // determines the 206 mask byte, and the game context flips it to the
    // host flow which cannot open @SystemContent).
    const npdmPath = process.env.ARCHIVE_NPDM;
    const nsNpdm = await fsp.readFile(npdmPath);
    const nsControls = accessControls(nsNpdm, runtimeId);
    fah = nsControls.fah; fac = nsControls.fac;
    console.log('ARCHIVE_NPDM override:', npdmPath, '| fah:', fah.length, 'B | fac:', fac.length, 'B');
  }
  console.log('access controls | fah:', fah.length, 'B | fac:', fac.length, 'B');

  // ---- 4. (skipped) program-index map (fs 810) ----
  // The fs-810 map walk needs the map-manager global slot (OunceCake:
  // text+0x11e11d8) — a MODULE-DATA offset that is fs-build-specific, and on
  // OUR build that VA is unmapped (ladder-2 wedge). Registering blind would
  // REPLACE the whole map (their register sends the full row set) without a
  // restore snapshot — skip it and test cmd 200 bare. If cmd 200 needs the
  // mapping, deriving OUR map-manager offset is RE work (rpc.query-enumerate
  // the fs data segment, scan for manager-shaped globals) — a separate task.
  console.log('fs-810 map: SKIPPED (build-specific module offset; cmd 200 tested bare)');

  // ---- 6. fake program context ----
  const owner = 0xf000000000000000n | BigInt('0x' + crypto.randomBytes(7).toString('hex'));
  console.log('fake owner:', hex64(owner));
  await s.write(s.base + 0x8000, fah);
  await s.write(s.base + 0xc000, fac);
  const ctxInput = Buffer.alloc(40);
  ctxInput[0] = 4;
  ctxInput.writeBigUInt64LE(owner, 8);
  idBytes(runtimeId).copy(ctxInput, 16);
  ctxInput.writeBigUInt64LE(BigInt(fah.length), 24);
  ctxInput.writeBigUInt64LE(BigInt(fac.length), 32);
  success(await s.ipc('Register owned temporary program context', registryHandle, 0, ctxInput,
    {send: [{address: s.base + 0x8000, size: fah.length, mode: 0},
      {address: s.base + 0xc000, size: fac.length, mode: 0}]}), 'Register program context');
  // No post-registration walk (the registry-manager slot is build-specific —
  // see step 5); the Remove cleanup below only needs the owner value.
  console.log('PROGRAM CONTEXT REGISTERED (fire-and-forget) | owner:', hex64(owner));
  let contextRegistered = true;
  await writeState({owner: owner.toString()});

  // ---- 6.5 ARCHIVE MODE: dump system data archives through the licensed,
  // spoofed session (the 2026-10-27 decode: the context register needs the
  // full route prelude — license + patch; a bare register refuses 0x320002.
  // The context carries the game NPDM rights; the ARCHIVE opens ride the
  // same spoofed domain + fs 206 type-1). ----
  const ARCHIVES = [];
  {
    const invPath = '/tmp/sysarch-inventory.json';
    if (process.argv.includes('--archives')) {
      ARCHIVES.push(...JSON.parse(fs.readFileSync(invPath)));
    } else if (process.argv.includes('--archive')) {
      const tid = process.argv[process.argv.indexOf('--archive') + 1];
      const arch = JSON.parse(fs.readFileSync(invPath)).find(a => a.title === tid);
      check(arch, 'archive ' + tid + ' not in the inventory');
      ARCHIVES.push(arch);
    }
  }
  if (ARCHIVES.length) {
    const OUTROOT = path.join(require('node:os').homedir(), 'dev/switch/dumps/fw23-archives');
    const archClient = await openDomain('Owned archive program FS');
    let archSpoof = null;
    try {
      const clientEntry = layout.table + (archClient.root - 1) * 0x30;
      const b = await mem.read(clientEntry, 0x30);
      const rootObj = Number(b.readBigUInt64LE(0x20));
      const h = await mem.read(rootObj, 0x40);
      const nca = Number(h.readBigUInt64LE(0x10));
      const n = await mem.read(nca, 0x30);
      archSpoof = [
        {address: rootObj + 0x30, original: h.subarray(0x30, 0x38)},
        {address: nca + 0x20, original: n.subarray(0x20, 0x28)},
      ];
      for (const field of archSpoof) await mem.write(field.address, field.original, u64(owner));
      console.log('archive spoof | domain root:', archClient.root);
      const {pathPacket} = require(path.join(engine, 'memory', 'paths.cjs'));
      const openArchive = async arch => {
        const contentPath = '@SystemContent://registered/' + arch.contentId + '.nca';
        for (const type of [1, 6]) {
          const pb = Buffer.alloc(0x301);
          pb.write(contentPath);
          await s.write(s.base + 0x4000, pb);
          const input = Buffer.alloc(8);
          input[0] = arch.attributes;
          input.writeUInt32LE(type, 4);
          const bytes = pathPacket(206, input, s.base + 0x4000, 0x301);
          const first = bytes.readUInt32LE(), second = bytes.readUInt32LE(4);
          let ds = 8;
          if (second >>> 31) {
            const special = bytes.readUInt32LE(ds);
            ds += 4 + (special & 1 ? 8 : 0);
            ds += 4 * ((special >>> 1 & 15) + (special >>> 5 & 15));
          }
          ds += (first >>> 16 & 15) * 8;
          ds += ((first >>> 20 & 15) + (first >>> 24 & 15) + (first >>> 28 & 15)) * 12;
          ds = (ds + 15) & ~15;
          bytes.copy(bytes, ds + 16, ds, ds + 16 + input.length);
          bytes.fill(0, ds, ds + 16);
          bytes[ds] = 1;
          bytes.writeUInt16LE(16 + input.length, ds + 2);
          bytes.writeUInt32LE(archClient.root, ds + 4);
          bytes.writeUInt32LE(0, ds + 12);
          bytes.writeUInt32LE(0, ds + 20);
          bytes.writeUInt32LE((bytes.readUInt32LE() & 0xffff0000 | 4) >>> 0);
          bytes.writeUInt32LE((bytes.readUInt32LE(4) + 4) >>> 0, 4);
          const reply = await domain.send(s, 'Archive 206 type-' + type, archClient.handle, bytes, {domain: true});
          if (!reply.result) return {type, storage: domain.oneHandle(reply)};
          console.log('  type-' + type, 'refused 0x' + (Number(reply.result) >>> 0).toString(16),
            '(canonical 0x' + (Number(reply.result) & 0x3fffff).toString(16) + ')');
        }
        return null;
      };
      let ok = 0, failed = 0;
      for (const [i, arch] of ARCHIVES.entries()) {
        const label = arch.title + ' v' + arch.version;
        const outDir = path.join(OUTROOT, arch.title);
        const manifestPath = path.join(outDir, 'manifest.json');
        let manifest = null;
        try {manifest = JSON.parse(await fsp.readFile(manifestPath));} catch {}
        const res = await openArchive(arch);
        if (!res) {console.log('==', label, '== REFUSED'); failed++; continue;}
        const storage = res.storage;
        try {
          const size = Number(await domain.storageSize(s, storage));
          console.log('==', label, '== type-' + res.type, '| size', size);
          manifest = {title: arch.title, version: arch.version, contentId: arch.contentId,
            attributes: arch.attributes, started: new Date().toISOString(), files: []};
          const head = await filesystem.readStorage(s, storage, 0, 0x50);
          check(head.readBigUInt64LE(0) === 0x50n, 'bad romfs header ' + label);
          const h = Array.from({length: 10}, (_, k) => head.readBigUInt64LE(k * 8));
          const dataOffset = Number(h[9]);
          const dirBytes = await filesystem.readStorage(s, storage, Number(h[3]), Number(h[4]));
          const fileBytes = await filesystem.readStorage(s, storage, Number(h[7]), Number(h[8]));
          const NONE = 0xffffffff;
          const files = [];
          const walkDir = (offset, prefix) => {
            let file = dirBytes.readUInt32LE(offset + 12);
            while (file !== NONE) {
              const e = fileBytes.subarray(file, file + 32);
              const len = e.readUInt32LE(28);
              const name = fileBytes.subarray(file + 32, file + 32 + len).toString('utf8');
              files.push({path: prefix + name, offset: Number(e.readBigUInt64LE(8)), size: Number(e.readBigUInt64LE(16))});
              file = e.readUInt32LE(4);
            }
            let child = dirBytes.readUInt32LE(offset + 8);
            while (child !== NONE) {
              const e = dirBytes.subarray(child, child + 32);
              const len = e.readUInt32LE(28);
              const name = dirBytes.subarray(child + 32, child + 32 + len).toString('utf8');
              walkDir(child, prefix + name + '/');
              child = e.readUInt32LE(4);
            }
          };
          walkDir(0, '/');
          console.log('  files:', files.length);
          for (const [j, f] of files.entries()) {
            const target = path.join(outDir, 'archive', f.path);
            await fsp.mkdir(path.dirname(target), {recursive: true});
            const hash = crypto.createHash('sha256');
            const out = await fsp.open(target, 'w');
            try {
              for (let at = 0; at < f.size; at += 0x100000) {
                const take = Math.min(0x100000, f.size - at);
                const chunk = await filesystem.readStorage(s, storage, dataOffset + f.offset + at, take);
                hash.update(chunk);
                await out.write(chunk, 0, take, at);
              }
            } finally {await out.close();}
            manifest.files.push({path: f.path, size: f.size, sha256: hash.digest('hex')});
            if (j % 50 === 49) console.log('   ', j + 1, '/', files.length, 'files');
          }
          manifest.completed = new Date().toISOString();
          await fsp.writeFile(manifestPath, JSON.stringify(manifest, null, 2));
          ok++;
          console.log('==', label, '== DONE', files.length, 'files ->', outDir);
        } finally {await s.close(storage).catch(() => {});}
        if (i + 1 < ARCHIVES.length) await new Promise(r => setTimeout(r, Number(process.env.SYSARCH_COOLDOWN_MS ?? 4000)));
      }
      console.log('ARCHIVE MODE DONE:', ok, 'ok /', failed, 'refused');
    } finally {
      if (archSpoof) for (const field of [...archSpoof].reverse()) {
        const current = await mem.read(field.address, 8);
        if (!current.equals(field.original)) await mem.write(field.address, current, field.original);
      }
      await s.close(archClient.handle).catch(() => {});
    }
  } else {
  // ---- 7. spoof a fresh fsp-srv domain + fs cmd 200 ----
  const client = await openDomain('Owned update program FS');
  let spoofFields = null, storageHandle = null;
  try {
    const clientEntry = layout.table + (client.root - 1) * 0x30;
    const b = await mem.read(clientEntry, 0x30);
    const rootObj = Number(b.readBigUInt64LE(0x20));
    const h = await mem.read(rootObj, 0x40);
    const nca = Number(h.readBigUInt64LE(0x10));
    const n = await mem.read(nca, 0x30);
    spoofFields = [
      {object: rootObj, address: rootObj + 0x30, original: h.subarray(0x30, 0x38)},
      {object: nca, address: nca + 0x20, original: n.subarray(0x20, 0x28)},
    ];
    for (const field of spoofFields)
      await mem.write(field.address, field.original, u64(owner));
    const reply = success(await domain.send(s, 'Open composed current-program RomFS',
      client.handle, domain.wire.domain(client.root, 200), {domain: true}), 'fs cmd 200');
    check(reply.objects.length === 1, 'cmd 200 did not return one storage object');
    const copied = success(await domain.send(s, 'Copy composed program storage',
      client.handle, domain.wire.control(1, u32(reply.objects[0]))), 'Copy storage');
    storageHandle = domain.oneHandle(copied);
    console.log('COMPOSED ROMFS STORAGE:', storageHandle);
  } finally {
    if (spoofFields) for (const field of [...spoofFields].reverse()) {
      const current = await mem.read(field.address, 8);
      if (!current.equals(field.original)) await mem.write(field.address, current, field.original);
    }
    await s.close(client.handle).catch(() => {});
  }
  if (!storageHandle) throw Error('Composed storage open failed');

  // ---- 8. stream the composed image ----
  const size = Number(await filesystem.fileSize(s, storageHandle));
  check(size > 0x10000 && size < 0x800000000, 'Composed romfs size odd: ' + size);
  console.log('composed romfs size:', (size / 2 ** 30).toFixed(3), 'GiB (' + size + ' B)');
  const chunkedRead = async (offset, length) => {
    check(length <= 0x4000000, 'Table read too large');
    const parts = [];
    for (let at = 0; at < length; at += 0x40000)
      parts.push(await filesystem.readStorage(s, storageHandle, offset + at, Math.min(0x40000, length - at)));
    return Buffer.concat(parts);
  };
  const head = await filesystem.readStorage(s, storageHandle, 0, 0x50);
  const h = Array.from({length: 10}, (_, i) => head.readBigUInt64LE(i * 8));
  check(h[0] === 0x50n, 'RomFS header magic mismatch');
  const dataOffset = Number(h[9]);
  const dirBytes = await chunkedRead(Number(h[3]), Number(h[4]));
  const fileBytes = await chunkedRead(Number(h[7]), Number(h[8]));
  console.log('header ok | dirs:', Number(h[4]), '| files:', Number(h[8]), '| data at', dataOffset);
  // parse the file table (classic layout)
  const NONE = 0xffffffff;
  const files = [];
  const walkDir = (offset, prefix) => {
    let file = dirBytes.readUInt32LE(offset + 12);
    while (file !== NONE) {
      const e = fileBytes.subarray(file, file + 32);
      const len = e.readUInt32LE(28);
      const name = fileBytes.subarray(file + 32, file + 32 + len).toString('utf8');
      files.push({path: prefix + name, offset: Number(e.readBigUInt64LE(8)),
        size: Number(e.readBigUInt64LE(16))});
      file = e.readUInt32LE(4);
    }
    let child = dirBytes.readUInt32LE(offset + 8);
    while (child !== NONE) {
      const e = dirBytes.subarray(child, child + 24);
      const len = e.readUInt32LE(20);
      const name = dirBytes.subarray(child + 24, child + 24 + len).toString('utf8');
      walkDir(child, prefix + name + '/');
      child = e.readUInt32LE(4);
    }
  };
  walkDir(0, '/');   // leading slash: paths must match the base manifest shape
  files.sort((a, b2) => a.offset - b2.offset);
  console.log('composed tree:', files.length, 'files');
  // base manifest for the diff
  const baseManifestPath = path.join(path.dirname(OUT), 'base', 'manifest.json');
  const baseFiles = JSON.parse(await fsp.readFile(baseManifestPath)).files;
  const baseMap = new Map(baseFiles.map(f => [f.path, f]));

  const imagePath = path.join(OUT, 'romfs.img.part');
  let resumeAt = 0;
  if (fs.existsSync(statePath)) {
    const state = JSON.parse(await fsp.readFile(statePath));
    resumeAt = state.imageOffset || 0;
    if (resumeAt >= size) resumeAt = 0;   // stale/nonsense checkpoint -> fresh
    // A state without its .part (deleted between runs) is a fresh start.
    if (resumeAt > 0 && !fs.existsSync(imagePath)) {
      console.log('checkpoint without a .part — RESTARTING FRESH');
      resumeAt = 0;
    } else if (resumeAt > 0) {
      const stat = await fsp.stat(imagePath);
      // The checkpoint may outlive the .part's persisted bytes (a failed write
      // path can record a boundary ahead of what hit the disk). Rather than
      // die, fall back to a FRESH start — the cost is a re-read, never wrong
      // data (every file re-hashes from its extent start).
      if (stat.size < resumeAt) {
        console.log('checkpoint (' + resumeAt + ') exceeds the .part (' + stat.size + ') — RESTARTING FRESH');
        resumeAt = 0;
      } else {
        console.log('RESUME from image offset', resumeAt, '(' + (resumeAt / 2 ** 20).toFixed(1) + ' MiB)');
      }
    }
  }
  const mode = resumeAt ? 'r+' : 'w';
  const imageHandle = await fsp.open(imagePath, mode);

  // zero-size files complete without any stream data
  const manifestComposed = {section: 'romfs-composed', started: new Date().toISOString(), files: []};
  let fileQueue = files.filter(f => f.size > 0);
  for (const f of files.filter(f2 => f2.size === 0))
    manifestComposed.files.push({path: f.path, size: 0, offset: f.offset,
      sha256: crypto.createHash('sha256').digest('hex')});
  let qi = 0;
  // on resume: drop files fully before the checkpoint (re-hashed at finalize)
  if (resumeAt) while (qi < fileQueue.length && dataOffset + fileQueue[qi].offset + fileQueue[qi].size <= resumeAt) qi++;
  const t0s = Date.now();
  let read = resumeAt, lastLog = Date.now(), lastCheckpoint = Date.now();
  const active = new Map();    // extent start -> {file, hash, fed}
  try {
    while (read < size) {
      if (stopping.flag) throw STOP;
      const take = Math.min(CHUNK, size - read);
      const bytes = await filesystem.readStorage(s, storageHandle, read, take);
      // node caps a write call's offset arg at 256 KiB — slice the chunk
      for (let o = 0; o < take; o += 0x40000)
        await imageHandle.write(bytes, o, Math.min(0x40000, take - o), read + o);
      const from = read, to = read + take;
      for (let i = qi; i < fileQueue.length; i++) {
        const f = fileQueue[i];
        const start = dataOffset + f.offset;
        if (start >= to) break;
        let entry = active.get(start);
        if (!entry) {entry = {file: f, hash: crypto.createHash('sha256'), fed: 0}; active.set(start, entry);}
        const overlapFrom = Math.max(start, from), overlapTo = Math.min(start + f.size, to);
        if (overlapTo <= overlapFrom) continue;
        entry.hash.update(bytes.subarray(overlapFrom - from, overlapTo - from));
        entry.fed += overlapTo - overlapFrom;
        if (entry.fed === f.size) {
          manifestComposed.files.push({path: f.path, size: f.size, offset: f.offset,
            sha256: entry.hash.digest('hex')});
          active.delete(start);
        }
      }
      // advance the queue pointer past completed files (never the open straddler)
      while (qi < fileQueue.length) {
        const f = fileQueue[qi];
        const start = dataOffset + f.offset;
        if (active.has(start) || start >= to) break;
        qi++;
      }
      read += take;
      if (Date.now() - lastLog > 15000) {
        const rate = (read - resumeAt) / 1024 / ((Date.now() - t0s) / 1000);
        console.log('  ' + (read / 2 ** 20).toFixed(1) + ' / ' + (size / 2 ** 20).toFixed(1) +
          ' MiB | ' + (rate / 1024).toFixed(2) + ' MiB/s | hashed: ' + manifestComposed.files.length);
        lastLog = Date.now();
      }
      if (Date.now() - lastCheckpoint > 30000) {
        await imageHandle.sync();
        // checkpoint = earliest uncompleted file's extent start (sorted)
        const boundary = qi < fileQueue.length ? dataOffset + fileQueue[qi].offset : size;
        await writeState({imageOffset: boundary, hashed: manifestComposed.files.length});
        lastCheckpoint = Date.now();
      }
    }
  } catch (e) {
    await imageHandle.sync();
    const boundary = qi < fileQueue.length ? dataOffset + fileQueue[qi].offset : size;
    await writeState({imageOffset: Math.min(boundary, read), hashed: manifestComposed.files.length});
    await imageHandle.close();
    if (e === STOP) {console.log('STOPPED — checkpoint at', Math.min(boundary, read), '— rerun to resume'); return;}
    throw e;
  }
  await imageHandle.sync();
  await imageHandle.close();
  check(read === size, 'Stream ended early: ' + read + ' != ' + size);
  console.log('IMAGE COMPLETE | files hashed:', manifestComposed.files.length, '/', files.length);

  // finalize: rename, manifests, diff, overlay
  await fsp.rename(imagePath, path.join(OUT, 'romfs.img'));
  // (dump-state.json deletion moved AFTER section 9: cleanup needs the
  // armed-state record — a run that dies between here and cleanup would
  // otherwise leave armed state with its record erased)
  // composed manifest complete only if every file hashed; otherwise rebuild from disk
  if (manifestComposed.files.length !== files.length) {
    console.log('re-hashing extents from the image on disk (resume stitching)...');
    manifestComposed.files.length = 0;
    const fd = await fsp.open(path.join(OUT, 'romfs.img'), 'r');
    try {
      for (const f of files) {
        const buf = Buffer.alloc(Math.min(f.size, 0x100000));
        const hash = crypto.createHash('sha256');
        for (let at = 0; at < f.size; at += 0x100000) {
          const take = Math.min(0x100000, f.size - at);
          const {bytesRead} = await fd.read(buf, 0, take, dataOffset + f.offset + at);
          check(bytesRead === take, 'Image re-hash short read: ' + f.path);
          hash.update(buf.subarray(0, take));
        }
        manifestComposed.files.push({path: f.path, size: f.size, offset: f.offset,
          sha256: hash.digest('hex')});
        if (manifestComposed.files.length % 20000 === 0)
          console.log('  re-hashed', manifestComposed.files.length, '/', files.length);
      }
    } finally {await fd.close();}
  }
  manifestComposed.completed = new Date().toISOString();
  await fsp.writeFile(path.join(OUT, 'manifest-composed.json'), JSON.stringify(manifestComposed, null, 2));
  // delta vs base
  const delta = {section: 'romfs-delta', base: 'base/manifest.json',
    generated: new Date().toISOString(), added: [], changed: [], unchanged: 0};
  for (const f of manifestComposed.files) {
    const b = baseMap.get(f.path);
    if (!b) delta.added.push(f);
    else if (b.size !== f.size || b.sha256 !== f.sha256) delta.changed.push({path: f.path, size: f.size,
      sha256: f.sha256, base: {size: b.size, sha256: b.sha256}});
    else delta.unchanged++;
  }
  await fsp.writeFile(path.join(OUT, 'manifest-delta.json'), JSON.stringify(delta, null, 2));
  console.log('DELTA | added:', delta.added.length, '| changed:', delta.changed.length,
    '| unchanged:', delta.unchanged);
  // LayeredFS overlay tree (only the delta files, copied from the image)
  const overlayRoot = path.join(OUT, 'romfs-overlay');
  const fd = await fsp.open(path.join(OUT, 'romfs.img'), 'r');
  try {
    let n = 0;
    for (const f of [...delta.added, ...delta.changed]) {
      const target = path.join(overlayRoot, 'romfs', f.path);
      await fsp.mkdir(path.dirname(target), {recursive: true});
      const out = await fsp.open(target, 'w');
      try {
        const buf = Buffer.alloc(Math.min(f.size, 0x100000));
        for (let at = 0; at < f.size; at += 0x100000) {
          const take = Math.min(0x100000, f.size - at);
          const {bytesRead} = await fd.read(buf, 0, take, dataOffset + f.offset + at);
          check(bytesRead === take, 'Overlay copy short read: ' + f.path);
          await out.write(buf.subarray(0, take), 0, take, at);
        }
      } finally {await out.close();}
      if (++n % 5000 === 0) console.log('  overlay', n, 'files');
    }
  } finally {await fd.close();}
  console.log('OVERLAY TREE:', delta.added.length + delta.changed.length, 'files ->', overlayRoot);

  }   // end of the non-archive (composed romfs) branch
  // ---- 9. cleanup console-side state ----
  success(await s.ipc('Remove owned temporary program context', registryHandle, 1, u64(owner)),
    'Remove program context');
  contextRegistered = false;
  await s.ipc('Remove owned patch location', registered, 2, idBytes(runtimeId)).catch(() => {});
  await fsp.rm(statePath, {force: true});    // armed state disarmed -> records can go
  console.log('MKW UPDATE ROMFS DONE ->', OUT);
  await s.cleanup().catch(() => {});
})().catch(e => {console.error('FAILED:', e.stack || e.message); process.exitCode = 1;});