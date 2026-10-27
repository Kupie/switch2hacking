#!/usr/bin/env node
// MKW update ExeFS via the OunceCake selectPatch route (lr registered patch):
// license BASE (real rights id + full account dance) in-session ->
// lr original+registered resolvers -> RegisterOwnedPatchLocation ->
// ldr:ro cmd 0 [patch-attrs, base-storage, runtime-id] -> composed CodeFS ->
// walk + dump exefs + manifest. One Session for everything (the es key
// registration and cmd 0 must ride the same session context).
const path = require('node:path');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const crypto = require('node:crypto');
const latest = JSON.parse(fs.readFileSync(process.env.HOME + '/dev/ns2jb/latest-session.json'));
const engine = path.join(latest.directory, 'switch2');
const {Session, u32, u64, check} = require(path.join(engine, 'app', 'session.cjs'));
const domain = require(path.join(engine, 'app', 'domain.cjs'));
const {paths} = require(path.join(engine, 'memory', 'paths.cjs'));

const TITLE_ARG = process.argv.find(x => /^0?x?[0-9a-fA-F]{16}$/.test(x));
const BASE_TITLE = BigInt(TITLE_ARG ? '0x' + TITLE_ARG.replace(/^0x/, '') : '0400c3f00006e000');
let BASE_CONTENT_ID = null;   // resolved at runtime via NCM (program content id)
const UPDATE_TITLE = BASE_TITLE | 0x800n;   // update tid = base | 0x800
const fsSync2 = require('node:fs');
const TITLE_HEX = BASE_TITLE.toString(16).padStart(16, '0');
const GAME_DIR = path.join(require('node:os').homedir(), 'dev/switch/roms', TITLE_HEX);
// output: update-v<ver> per the game.json discovery, else composed dir
let OUT = null;
try {
  const game = JSON.parse(fsSync2.readFileSync(path.join(GAME_DIR, 'game.json')));
  const v = game.discovery?.updates?.[0]?.version;
  if (v != null) OUT = path.join(GAME_DIR, 'update-v' + v);
} catch {}
if (!OUT || !fsSync2.existsSync(OUT)) OUT = path.join(GAME_DIR, 'update-romfs-composed');

const success = (r, l) => {if (r.result) throw Error(l + ': 0x' + (Number(r.result) >>> 0).toString(16)); return r;};
const idBytes = v => {const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return b;};
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

(async () => {
  const s = new Session('mkwupd-' + Date.now(), 0x80000);
  s.record = async () => {};
  await s.initialize();
  try {
    // ---- attach: root + pathApi + loader ----
    // SM fallback: helper-svc getService refuses fresh sessions; open services
    // via the TIPC 0x11 packet on the monitor's sm handle (the wave identity).
    const fsMemory = require(path.join(engine, 'tools', 'fs-memory.cjs'));
    const memory = await fsMemory.connect();
    const nativeInfo = await memory.request({command: 'root-native-info'});
    const smHandle = (nativeInfo.services || []).find(x => x.sm)?.sm;
    check(smHandle, 'no sm handle in monitor services');
    const openService = async name => {
      try {return await s.openService(name);} catch (e) {}
      const packet = Buffer.alloc(256);
      packet.writeUInt32LE(0x11); packet.writeUInt32LE(2, 4); packet.write(name, 8);
      await s.write(s.base, packet);
      const transport = await s.call('send', s.base, 4096, smHandle);
      check(!transport, 'sm transport failed');
      const reply = await s.readOwned(s.base, 256);
      let at = 8, count = 0, handle;
      if (reply.readUInt32LE(4) >>> 31) {
        const special = reply.readUInt32LE(at); at += 4;
        count = (special >>> 5) & 15;
        if (count) {handle = reply.readUInt32LE(at); at += 4; s.handles.add(handle);}
      }
      const result = reply.readUInt32LE(at) >>> 0;
      check(!result && count === 1 && handle > 0, 'sm open ' + name + ': 0x' + (result & 0x3fffff).toString(16));
      return handle;
    };
    const proof = JSON.parse(fs.readFileSync(path.join(engine, 'ro', 'root', 'current-root.json')));
    const root = domain.oneHandle(success(await domain.send(s, 'clone root', proof.rootHandle, domain.wire.control(2)), 'clone root'));
    const pathApi = paths(s, domain);
    const roDir = path.join(engine, 'ro');
    const loaderFile = fs.readdirSync(roDir).filter(f => f.endsWith('-loader-root-copy.json')).pop();
    const loaderEv = JSON.parse(fs.readFileSync(path.join(roDir, loaderFile)));
    const loader = domain.oneHandle(success(await domain.send(s, 'clone loader', loaderEv.copy.handle, domain.wire.control(2)), 'clone loader'));
    console.log('attached | root:', root, '| loader:', loader);

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

    // ---- license the BASE (real rights id + full dance) ----
    const ncm = await openService('ncm');
    const storageReply = success(await s.ipc('OpenContentStorage', ncm, 4, Buffer.from([4])), 'OpenContentStorage');
    const store = domain.oneHandle(storageReply);
    try {
      // attributes from GetContentInfoByType (db cmd 24) — attr is title-specific
      // (TOTK base = 0, MKW base = 1); attr!=real fails 0x1fb402.
      const db1 = domain.oneHandle(success(await s.ipc('OpenContentMetaDatabase', ncm, 5, Buffer.from([4])),
        'Open DB for info'));
      let attr = 1;
      try {
        const latest = success(await s.ipc('GetLatestContentMetaKey', db1, 6, idBytes(BASE_TITLE)),
          'GetLatestContentMetaKey');
        const key = Buffer.from(latest.data.subarray(0, 16));
        const infoInput = Buffer.alloc(24);
        infoInput[0] = 1;                    // ContentType::Program
        key.copy(infoInput, 8);
        const info = success(await s.ipc('GetContentInfoByType', db1, 24, infoInput), 'GetContentInfoByType').data;
        attr = info[21] & 15;
        console.log('base program attributes:', attr);
      } finally {await s.close(db1);}
      const rightsInput = Buffer.concat([Buffer.from(BASE_CONTENT_ID, 'hex'), Buffer.from([attr])]);
      const rightsReply = success(await s.ipc('GetContentRightsId', store, 20, rightsInput), 'GetContentRightsId');
      const rights = Buffer.from(rightsReply.data.subarray(0, 16));
      const generation = rightsReply.data[16] ?? 0;
      console.log('base rights:', rights.toString('hex'), 'gen:', generation);
      const es = await openService('es');
      const prep = async () => {
        await s.write(s.base + 0x5200, rights);
        await s.write(s.base + 0x5300, u32(generation));
        return s.ipc('Prepare installed title license', es, 503, Buffer.alloc(0),
          {send: [{address: s.base + 0x5200, size: 16, mode: 0}, {address: s.base + 0x5300, size: 4, mode: 0}]});
      };
      let r = await prep();
      let ctx = null;
      if ([0x1491, 0x691].includes(Number(r.result) & 0x3fffff)) {
        const opened = success(await s.ipc('Create export rights context', es, 2001), 'es 2001');
        ctx = domain.oneHandle(opened);
        const rightsApp = Buffer.alloc(8); rightsApp.writeBigUInt64LE(rights.readBigUInt64BE(), 0);
        await s.write(s.base + 0x3200, rightsApp);
        success(await s.ipc('Select export title rights', ctx, 2, Buffer.alloc(0),
          {send: [{address: s.base + 0x3200, size: 8, mode: 0}]}), 'ctx 2');
        const selectAccounts = () => s.ipc('Request account rights', ctx, 17, Buffer.from([1]),
          {send: [{address: s.base + 0x3200, size: 8, mode: 0}, {address: s.base + 0x3400, size: 8, mode: 0}]});
        success(await selectAccounts(), 'ctx 17');
        success(await s.ipc('Evaluate', ctx, 3), 'ctx 3');
        r = await prep();
        if ([0x1491, 0x691].includes(Number(r.result) & 0x3fffff)) {
          // account branch: acc:su ListUsers -> per-user 102/120 -> uids
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
          check(accounts.length, 'no linked accounts');
          console.log('accounts:', accounts.map(a => a.toString('hex')));
          await s.write(s.base + 0x3400, Buffer.concat(accounts));
          success(await s.ipc('Select account rights', ctx, 1, Buffer.from([0]),
            {send: [{address: s.base + 0x3400, size: accounts.length * 8, mode: 0}]}), 'ctx 1');
          success(await selectAccounts(), 'ctx 17b');
          success(await s.ipc('Evaluate 2', ctx, 3), 'ctx 3b');
          r = await prep();
        }
      }
      check(!r.result, 'base license failed: 0x' + (Number(r.result) >>> 0).toString(16));
      console.log('BASE LICENSE OK');
    } finally {await s.close(store);}

    // ---- lr: original + registered resolvers ----
    const lr = await openService('lr');
    const originalReply = success(await s.ipc('Open original resolver', lr, 0, Buffer.from([4])), 'lr 0');
    const original = domain.oneHandle(originalReply);
    const registeredReply = success(await s.ipc('Open registered resolver', lr, 1), 'lr 1');
    const registered = domain.oneHandle(registeredReply);
    console.log('lr | original:', original, '| registered:', registered);

    const readLocation = async (resolver, programId, label) => {
      const address = s.base + 0x3800, size = 0x300;
      const reply = await domain.send(s, 'Resolve location ' + label, resolver,
        fixedOutput(0, idBytes(programId), address, size));
      if ([0x408, 0x1408].includes(Number(reply.result) & 0x3fffff)) return null;
      check(!reply.result, 'Resolve ' + label + ': 0x' + (Number(reply.result) >>> 0).toString(16));
      const b = await s.readOwned(address, size);
      const end = b.indexOf(0);
      return {
        contentPath: b.subarray(0, end).toString('utf8'),
        attributes: reply.data.subarray(0, 16).toString('hex')};
    };
    const baseLoc = await readLocation(original, BASE_TITLE, 'base');
    check(baseLoc, 'base location not resolved');
    console.log('base loc:', baseLoc.contentPath, '| attrs:', baseLoc.attributes);
    const patchLoc = await readLocation(original, UPDATE_TITLE, 'update');
    check(patchLoc, 'update location not resolved');
    console.log('patch loc:', patchLoc.contentPath, '| attrs:', patchLoc.attributes);

    // ---- register the patch location ----
    // runtime id via 618 on the update path
    const pathBuffer = Buffer.alloc(0x301);
    pathBuffer.write(patchLoc.contentPath);
    const identity = success(await pathApi.raw(root, 618, pathBuffer, Buffer.from([1])), '618');
    const runtimeId = identity.data.readBigUInt64LE(0);
    console.log('runtime id: 0x' + runtimeId.toString(16));
    const input = Buffer.alloc(32);
    idBytes(runtimeId).copy(input);
    idBytes(BASE_TITLE).copy(input, 8);
    Buffer.from(patchLoc.attributes, 'hex').copy(input, 16);
    const pathAddr = s.base + 0x4000;
    const filename = Buffer.alloc(0x300);
    filename.write(patchLoc.contentPath);
    await s.write(pathAddr, filename);
    success(await domain.send(s, 'Register owned patch location', registered,
      pathRequest(1, input, pathAddr, 0x300)), 'Register patch');
    console.log('PATCH REGISTERED');

    // ---- cmd 0 composed mount ----
    const patchAttrs = parseInt(patchLoc.attributes.slice(0, 2), 16);
    const mount = Buffer.alloc(16);
    mount[0] = patchAttrs; mount[1] = 4;
    mount.writeBigUInt64LE(runtimeId, 8);
    const reply = await s.ipc('Open composed CodeFS', loader, 0, mount,
      {receive: [{address: s.base + 0x5000, size: 0x1a4, mode: 0}]});
    check(!reply.result, 'cmd 0 composed: 0x' + (Number(reply.result) >>> 0).toString(16));
    const codefs = domain.oneHandle(reply);
    console.log('COMPOSED CODEFS:', codefs);

    // ---- walk + dump ----
    const walk = async dir => {
      const opened = success(await pathApi.normal(codefs, 9, dir, u32(3)), 'opendir ' + dir);
      const dirHandle = domain.oneHandle(opened);
      const names = [];
      try {
        for (;;) {
          const rr = await s.ipc('readdir', dirHandle, 0, Buffer.alloc(0),
            {receive: [{address: s.base + 0x6000, size: 4 * 0x310, mode: 0}]});
          const count = Number(rr.data.readBigUInt64LE());
          if (!count) break;
          const rows = await s.readOwned(s.base + 0x6000, count * 0x310);
          for (let i = 0; i < count; i++) {
            const row = rows.subarray(i * 0x310, (i + 1) * 0x310);
            const end = row.subarray(0, 0x301).indexOf(0);
            names.push({name: row.subarray(0, end).toString('utf8'), type: row[0x304], size: Number(row.readBigUInt64LE(0x308))});
          }
        }
      } finally {await s.close(dirHandle);}
      return names;
    };
    const manifest = {section: 'exefs', started: new Date().toISOString(), files: []};
    const rootEntries = await walk('/');
    console.log('codefs /:', rootEntries.map(e => e.name + (e.type === 0 ? '/' : '')).join(' '));
    await fsp.mkdir(OUT + '/exefs', {recursive: true});
    for (const entry of rootEntries) {
      if (entry.type === 0) continue;
      const opened = success(await pathApi.normal(codefs, 8, '/' + entry.name, u32(1)), 'open ' + entry.name);
      const fh = domain.oneHandle(opened);
      try {
        let at = 0; const parts = [];
        while (at < entry.size) {
          const take = Math.min(0x10000, entry.size - at);
          const rr = await s.ipc('read ' + entry.name, fh, 0,
            Buffer.concat([u64(0), u64(at), u64(take)]),
            {receive: [{address: s.base + 0x6000, size: take, mode: 1}]});
          success(rr, 'read');
          parts.push(await s.readOwned(s.base + 0x6000, take));
          at += take;
        }
        const bytes = Buffer.concat(parts);
        await fsp.writeFile(OUT + '/exefs/' + entry.name, bytes);
        manifest.files.push({path: '/' + entry.name, size: bytes.length,
          sha256: crypto.createHash('sha256').update(bytes).digest('hex')});
        console.log('  exefs:', entry.name, bytes.length, 'bytes');
      } finally {await s.close(fh);}
    }
    await fsp.writeFile(OUT + '/manifest-exefs.json', JSON.stringify(manifest, null, 2));
    console.log('MKW UPDATE EXEFS DONE ->', OUT + '/exefs');

    // ---- cleanup: unregister + close ----
    await s.ipc('Remove owned patch location', registered, 2, idBytes(runtimeId)).catch(() => {});
    await s.close(codefs);
    await s.close(registered);
    await s.close(original);
    await s.close(loader);
    await s.close(root);
  } finally {await s.cleanup().catch(() => {});}
})().catch(e => {console.error('FAILED:', e.message); process.exitCode = 1;});