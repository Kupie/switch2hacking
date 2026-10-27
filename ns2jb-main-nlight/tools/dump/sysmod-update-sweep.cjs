#!/usr/bin/env node
// SYSTEM-UPDATE content sweep: metaType 0x81 (Update) / 0x82 (Delta?) / 0x01
// (sysprogram) across storages 0..4. Enumerates keys + resolves program/content
// ids + paths. Read-only. Same machinery as the proven sysarch sweep.
const path = require('node:path');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const latest = JSON.parse(fs.readFileSync(process.env.HOME + '/dev/ns2jb/latest-session.json'));
const engine = path.join(latest.directory, 'switch2');
const {Session, u32, u64, check} = require(path.join(engine, 'app', 'session.cjs'));
const domain = require(path.join(engine, 'app', 'domain.cjs'));
const fsMemory = require(path.join(engine, 'tools', 'fs-memory.cjs'));
const success = (r, l) => {if (r.result) throw Error(l + ': 0x' + (Number(r.result) >>> 0).toString(16)); return r;};
const pad16 = v => v.toString(16).padStart(16, '0');
(async () => {
  const memory = await fsMemory.connect();
  const info = await memory.request({command: 'root-native-info'});
  const smHandle = (info.services || []).find(x => x.sm)?.sm;
  check(smHandle, 'no sm handle');
  const s = new Session('sysmodsw-' + Date.now(), 0x800000);
  s.record = async () => {};
  await s.initialize();
  s.bulkDownloads = false;
  const openService = async name => {
    try {const h = await s.openService(name); if (h > 0) return h;} catch (e) {}
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
    check(!result && count === 1 && handle > 0, 'sm open ' + name + ': 0x' + (result & 0x3fffff).toString(16));
    return handle;
  };
  const handles = [];
  const track = h => {handles.push(h); return h;};
  try {
    const ncm = await openService('ncm');
    const results = [];
    for (const storage of [3, 0, 1, 2, 4]) {
      let db;
      try {db = track(domain.oneHandle(success(await s.ipc('OpenContentMetaDatabase ' + storage, ncm, 5,
        Buffer.from([storage])), 'Open DB ' + storage)));} catch (e) {console.log('== storage', storage, ': DB open refused (skip) =='); continue;}
      console.log('== storage', storage, 'sweep ==');
      const found = new Map();
      const sweep = async (metaType, min = 0n, max = 0xffffffffffffffffn) => {
        const input = Buffer.alloc(32);
        input[0] = metaType;
        input.writeBigUInt64LE(0n, 8);
        input.writeBigUInt64LE(min, 16);
        input.writeBigUInt64LE(max, 24);
        const address = s.base + 0x6000, capacity = 32;
        const reply = success(await s.ipc('ListContentMeta t0x' + metaType.toString(16),
          db, 5, input, {receive: [{address, size: capacity * 16, mode: 0}]}), 'ListContentMeta');
        const total = reply.data.readInt32LE(), count = reply.data.readInt32LE(4);
        const bytes = await s.readOwned(address, capacity * 16);
        for (let i = 0; i < count; i++) {
          const key = bytes.subarray(i * 16, (i + 1) * 16);
          const id = pad16(key.readBigUInt64LE());
          const version = key.readUInt32LE(8);
          const mt = key[12];
          if (!found.has(id) || version > found.get(id).version) found.set(id, {id, version, metaType: mt});
        }
        if (total <= count) return;
        if (min === max) {
          const latestKey = success(await s.ipc('GetLatestContentMetaKey', db, 6, u64(BigInt('0x' + id)),
            ), 'GetLatestContentMetaKey');
          if (!found.has(id)) found.set(id, {id, version: latestKey.data.readUInt32LE(8), metaType});
          return;
        }
        const mid = (min + max) / 2n;
        await sweep(metaType, min, mid);
        await sweep(metaType, mid + 1n, max);
      };
      for (const metaType of [0x81, 0x82, 0x01]) {
        try {await sweep(metaType);} catch (e) {console.log('  sweep t' + metaType.toString(16) + ':', e.message.slice(0, 60));}
      }
      const rows = [...found.values()];
      if (!rows.length) {console.log('  (no keys)'); continue;}
      console.log('  keys:', rows.length);
      for (const f of rows.slice(0, 12)) console.log('   ', f.id, 'v' + f.version, 't0x' + f.metaType.toString(16));
      // resolve program content ids + paths for each
      for (const f of rows) {
        const key = Buffer.alloc(16);
        key.writeBigUInt64LE(BigInt('0x' + f.id), 0);
        key.writeUInt32LE(f.version, 8);
        key[12] = f.metaType;
        for (const contentType of [1]) {           // Program
          const input = Buffer.alloc(24);
          input[0] = contentType;
          key.copy(input, 8);
          try {
            const cid = success(await s.ipc('GetContentIdByType', db, 3, input), 'GetContentIdByType')
              .data.subarray(0, 16).toString('hex');
            results.push({storage, title: f.id, version: f.version, metaType: f.metaType,
              contentType, contentId: cid});
            console.log('    ', f.id, 'v' + f.version, 'content[' + contentType + ']:', cid);
          } catch (e) {console.log('     ', f.id, 'content[' + contentType + '] lookup failed:', e.message.slice(0, 50));}
        }
      }
    }
    await fsp.writeFile('/tmp/sysmod-update-inventory.json', JSON.stringify(results, null, 2));
    console.log('== inventory ==', results.length, 'rows -> /tmp/sysmod-update-inventory.json');
  } finally {
    for (const h of [...handles].reverse()) await s.close(h).catch(() => {});
    await s.cleanup().catch(() => {});
  }
})().catch(e => {console.error('FAILED:', e.stack || e.message); process.exitCode = 1;});
