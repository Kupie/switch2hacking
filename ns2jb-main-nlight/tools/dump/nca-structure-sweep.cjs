#!/usr/bin/env node
// NCA-LEVEL STRUCTURE sweep: for every storage-3 system title, enumerate
// which content types its NCA set carries (1 Program, 2 Data, 3 Control,
// 4 HtmlDocument, 5 Legal) + per-content attributes, then dump each title's
// control.nacp via fs cmd 10 fsType 3 (the proven route) into
// ~/dev/switch/dumps/fw23/control/.
'use strict';
const path = require('node:path');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const latest = JSON.parse(fs.readFileSync(process.env.HOME + '/dev/ns2jb/latest-session.json'));
const engine = path.join(latest.directory, 'switch2');
const {Session, u32, u64, check} = require(path.join(engine, 'app', 'session.cjs'));
const domain = require(path.join(engine, 'app', 'domain.cjs'));
const filesystem = require(path.join(engine, 'app', 'filesystem.cjs'));
const {paths} = require(path.join(engine, 'memory', 'paths.cjs'));
const fsMemory = require(path.join(engine, 'tools', 'fs-memory.cjs'));
const success = (r, l) => {if (r.result) throw Error(l + ': 0x' + (Number(r.result) >>> 0).toString(16)); return r;};
const check2 = (ok, m) => {if (!ok) throw Error(m);};
const pad16 = v => v.toString(16).padStart(16, '0');
const OUTROOT = path.join(require('node:os').homedir(), 'dev/switch/dumps/fw23');
(async () => {
  const memory = await fsMemory.connect();
  const info = await memory.request({command: 'root-native-info'});
  const smHandle = (info.services || []).find(x => x.sm)?.sm;
  check2(smHandle, 'no sm handle');
  const s = new Session('ncastruct-' + Date.now(), 0x2100000);
  s.record = async () => {};
  await s.initialize();
  s.bulkDownloads = true;
  const openService = async name => {
    try {const h = await s.openService(name); if (h > 0) return h;} catch (e) {}
    const pkt = Buffer.alloc(256);
    pkt.writeUInt32LE(0x11); pkt.writeUInt32LE(2, 4); pkt.write(name, 8);
    await s.write(s.base, pkt);
    const transport = await s.call('send', s.base, 4096, smHandle);
    check2(!transport, 'sm transport failed for ' + name);
    const reply = await s.readOwned(s.base, 256);
    let at = 8, count = 0, handle;
    if (reply.readUInt32LE(4) >>> 31) {
      const special = reply.readUInt32LE(at); at += 4;
      count = (special >>> 5) & 15;
      if (count) {handle = reply.readUInt32LE(at); at += 4; s.handles.add(handle);}
    }
    const result = reply.readUInt32LE(at) >>> 0;
    check2(!result && count === 1 && handle > 0, 'sm open ' + name + ': 0x' + (result & 0x3fffff).toString(16));
    return handle;
  };
  const handles = [];
  const track = h => {handles.push(h); return h;};
  try {
    const proof = JSON.parse(await fsp.readFile(path.join(engine, 'ro', 'root', 'current-root.json')));
    const root = track(domain.oneHandle(success(await domain.send(s, 'clone root', proof.rootHandle,
      domain.wire.control(2)), 'clone root')));
    const pathApi = paths(s, domain);
    const ncm = await openService('ncm');
    const db = track(domain.oneHandle(success(await s.ipc('Open DB 3', ncm, 5, Buffer.from([3])), 'Open DB 3')));
    // sweep all keys (metaType 0 + 1 patterns; enumerate 0x01)
    const found = new Map();
    const sweep = async (metaType, min = 0n, max = 0xffffffffffffffffn) => {
      const input = Buffer.alloc(32);
      input[0] = metaType;
      input.writeBigUInt64LE(0n, 8);
      input.writeBigUInt64LE(min, 16);
      input.writeBigUInt64LE(max, 24);
      const address = s.base + 0x6000, capacity = 32;
      const reply = success(await s.ipc('ListContentMeta t0x' + metaType.toString(16), db, 5, input,
        {receive: [{address, size: capacity * 16, mode: 0}]}), 'ListContentMeta');
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
      if (min === max) return;
      const mid = (min + max) / 2n;
      await sweep(metaType, min, mid);
      await sweep(metaType, mid + 1n, max);
    };
    await sweep(0x01);
    const rows = [...found.values()].sort((a, b) => a.id.localeCompare(b.id));
    console.log('== system titles:', rows.length, '==');
    const TYPE = {1: 'Program', 2: 'Data', 3: 'Control', 4: 'HtmlDocument', 5: 'Legal'};
    const structure = [];
    for (const f of rows) {
      const key = Buffer.alloc(16);
      key.writeBigUInt64LE(BigInt('0x' + f.id), 0);
      key.writeUInt32LE(f.version, 8);
      key[12] = f.metaType;
      const entry = {title: f.id, version: f.version, contents: {}};
      for (const contentType of [1, 2, 3, 4, 5]) {
        const input = Buffer.alloc(24);
        input[0] = contentType;
        key.copy(input, 8);
        try {
          const cid = success(await s.ipc('GetContentIdByType', db, 3, input), 'GetContentIdByType')
            .data.subarray(0, 16).toString('hex');
          let attributes = null;
          try {
            const cinfo = success(await s.ipc('GetContentInfoByType', db, 24, input), 'GetContentInfoByType').data;
            attributes = cinfo[21] & 15;
          } catch (e) {}
          entry.contents[TYPE[contentType]] = {contentId: cid, attributes};
        } catch (e) {  // not-present is normal (0xa05/x errors)
          if ((e.nativeResult?.canonical ?? 0) !== 0xa05 && Number((e.nativeResult?.raw ?? 0) & 0x3fffff) !== 0xa05)
            console.log('  ', f.id, TYPE[contentType], 'lookup:', e.message.slice(0, 60));
        }
      }
      structure.push(entry);
      const list = Object.entries(entry.contents).map(([t, c]) => t + ':' + (c.contentId||'').slice(0, 8)).join(' ');
      console.log(' ', f.id, 'v' + f.version, '|', list);
    }
    await fsp.mkdir(OUTROOT, {recursive: true});
    await fsp.writeFile(path.join(OUTROOT, 'nca-structure.json'), JSON.stringify({generated: new Date().toISOString(),
      titles: structure}, null, 2));
    console.log('structure ->', path.join(OUTROOT, 'nca-structure.json'));
    // control.nacp dumps via cmd 10 fsType 3
    console.log('== control.nacp sweep ==');
    const ctrlDir = path.join(OUTROOT, 'control');
    let nacpOk = 0;
    for (const [i, f] of rows.entries()) {
      if (!Object.keys((structure[i].contents)).includes('Control')) continue;
      const pb = Buffer.alloc(0x301);
      pb.write('@SystemContent://registered/' + structure[i].contents.Control.contentId + '.nca');
      const input = Buffer.alloc(16);
      input[0] = structure[i].contents.Control.attributes ?? 1;
      input.writeUInt32LE(3, 4);
      input.writeBigUInt64LE(BigInt('0x' + f.id), 8);
      try {
        const reply = await pathApi.raw(root, 10, pb, input);
        if (reply.result) {
          console.log('  ', f.id, 'control mount refused 0x' + (Number(reply.result) & 0x3fffff).toString(16));
          continue;
        }
        const fsobj = track(domain.oneHandle(reply));
        try {
          const file = track(domain.oneHandle(success(await filesystem.pathMethod(s, fsobj, 8, '/control.nacp', u32(1)), 'open nacp')));
          try {
            const size = Number(await filesystem.fileSize(s, file));
            const bytes = await filesystem.readFile(s, file, 0, size);
            await fsp.mkdir(ctrlDir, {recursive: true});
            await fsp.writeFile(path.join(ctrlDir, f.id + '.nacp'), bytes);
            nacpOk++;
          } finally {await s.close(file).catch(() => {});}
        } finally {await s.close(fsobj).catch(() => {});}
      } catch (e) {console.log('  ', f.id, 'nacp:', e.message.slice(0, 70));}
    }
    console.log('control.nacp:', nacpOk, '->', ctrlDir);
  } finally {
    for (const h of [...handles].reverse()) await s.close(h).catch(() => {});
    await s.cleanup().catch(() => {});
  }
})().catch(e => {console.error('FAILED:', e.stack || e.message); process.exitCode = 1;});
