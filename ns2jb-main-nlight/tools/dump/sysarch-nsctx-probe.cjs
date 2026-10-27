#!/usr/bin/env node
// The archive-gate fix derived from the 2026-10-27 RE: the fake-program-context
// must carry NS-CLASS fsaccess (system-content data rights), not a game NPDM.
// Route: 618 (runtime id) -> registry pair-swap (capture scan) -> Remove old
// context -> RegisterOwnedTemporaryProgramContext(ns fah/fac) -> fresh
// fsp-srv domain -> owner-field spoof -> fs 206 type-1 on the archive path.
'use strict';
const path = require('node:path');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const crypto = require('node:crypto');
const latest = JSON.parse(fs.readFileSync(process.env.HOME + '/dev/ns2jb/latest-session.json'));
const engine = path.join(latest.directory, 'switch2');
const {Session, u32, u64, check} = require(path.join(engine, 'app', 'session.cjs'));
const domain = require(path.join(engine, 'app', 'domain.cjs'));
const {paths, pathPacket} = require(path.join(engine, 'memory', 'paths.cjs'));
const fsMemory = require(path.join(engine, 'tools', 'fs-memory.cjs'));
const success = (r, l) => {if (r.result) throw Error(l + ': 0x' + (Number(r.result) >>> 0).toString(16)); return r;};
const idBytes = v => {const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return b;};
const hex64 = v => '0x' + v.toString(16);
const fastMemory = memory => ({read: memory.read.bind(memory), write: memory.write.bind(memory)});
const ARCH = process.argv[2] || '0400000000000812';
const STATE = path.join(process.env.HOME, 'dev/switch/dumps/fw23-archives/context-state.json');
// ns NPDM access controls (the banked fw23 ns dump)
function accessControls(bytes) {
  const region = (at, size) => bytes.subarray(at, at + size);
  const aci = region(bytes.readUInt32LE(0x70), bytes.readUInt32LE(0x74));
  const acid = region(bytes.readUInt32LE(0x78), bytes.readUInt32LE(0x7c));
  const header = acid.toString('ascii', 0x200, 0x204) === 'ACID' ? 0x200 :
    acid.length >= 0x340 && acid.toString('ascii', 0x300, 0x304) === 'ACID' ? 0x300 : -1;
  check(header > 0, 'ACID header not found');
  const control = (parent, field) => {
    const at = parent.readUInt32LE(field), size = parent.readUInt32LE(field + 4);
    return Buffer.from(parent.subarray(at, at + size));
  };
  const fah = control(aci, 0x20), fac = control(acid, header + 0x20);
  check(fah.length >= 0x1c && fac.length >= 0x2c, 'Access control sizes too small');
  return {fah, fac};
}
(async () => {
  const memory = await fsMemory.connect();
  const mem = fastMemory(memory);
  const sessionName = latest.session || path.basename(latest.directory);
  const layout = JSON.parse(await fsp.readFile(path.join(engine, 'ro', sessionName + '-layout.json')));
  check(layout.rootVptr && layout.table, 'Layout unusable');
  const nsNpdm = await fsp.readFile(path.join(process.env.HOME, 'dev/switch/dumps/fw23/040000000000001f-ns/main.npdm'));
  const {fah, fac} = accessControls(nsNpdm);
  console.log('ns fah:', fah.length, 'B | fac:', fac.length, 'B');

  const s = new Session('nsctxarch-' + Date.now(), 0x2100000);
  s.bulkDownloads = true; s.record = async () => {};
  await s.initialize();
  const nativeInfo = await memory.request({command: 'root-native-info'});
  const smHandle = (nativeInfo.services || []).find(x => x.sm)?.sm;
  const openService = async name => {
    try {const h = await s.openService(name); if (h > 0) return h;} catch (e) {}
    check(smHandle, 'no sm for ' + name);
    const pkt = Buffer.alloc(256);
    pkt.writeUInt32LE(0x11); pkt.writeUInt32LE(2, 4); pkt.write(name, 8);
    await s.write(s.base, pkt);
    const transport = await s.call('send', s.base, 4096, smHandle);
    check(!transport, 'sm open ' + name);
    const reply = await s.readOwned(s.base, 256);
    let at = 8, count = 0, handle;
    if (reply.readUInt32LE(4) >>> 31) {
      const special = reply.readUInt32LE(at); at += 4;
      count = (special >>> 5) & 15;
      if (count) {handle = reply.readUInt32LE(at); at += 4; s.handles.add(handle);}
    }
    check(!(reply.readUInt32LE(at) >>> 0) && count === 1 && handle > 0, 'sm open ' + name + ' failed');
    return handle;
  };
  const openDomain = async label => {
    const handle = await openService('fsp-srv');
    success(await s.ipc(label + ' SetCurrentProcess', handle, 1, u64(0), {pid: true}), label + ' SetCurrentProcess');
    const reply = success(await domain.send(s, label + ' ConvertToDomain', handle, domain.wire.control(0)), label);
    return {label, handle, root: reply.data.readUInt32LE()};
  };
  const pathApi = paths(s, domain);
  const proof = JSON.parse(await fsp.readFile(path.join(engine, 'ro', 'root', 'current-root.json')));
  const handles = [];
  const track = h => {handles.push(h); return h;};
  try {
    const root = track(domain.oneHandle(success(await domain.send(s, 'clone root', proof.rootHandle,
      domain.wire.control(2)), 'clone root')));

    // 618 on the TOTK UPDATE program path (banked resolve-state) -> runtime id
    const resolveState = JSON.parse(await fsp.readFile(
      path.join(process.env.HOME, 'dev/switch/roms/0100f2c0115b6000/resolve-state.json')));
    const updPath = resolveState['update-v720896'].contentPath;
    const pathBuffer = Buffer.alloc(0x301);
    pathBuffer.write(updPath);
    const identity = success(await pathApi.raw(root, 618, pathBuffer, Buffer.from([1])), '618');
    const runtimeId = identity.data.readBigUInt64LE(0);
    check(runtimeId > 0n, 'runtime id failed');
    console.log('runtime id:', hex64(runtimeId));

    // registry pair-swap (capture scan) -> registryHandle
    const captureInfo = layout.range;
    const captureBytes = await fsp.readFile(captureInfo.outputFile);
    check(captureBytes.length === captureInfo.length &&
      crypto.createHash('sha256').update(captureBytes).digest('hex') === captureInfo.sha256, 'Capture hash differs');
    const captureTable = captureBytes.subarray(layout.table - captureInfo.address,
      layout.table - captureInfo.address + layout.count * 0x30);
    const candidates = [];
    for (let at = 0; at + 0x30 <= captureTable.length; at += 0x30) {
      if (captureTable.readBigUInt64LE(at + 0x28) !== BigInt(layout.rootVptr) + 0x5888n) continue;
      candidates.push({entry: layout.table + at, domain: Number(captureTable.readBigUInt64LE(at + 0x18)),
        object: Number(captureTable.readBigUInt64LE(at + 0x20)),
        pair: captureTable.subarray(at + 0x20, at + 0x30).toString('hex')});
    }
    check(candidates.length >= 1, 'no registry interface row');
    let source = null;
    for (const cand of candidates) {
      const live = await mem.read(cand.entry, 0x30);
      if (live.readBigUInt64LE(0x28) !== BigInt(layout.rootVptr) + 0x5888n) continue;
      if (live.readBigUInt64LE(0x18) !== BigInt(cand.domain) ||
          live.readBigUInt64LE(0x20) !== BigInt(cand.object)) continue;
      source = {...cand, pair: live.subarray(0x20).toString('hex')};
      break;
    }
    check(source, 'registry interface entry not found');
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
        copied = success(await domain.send(s, 'Copy registry', auxiliary.handle,
          domain.wire.control(1, u32(auxiliary.root))), 'Copy registry');
      } finally {
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
    check(registryHandle, 'registry copy failed');

    // stale context cleanup (TONK context from tonight's arming)
    let armState = {};
    try {armState = JSON.parse(await fsp.readFile(STATE));} catch {}
    const previous = armState.owner ? BigInt(armState.owner) : null;
    if (previous) {
      await s.ipc('Remove stale context', registryHandle, 1, u64(previous))
        .then(() => console.log('stale context removed'))
        .catch(() => console.log('stale context remove refused (tolerated)'));
    }

    // register the NS-CLASS context
    const owner = 0xf000000000000000n | BigInt('0x' + crypto.randomBytes(7).toString('hex'));
    await s.write(s.base + 0x8000, fah);
    await s.write(s.base + 0xc000, fac);
    const ctxInput = Buffer.alloc(40);
    ctxInput[0] = 4;
    ctxInput.writeBigUInt64LE(owner, 8);
    idBytes(runtimeId).copy(ctxInput, 16);
    ctxInput.writeBigUInt64LE(BigInt(fah.length), 24);
    ctxInput.writeBigUInt64LE(BigInt(fac.length), 32);
    success(await s.ipc('Register NS program context', registryHandle, 0, ctxInput,
      {send: [{address: s.base + 0x8000, size: fah.length, mode: 0},
        {address: s.base + 0xc000, size: fac.length, mode: 0}]}), 'Register NS context');
    console.log('NS CONTEXT REGISTERED | owner:', hex64(owner));
    await fsp.mkdir(path.dirname(STATE), {recursive: true});
    await fsp.writeFile(STATE, JSON.stringify({owner: owner.toString(), at: new Date().toISOString(),
      npdm: 'fw23/040000000000001f-ns'}, null, 2));

    // fresh domain + spoof + 206
    const inv = JSON.parse(fs.readFileSync('/tmp/sysarch-inventory.json'));
    const arch = inv.find(a => a.title === ARCH);
    check(arch, 'archive not in inventory');
    const contentPath = '@SystemContent://registered/' + arch.contentId + '.nca';
    const client = await openDomain('Spoofed NS archive FS');
    let spoofFields = null;
    try {
      const clientEntry = layout.table + (client.root - 1) * 0x30;
      const b = await mem.read(clientEntry, 0x30);
      const rootObj = Number(b.readBigUInt64LE(0x20));
      const h = await mem.read(rootObj, 0x40);
      const nca = Number(h.readBigUInt64LE(0x10));
      const n = await mem.read(nca, 0x30);
      spoofFields = [
        {address: rootObj + 0x30, original: h.subarray(0x30, 0x38)},
        {address: nca + 0x20, original: n.subarray(0x20, 0x28)},
      ];
      for (const field of spoofFields) await mem.write(field.address, field.original, u64(owner));
      console.log('spoofed | root:', client.root, '| path:', contentPath);
      for (const type of [1, 6]) {
        const pb = Buffer.alloc(0x301);
        pb.write(contentPath);
        await s.write(s.base + 0x4000, pb);
        const input = Buffer.alloc(8);
        input[0] = 1;
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
        bytes.writeUInt32LE(client.root, ds + 4);
        bytes.writeUInt32LE(0, ds + 12);
        bytes.writeUInt32LE(0, ds + 20);
        bytes.writeUInt32LE((bytes.readUInt32LE() & 0xffff0000 | 4) >>> 0);
        bytes.writeUInt32LE((bytes.readUInt32LE(4) + 4) >>> 0, 4);
        const reply = await domain.send(s, 'Spoofed 206 type-' + type, client.handle, bytes, {domain: true});
        if (reply.result) {
          console.log('type-' + type, 'REFUSED: 0x' + (Number(reply.result) >>> 0).toString(16),
            '(canonical 0x' + (Number(reply.result) & 0x3fffff).toString(16) + ')');
          continue;
        }
        const storage = domain.oneHandle(reply);
        const size = Number(await domain.storageSize(s, storage));
        console.log('type-' + type, 'OPEN! storage', storage, '| size', size);
        await s.close(storage).catch(() => {});
        break;
      }
    } finally {
      if (spoofFields) for (const field of [...spoofFields].reverse()) {
        const current = await mem.read(field.address, 8);
        if (!current.equals(field.original)) await mem.write(field.address, current, field.original);
      }
      console.log('spoof fields restored');
    }
  } finally {
    for (const h of [...handles].reverse()) await s.close(h).catch(() => {});
    await s.cleanup().catch(() => {});
  }
})().catch(e => {console.error('FAILED:', e.stack || e.message); process.exitCode = 1;});
