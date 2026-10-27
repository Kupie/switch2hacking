#!/usr/bin/env node
// Live app-process text-table probe (emulator divergence analysis).
//
// Route: the RO monitor's debug-suite rig (read-only by design):
//   0x524f0017 ATTACH {pid}          -> {result, debug handle}
//   0x524f0019 QUERY {debug, addr}  -> MemoryInfo (base/size/perms/type)
//   0x524f0018 READ  {debug, addr, size <= 64KiB} -> bytes
//   0x524f001a DETACH {debug}
// Any process readable, heap included (unlike 0016's t3/t4 restriction).
//
// Captures from the running SmileBASIC app:
//   - mainBase (query walk + text-head match vs our module, build EF33B250..)
//   - *(mainBase+0x9cbbc0) -> holder; *holder -> table
//   - table+0x20/+0x24 -> E bucket count/offset (8-byte records)
//   - dereferenced key strings per record
//   - main+0x35602b0 guard bytes (reference datum)
//
// Usage (netns-wrapped, live READY session, app running):
//   sudo -n ip netns exec switchlab runuser -u nlight -- \
//     node tools/rig/app-table-probe.cjs [--out /tmp/app-table.json]
'use strict';
const fsSync = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const {execFileSync} = require('node:child_process');
const latest = JSON.parse(fsSync.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json')));
const engine = path.join(latest.directory, 'switch2');
const {Client} = require(path.join(engine, 'process', 'client.cjs'));
const fsMemory = require(path.join(engine, 'tools', 'fs-memory.cjs'));
const connection = JSON.parse(fsSync.readFileSync(path.join(engine, '..', 'connection.json')));

const check = (ok, m) => {if (!ok) throw Error(m);};
const MAIN = path.join(process.env.HOME, '/dev/switch/roms/0100c9100b06a000/base/exefs/main');
const TEXT_HEAD = 64;

async function main() {
  const argv = process.argv.slice(2);
  const outFile = argv.includes('--out') ? argv[argv.indexOf('--out') + 1] : '/tmp/app-table.json';
  // unpack our module text
  const tmp = '/tmp/app-table-main';
  fsSync.rmSync(tmp, {recursive: true, force: true});
  execFileSync('python3', [path.join(__dirname, '..', 'nso-unpack.py'), MAIN, tmp]);
  const text = fsSync.readFileSync(path.join(tmp, 'text.bin'));

  // The controller already holds an exported ro:dmnt handle (root-native-info
  // services); the rig requests ride the controller ipc path — no sm open.
  const memory = await fsMemory.connect();
  const state0 = await memory.request({command: 'root-native-info'});
  const ro = (state0.services || []).find(x => x.name === 'ro:dmnt');
  check(ro && ro.handle, 'no exported ro:dmnt handle — monitor up?');
  console.log('rig via controller | ro:dmnt handle', ro.handle);
  const roPid = 209;   // the monitor's pid (session JeBXQE record)
  const out = {at: new Date().toISOString(), bucket: null, entries: null};
  let debug = null;
  const rig = async (id, words) => {
    const b = Buffer.alloc(64);
    words.forEach((w, i) => b.writeBigUInt64LE(BigInt(w), i * 8));
    const r = await memory.request({command: 'root-native-ipc', handle: ro.handle, id,
      hex: b.toString('hex')});
    check(!r.result, 'rig 0x' + id.toString(16) + ' failed: 0x' + (Number(r.result) >>> 0).toString(16));
    return r;
  };

  const replyData = reply => Buffer.from(reply.data ?? reply.hex ?? '', 'hex');
  try {
    // 1. app pid via controller id-7 sweep (tid at reply offset 0)
    const state = await memory.request({command: 'root-native-info'});
    const pmDmnt = (state.services || []).find(x => x.name === 'pm:dmnt');
    check(pmDmnt, 'pm:dmnt not held');
    const rows = [];
    for (let pid = 140; pid <= 230; pid++) {
      const b = Buffer.alloc(16);
      b.writeBigUInt64LE(BigInt(pid), 0);
      const r = await memory.request({command: 'root-native-ipc', handle: pmDmnt.handle,
        id: 7, hex: b.subarray(0, 16).toString('hex')}).catch(() => ({result: 1}));
      if (r && !r.result) {
        const data = Buffer.from(r.hex || r.data || '', 'hex');
        if (data.length >= 8) {
          const tid = data.readBigUInt64LE(0);
          if (tid) rows.push({pid, tid: tid.toString(16).padStart(16, '0')});
        }
      }
    }
    const app = rows.find(r => r.tid.endsWith('0b06a000'));
    check(app, 'SmileBASIC app pid not found (running?): rows=' + rows.length);
    const pid = BigInt(app.pid);
    out.app = {pid: app.pid, tid: app.tid};
    console.log('app pid', app.pid, 'tid', app.tid);

    // 2. attach + query walk to find mainBase (text-head match)
    const attach = replyData(await rig(0x524f0017, [pid, 0, 0, 0]));
    check(attach.length >= 16 && !attach.readBigUInt64LE(0), 'attach failed');
    debug = Number(attach.readBigUInt64LE(8));
    check(debug > 0, 'no debug handle');
    console.log('attached: debug handle', debug);
    const query = async addr => {
      const r = replyData(await rig(0x524f0019, [debug, addr, 0, 0]));
      check(r.length >= 56 && !r.readBigUInt64LE(0), 'query failed at 0x' + addr.toString(16));
      return {base: r.readBigUInt64LE(16), size: r.readBigUInt64LE(24),
        type: Number(r.readBigUInt64LE(32)), perms: Number(r.readBigUInt64LE(40) & 0xffffffffn)};
    };
    const readDebug = async (addr, len) => {
      check(len > 0 && len <= 0x10000, 'read length out of range');
      const r = await rig(0x524f0018, [debug, addr, len, 0]);
      check(!replyData(r).readBigUInt64LE(0) || replyData(r).readBigUInt64LE(0) === 0n,
        'debug read failed at 0x' + addr.toString(16));
      // 0018 receive rides the monitor buffer (s.base+0x1800000): the reply
      // data hex IS the read bytes after the 16-byte output head? The worker
      // reply carries `data` = output area; check both shapes:
      const d = replyData(r);
      // The worker's reply data starts at the output (16 bytes: {read, length}),
      // then the receive buffer contents follow in `hex`/data. Detect by size.
      if (d.length >= 16 && d.readBigUInt64LE(0) === 0n && d.readBigUInt64LE(8) === BigInt(len)) {
        return d.subarray(16, 16 + len);
      }
      return d.subarray(0, len);
    };
    // walk regions from the sdk base downward
    const sdkBase = BigInt(connection.addresses.sdk);
    out.sdkBase = sdkBase.toString(16);
    console.log('sdk base: 0x' + sdkBase.toString(16));
    let mainBase = null;
    let at = sdkBase;
    for (let i = 0; i < 60 && !mainBase; i++) {
      let info;
      try {info = await query(BigInt(at - 1));}
      catch {at -= 0x1000000n; continue;}
      if (info.perms === 0 || info.type === 0 || info.size === 0n) {at -= 0x1000000n; continue;}
      // readable + executable class regions only (text)
      if ((info.perms & 5) !== 5) {at = info.base - 1n; continue;}
      try {
        const head = await readDebug(info.base, Math.min(TEXT_HEAD, Number(info.size)));
        if (head.subarray(0, TEXT_HEAD).equals(text.subarray(0, TEXT_HEAD))) {mainBase = info.base; break;}
      } catch {}
      at = info.base - 1n;
      if (info.base <= 0x10000n) break;
    }
    check(mainBase, 'main base not found (region walk below sdk base)');
    out.mainBase = mainBase.toString(16);
    console.log('main base: 0x' + mainBase.toString(16), '(text head match, build EF33B250...)');

    // 3. derefs
    const deref = async addr => {
      const b = await readDebug(BigInt(addr), 8);
      return b.readBigUInt64LE(0);
    };
    const holderPtr = mainBase + 0x9cbbc0n;
    const holder = await deref(holderPtr);
    const table = await deref(holder);
    out.holderPtr = holderPtr.toString(16); out.holder = holder.toString(16); out.table = table.toString(16);
    console.log('*(main+0x9cbbc0) holder = 0x' + holder.toString(16));
    console.log('*holder table = 0x' + table.toString(16));

    // 4/5. bucket header + 8-byte records + key derefs
    const hdr = await readDebug(table, 0x30);
    const count = hdr.readUInt32LE(0x20), offset = hdr.readUInt32LE(0x24);
    out.count = count; out.offset = '0x' + offset.toString(16);
    console.log('table+0x20 count:', count, '| +0x24 offset: 0x' + offset.toString(16));
    if (count && count < 4096 && offset) {
      const bucketBytes = Math.min(count * 8, 0x10000);
      const bucket = await readDebug(table + BigInt(offset), bucketBytes);
      out.bucket = bucket.toString('hex');
      const entries = [];
      for (let i = 0; i < count && entries.length < 512; i++) {
        const keyPtr = bucket.readBigUInt64LE(i * 8);
        if (!keyPtr) continue;
        try {
          const keyBytes = await readDebug(keyPtr, 64);
          const end = keyBytes.indexOf(0);
          entries.push({index: i, keyPtr: keyPtr.toString(16),
            key: keyBytes.subarray(0, end < 0 ? 64 : end).toString('utf8')});
        } catch {entries.push({index: i, keyPtr: keyPtr.toString(16), key: null});}
      }
      out.entries = entries;
      console.log('E bucket:', count, 'records ->', entries.length, 'keys dereferenced');
    }

    // 6. guard (reference)
    try {
      const guard = await readDebug(BigInt(mainBase + 0x35602b0n), 8);
      out.guard = guard.toString('hex');
      console.log('guard @main+0x35602b0:', out.guard);
    } catch (e) {out.guard = null; console.log('guard read failed:', e.message.slice(0, 40));}
  } finally {
    if (debug) {try {await rig(0x524f001a, [debug, 0, 0, 0]);} catch {}}
  }
  out.at = new Date().toISOString();
  fsSync.writeFileSync(outFile, JSON.stringify(out, null, 2));
  console.log('probe complete ->', outFile);
}
main().catch(e => {console.error('FAILED:', e.stack || e.message); process.exitCode = 1;});