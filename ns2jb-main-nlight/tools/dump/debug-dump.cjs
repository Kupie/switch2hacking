// Debug-rig process dumper: attach (svc 0x60 via rig 0x524f0017), walk the
// target's whole address space (rig 0x524f0019 = QueryDebugProcessMemory),
// bulk-read module regions (rig 0x524f0018 = ReadDebugProcessMemory — the
// KERNEL-mediated read: even execute-only text is readable, no flip needed)
// and fetch via the fast owned-buffer channel. Detach at the end.
//
// Usage: node debug-dump.cjs <pid> [--max-chunks=N]
'use strict';
const fsSync = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fsSync.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json')));
const {Client} = require(path.join(latest.directory, 'switch2', 'process', 'client.cjs'));
const {connect} = require(path.join(latest.directory, 'switch2', 'tools', 'fs-memory.cjs'));

async function main() {
  const targetPid = BigInt(process.argv[2] || 0);
  if (!targetPid) throw Error('usage: debug-dump.cjs <pid>');
  const maxChunks = Number((process.argv.find(a => a.startsWith('--max-chunks=')) || '').slice(13)) || 512;
  let client;
  try { client = await new Client().open(); }
  catch (error) {
    const memory = await connect();
    const state = await memory.request({command: 'root-native-info'});
    const owned = (state.services || []).filter(x => x.name === 'ro:dmnt').pop();
    if (!owned) throw error;
    const execution = JSON.parse(fsSync.readFileSync(
      path.join(latest.directory, 'switch2', 'ro', 'current-execution.json')));
    client = new Client();
    client.memory = memory; client.pid = execution.pid; client.handle = owned.handle;
    client.record = {session: execution.session, calls: []};
    client.file = path.join(latest.directory, 'switch2', 'process', 'dbgdump-' + Date.now() + '.json');
    console.log('reusing owned ro:dmnt', owned.handle);
  }
  const memory = client.memory;
  const fsHandle = await client.fsProcess();
  const fsInfo = await client.info(fsHandle);
  const fsPid = BigInt(fsInfo.pid);
  const req = (id, values) => client.request(id, fsHandle, values);
  const check = (c, m) => { if (!c) throw Error(m); };

  console.log('attaching to pid', targetPid.toString(), '...');
  const attach = await req(0x524f0017, [fsPid, targetPid, 0n, 0n]);
  check(attach.result === 0n || attach.result === 0, 'attach failed: 0x' + attach.result.toString(16));
  console.log('attached (handle', attach.values?.[4]?.toString() + ')');
  // LIFECRITICAL: drain the attach/module events immediately — a live target
  // blocks once the kernel's event queue fills. Never-thawed = frozen target.
  const drain = async () => {
    try { return await req(0x524f001c, [fsPid, 0n, 0n, 0n]); } catch (e) { return null; }
  };
  let drained = 0;
  for (let i = 0; i < 16; i++) {
    const ev = await drain();
    if (!ev || ev.result !== 0) break;
    drained++;
  }
  console.log('drained', drained, 'initial debug events');

  // Full address-space walk via QueryDebugProcessMemory
  const regions = [];
  let at = 0n;
  for (let i = 0; i < 400; i++) {
    const q = await req(0x524f0019, [fsPid, at, 0n, 0n]);
    const v = q.values;
    if (q.result) break;
    const r = {base: v[4], size: v[5], type: v[6] & 0xffffffffn, attributes: v[6] >> 32n,
      permissions: v[7] & 0xffffffffn, ipcReferences: v[7] >> 32n, deviceReferences: v[8]};
    regions.push(r);
    const end = r.base + r.size;
    if (r.size === 0n || end <= at || end > 2n ** 42n) break;
    at = end;
  }
  console.log('walked', regions.length, 'regions');
  const outDir = path.join(latest.directory, 'debug-dump', targetPid.toString());
  fsSync.mkdirSync(outDir, {recursive: true});
  fsSync.writeFileSync(path.join(outDir, 'regions.json'), JSON.stringify(regions.map(r => ({
    base: r.base.toString(), size: r.size.toString(), type: Number(r.type),
    attributes: Number(r.attributes), permissions: Number(r.permissions)})), null, 1));
  for (const r of regions) {
    if (![3n, 4n, 5n].includes(r.type) || r.attributes !== 0n || r.size > 32 * 1024 * 1024) {
      console.log(`skip 0x${r.base.toString(16)} t${r.type} p${r.permissions} (${r.size})`);
      continue;
    }
    const name = `r-${r.base.toString(16)}-${r.size.toString(16)}.bin`;
    const out = path.join(outDir, name);
    if (fsSync.existsSync(out)) continue;
    const info = await memory.request({command: 'root-native-info'});
    const fetchAt = Number(info.ownedBase) + 0x1800000;
    const fd = fsSync.openSync(out, 'w');
    let chunks = 0;
    try {
      for (let off = 0n; off < r.size && chunks < maxChunks; off += 0x10000n) {
        const len = r.size - off > 0x10000n ? 0x10000n : r.size - off;
        const reply = await req(0x524f0018, [fsPid, r.base + off, len, 0n]);
        check(reply.result === 0n, 'debug read failed: 0x' + reply.result.toString(16));
        const fetched = await memory.request({command: 'root-native-owned-fetch',
          address: fetchAt, length: Number(len)});
        const buf = Buffer.from(fetched.hex, 'hex');
        check(buf.length === Number(len), 'fetch short');
        fsSync.writeSync(fd, buf);
        chunks++;
        if (chunks % 16 === 0) await drain();   // keep the queue empty (LIFECRITICAL)
        if (chunks % 32 === 0) console.log(`  ${name} +0x${off.toString(16)} (${chunks} chunks)`);
      }
    } finally { fsSync.closeSync(fd); }
    console.log(`dumped ${name} (${r.size} bytes, ${chunks} chunks)`);
  }
  const det = await req(0x524f001a, [fsPid, 0n, 0n, 0n]);
  console.log('detached:', det.result);
  console.log('DONE');
}
main().catch(e => {console.error(e.stack || e); process.exitCode = 1;});
