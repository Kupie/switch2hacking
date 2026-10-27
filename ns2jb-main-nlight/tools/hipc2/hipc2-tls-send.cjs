// HIPC2 TLS-safe driver v3 — PC-side ring scan + dispatch patch.
//
// The worker frame: call0 = SDK wait(gate) [the REAL park], call1 =
// memcpy(TLS, cfgFrame, 0x100), call2 = send(TLS, 0x100, handle),
// call3 = memcpy(replyArea, TLS, 0x100).
//
// Flow:
//   1. PC ring scan with memory.read (the boot's own proven primitive on
//      these exact structs): 3 API-worker structs -> tpidr offset (cross-
//      thread +0x1f8 agreement) -> read the parked worker's own struct
//      -> its TLS -> validate (+0x110 token, +0x1f8 global match).
//   2. root-native-worker-hipc2-patch {tls}: three owned frame writes.
//   3. root-native-worker-release: signals the gate -> the worker wakes,
//      runs the patched calls on its OWN thread, exits.
//   4. poll + join, read the reply area, parse SFCO.
//
// Usage (netns-wrapped, live READY session):
//   sudo -n ip netns exec switchlab runuser -u nlight -- node hipc2-tls-send.cjs
'use strict';
const fsSync = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fsSync.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json')));
const {connect} = require(path.join(latest.directory, 'switch2', 'tools', 'fs-memory.cjs'));

function cmifFrame(cmd, args) {
  const b = Buffer.alloc(0x100);
  b.writeUInt32LE(4, 0); b.writeUInt32LE(8, 4);
  b.write('SFCI', 0x10); b.writeUInt32LE(0, 0x14);
  b.writeUInt32LE(cmd, 0x18); b.writeUInt32LE(0, 0x1c);
  (args || []).forEach((a, i) => b.writeBigUInt64LE(BigInt(a), 0x20 + i * 8));
  return b;
}
function hipc2Frame(cmd, seq, args) {
  const b = Buffer.alloc(0x100);
  // wc = total words = 2 hdr + 2 pad + 4 SFCI + 2 per u64 arg (pgl-decoded)
  b.writeUInt32LE(6, 0x00); b.writeUInt32LE(8 + 2 * (args || []).length, 0x04);
  b.write('SFCI', 0x10); b.writeUInt32LE(1, 0x14);
  b.writeUInt32LE(cmd, 0x18); b.writeUInt32LE(seq, 0x1C);
  (args || []).forEach((a, i) => b.writeBigUInt64LE(BigInt(a), 0x20 + i * 8));
  return b;
}

async function main() {
  const memory = await connect();
  const req = c => memory.request(c);
  const read = (at, len) => memory.read(at, len);
  const info = await req({command: 'root-native-info'});
  console.log('session', info.session);

  // ---- PC-side ring scan -> tpidr offset ----
  const ringFile = path.join(latest.directory, 'switch2', 'ro',
    latest.directory.split('/').pop() + '-thread-ring.json');
  const ring = JSON.parse(fsSync.readFileSync(ringFile));
  const groups = new Map();
  for (const n of ring.nodes.filter(t => t.state === 3 && t.size === 0xc000 && t.argument === 0)) {
    if (!groups.has(n.entry)) groups.set(n.entry, []);
    groups.get(n.entry).push(n);
  }
  const matches = [...groups.values()].filter(rows => rows.length === 7);
  if (matches.length !== 1) throw Error('ring: no unique API-worker group (' + matches.length + ')');
  const structs = matches[0].slice(0, 3);
  console.log('ring: 3 API-worker structs at', structs.map(s => '0x' + s.address.toString(16)).join(' '));
  const structVals = [];
  for (const node of structs) {
    const raw = await read(node.address, 0x1c0);
    const vals = {};
    for (let o = 0; o + 8 <= 0x1c0; o += 8) {
      const v = raw.readBigUInt64LE(o);
      if (v > 0x10000n && v < 2n ** 40n && (v & 7n) === 0n) vals[o] = v;
    }
    structVals.push(vals);
  }
  let tpidrOffset = -1, ringGlobal = 0n;
  for (const key of Object.keys(structVals[0])) {
    const off = Number(key);
    const vals = structVals.map(v => v[off]);
    if (vals.some(v => v === undefined) || new Set(vals.map(String)).size < 3) continue;
    const g1 = (await read(Number(vals[0]) + 0x1f8, 8)).readBigUInt64LE();
    const g2 = (await read(Number(vals[1]) + 0x1f8, 8)).readBigUInt64LE();
    if (g1 === g2 && g1 > 0x10000n && g1 < 2n ** 40n) { tpidrOffset = off; ringGlobal = g1; break; }
  }
  if (tpidrOffset < 0) throw Error('ring: tpidr field not found');
  console.log('ring: tpidr at struct+0x' + tpidrOffset.toString(16), 'global 0x' + ringGlobal.toString(16));

  const worker = info.worker;
  if (!worker || !worker.thread) throw Error('no parked worker in state — run the prepare first');
  console.log('parked worker thread struct at 0x' + worker.thread.toString(16));
  const wstruct = await read(worker.thread, 0x1c0);
  const tls = wstruct.readBigUInt64LE(tpidrOffset);
  if (tls <= 0x10000n || tls >= 2n ** 40n) throw Error('worker TLS implausible: 0x' + tls.toString(16));
  const token = (await read(Number(tls) + 0x110, 8)).readBigUInt64LE();
  const global = (await read(Number(tls) + 0x1f8, 8)).readBigUInt64LE();
  console.log('worker TLS 0x' + tls.toString(16), 'token 0x' + token.toString(16), 'global match:', global === ringGlobal);
  if (token === 0n || global !== ringGlobal) throw Error('worker TLS validation failed');
  console.log('=== TLS FOUND AND VALIDATED ===');

  // ---- dispatch: write the frame + patch + release + join ----
  const hipc2Send = async (frame, label) => {
    const cfg = await req({command: 'root-native-worker-hipc2-cfg', frameHex: frame.toString('hex')});
    const patched = await req({command: 'root-native-worker-hipc2-patch', tls: tls.toString()});
    console.log(`${label}: patched (replyArea 0x${patched.replyArea.toString(16)}, handle ${patched.handle})`);
    await req({command: 'root-native-worker-release'});
    const deadline = Date.now() + 30000;
    for (;;) {
      const st = await req({command: 'root-native-worker-state'});
      if (st.finished) break;
      if (Date.now() > deadline) throw Error('worker did not finish (30s) — send may be blocked; not retrying');
      await new Promise(r => setTimeout(r, 100));
    }
    const joined = await req({command: 'root-native-worker-join'});
    const reply = await memory.read(cfg.replyArea, 0x100);
    const sfco = reply.slice(0x10, 0x14).toString() === 'SFCO';
    return {values: joined.values || [], reply, sfco};
  };

  // CONTROL: cmif -> the worker's carried handle (pm:shell cmd 6, expect pid 207)
  const r0 = await hipc2Send(cmifFrame(6), 'CONTROL cmif pm:shell cmd6');
  console.log('CONTROL values', JSON.stringify(r0.values), 'SFCO', r0.sfco);
  const result = r0.sfco ? r0.reply.readUInt32LE(0x1c) : -1;
  const pid = r0.sfco ? r0.reply.readBigUInt64LE(0x20) : -1n;
  console.log(`  result 0x${(result >>> 0).toString(16)} pid ${pid}`);
  if (!r0.sfco) throw Error('CONTROL FAILED — no SFCO; the worker/TLS pipeline is broken, stopping');
  console.log(pid === 207n ? '  <<< CONTROL PASSED' : '  <<< CONTROL replied (unexpected pid)');

  // ---- helper: full cycle per test (prepare → salvage-scan → patch → run) ----
  const runWorker = async (openHandle, frame, label) => {
    // prepare (spawns a parked worker; its internal scan may abandon — fine)
    await req({command: 'root-native-worker-hipc2-prepare', handle: openHandle,
      frameHex: frame.toString('hex')}).catch(e => {
      if (!/abandoned|still active/i.test(String(e.message))) throw e;
      console.log(`  (${label}) prepare abandoned — salvaging the parked worker`);
    });
    const st = await req({command: 'root-native-info'});
    const wk = st.worker;
    if (!wk || !wk.thread) throw Error('no worker in state after prepare');
    // per-worker TLS (each worker has its own)
    const ws = await read(wk.thread, 0x1c0);
    const wtls = ws.readBigUInt64LE(tpidrOffset);
    const wtok = (await read(Number(wtls) + 0x110, 8)).readBigUInt64LE();
    const wglo = (await read(Number(wtls) + 0x1f8, 8)).readBigUInt64LE();
    if (wtls <= 0x10000n || wtok === 0n || wglo !== ringGlobal)
      throw Error(`${label}: worker TLS validation failed (0x${wtls.toString(16)})`);
    console.log(`  (${label}) worker TLS 0x${wtls.toString(16)} validated`);
    const cfg = await req({command: 'root-native-worker-hipc2-cfg', frameHex: frame.toString('hex')});
    await req({command: 'root-native-worker-hipc2-patch', tls: wtls.toString()});
    await req({command: 'root-native-worker-release'});
    const deadline = Date.now() + 30000;
    for (;;) {
      const s2 = await req({command: 'root-native-worker-state'});
      if (s2.finished) break;
      if (Date.now() > deadline) throw Error(`${label}: worker did not finish — send may be blocked; not retrying`);
      await new Promise(r => setTimeout(r, 100));
    }
    const joined = await req({command: 'root-native-worker-join'});
    const reply = await memory.read(cfg.replyArea, 0x100);
    const sfco = reply.slice(0x10, 0x14).toString() === 'SFCO';
    return {values: joined.values || [], reply, sfco};
  };

  // ---- the nvdrv test (slot is free after the control join) ----
  const sm = info.services?.find(s => s.name === 'pm:shell')?.sm;
  const nv = await req({command: 'root-native-sm-service', handle: sm, name: 'nvdrv:t'});
  const nvHandle = nv.moves?.[0];
  console.log('nvdrv:t handle', nvHandle);
  if (nvHandle) {
    for (const [cmd, seq, args, label] of [
      [0, 0, [], 'cmd0 noargs'],
      [2, 0, [], 'cmd2 noargs'],
      [3, 0, [3n], 'cmd3 1arg'],
      [3, 1, [3n], 'cmd3 1arg seq1'],
    ]) {
      const r = await runWorker(nvHandle, hipc2Frame(cmd, seq, args), `HIPC2 nvdrv:t ${label}`);
      const res = r.sfco ? r.reply.readUInt32LE(0x1c) : -1;
      console.log(`  values ${JSON.stringify(r.values)} SFCO ${r.sfco} result 0x${(res >>> 0).toString(16)} reply ${r.reply.subarray(0, 0x30).toString('hex')}`);
      if (r.sfco) { console.log('  <<<*** EUREKA: HIPC2 ANSWERED VIA THE WORKER TLS ***>>>'); break; }
    }
    await req({command: 'root-native-close-handle', handle: nvHandle}).catch(() => {});
  }
  console.log('driver complete');
}

main().catch(e => {console.error(e.stack || e); process.exitCode = 1;});
