// HIPC2 via the exec-cave blob (experiments/hipc2.c) — svc 0x22 transport.
// Control first: pm:shell cmd 6 (GetApplicationProcessIdForShell) — expect
// SFCO + pid 207. Then the target service.
//
// Usage: node hipc2-cave-client.cjs [service] [--control-only]
'use strict';
const fsSync = require('node:fs');
const path = require('node:path');
const {buildBlob, fnv} = require('../../engine/build-experiment.cjs');
const latest = JSON.parse(fsSync.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json')));
const {connect} = require(path.join(latest.directory, 'switch2', 'tools', 'fs-memory.cjs'));

let seq = 1;
const SFCI = 0x49434653n, SFCO = 0x4f434653n;

async function main() {
  const memory = await connect();
  const req = c => memory.request(c);
  const info = await req({command: 'root-native-info'});
  console.log('session', info.session);

  // rig session: reuse an owned ro:dmnt (the budget) or open fresh
  let rig = (info.services || []).filter(s => s.name === 'ro:dmnt').pop()?.handle;
  if (!rig) {
    const sm = info.services?.find(s => s.name === 'pm:shell')?.sm;
    const open = await req({command: 'root-native-sm-service', handle: sm, name: 'ro:dmnt'});
    if (open.result) throw Error('ro:dmnt open failed: 0x' + open.result.toString(16));
    rig = open.moves?.[0];
    console.log('opened fresh ro:dmnt', rig);
  } else console.log('reusing owned ro:dmnt', rig);

  const worker = async hex => {
    console.log('  [worker] hex ' + hex.length / 2 + ' bytes...');
    await req({command: 'root-native-worker-prepare', kind: 'ro-exec', handle: rig, hex});
    console.log('  [worker] prepared');
    await req({command: 'root-native-worker-release'});
    const deadline = Date.now() + 20000;
    for (;;) {
      const st = await req({command: 'root-native-worker-state'});
      if (st.finished) break;
      if (Date.now() > deadline) throw Error('rig worker deadline');
      await new Promise(r => setTimeout(r, 50));
    }
    const joined = await req({command: 'root-native-worker-join'});
    const reply = joined.responses?.[0];
    if (!reply) throw Error('no rig response');
    if (reply.transport) throw Error('rig transport 0x' + reply.transport.toString(16));
    if (reply.result) throw Error('rig result 0x' + reply.result.toString(16));
    const data = Buffer.from(reply.data, 'hex');
    const w = [];
    for (let i = 0; i + 8 <= data.length; i += 8) w.push(data.readBigUInt64LE(i));
    if (w[0] !== 0x43584532464f524en) throw Error('bad NRO2EXEC tag: ' + w[0].toString(16));
    if (w[2] !== 0n) throw Error('exec status 0x' + w[2].toString(16) + ' detail ' + w[7].toString(16) +
      ' codes ' + (w[8 + 8] || 0n) + '/' + (w[8 + 9] || 0n) + '/' + (w[8 + 10] || 0n));
    return w.slice(8, 16);   // out[0..7]
  };
  const rigHex = words => Buffer.concat(words.map(x => {
    const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(x)); return b;
  })).toString('hex');

  // pre-built blob (build OUTSIDE the netns: node engine/build-experiment.cjs
  // experiments/hipc2.c) — never compile inside the runuser environment
  const blob = fsSync.readFileSync(path.join(__dirname, 'experiments', 'build', 'hipc2.bin'));
  const fnv64 = '0x' + fnv(blob).toString(16);
  console.log('blob', blob.length, 'bytes fnv', fnv64);
  await worker(rigHex([1n, BigInt(blob.length)]));
  const chunks = [];
  for (let off = 0; off < blob.length; off += 184) {
    const part = blob.subarray(off, Math.min(off + 184, blob.length));
    chunks.push(rigHex([2n, BigInt(off), BigInt(part.length)]) + part.toString('hex'));
  }
  for (const c of chunks) await worker(c);
  const commit = await worker(rigHex([3n, 0n, BigInt(fnv64)]));
  console.log('committed:', commit[5] ? 'YES' : 'NO', 'cave', commit[3].toString(16));
  console.log('UPLOAD COMPLETE');

  // sub 4 requires >= 80 bytes (10 words): {sub, args[8], pad}
  const run = (handle, wc, sfciToken, cmdSeq, a3, a4, a5, a6) =>
    worker(rigHex([4n, (BigInt(wc) << 32n) | BigInt(handle), sfciToken, cmdSeq, a3, a4, a5, a6, 0n, 0n]));

  if (process.argv.includes('--upload-only')) { console.log('(upload-only mode)'); return; }
  const parse = (tag, out) => {
    const magic = out[2] & 0xffffffffn;
    const ok = magic === SFCO;
    console.log(tag + ':', ok ? 'SFCO ✓' : 'NO SFCO (request frame still in buffer = transport failed)',
      '| out words:', out.map(x => x.toString(16)).join(' '));
    return ok;
  };

  // CONTROL: pm:shell cmd 6, wc 8 (no args)
  const sm = info.services?.find(s => s.name === 'pm:shell')?.sm;
  const pmOpen = await req({command: 'root-native-sm-service', handle: sm, name: 'pm:shell'});
  if (pmOpen.result) throw Error('pm:shell open failed: 0x' + pmOpen.result.toString(16));
  const pmHandle = pmOpen.moves?.[0];
  const out = await run(pmHandle, 8, SFCI | (1n << 32n), 6n | (BigInt(seq++) << 32n), 0n, 0n, 0n, 0n);
  const ok = parse('CONTROL pm:shell cmd6', out);
  if (ok) {
    const result = Number(out[3] >> 32n) || Number(out[2] >> 32n);
    console.log('  token/cmd echo out[2..3]; pid candidates out[4]:', out[4]?.toString(),
      '(expect 207 if layout matches)');
  }
  await req({command: 'root-native-close-handle', handle: pmHandle}).catch(() => {});
  if (!ok || process.argv.includes('--control-only')) return;

  // TARGET
  const name = process.argv[2] || 'nvdrv:t';
  const svc = await req({command: 'root-native-sm-service', handle: sm, name});
  if (svc.result) throw Error(name + ' open failed: 0x' + svc.result.toString(16));
  const h = svc.moves?.[0];
  console.log(name, 'handle', h);
  for (const [cmd, wc, a3] of [[0, 8, 0n], [2, 8, 0n], [3, 10, 3n], [4, 8, 0n]]) {
    const o = await run(h, wc, SFCI | (1n << 32n), BigInt(cmd) | (BigInt(seq++) << 32n), a3, 0n, 0n, 0n);
    if (parse(name + ' cmd ' + cmd, o)) { console.log('  <<<*** HIPC2 UNLOCKED ***>>>'); break; }
  }
  await req({command: 'root-native-close-handle', handle: h}).catch(() => {});
}

main().catch(e => {console.error(e.stack || e); process.exitCode = 1;});
