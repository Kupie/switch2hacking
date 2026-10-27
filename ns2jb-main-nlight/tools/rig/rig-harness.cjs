// Side-channel experiment harness. Experiments are data: sources under
// experiments/ rebuild to blobs on change and run inside the RO monitor's
// code cave with the stable ABI `void exp(const u64 args[8], u64 out[8])`.
// Nothing console-side restarts between experiments, no experiment code
// ever executes in the fs process, and the harness never writes to NAND.
//
// Exec protocol (0x524f0003), fixed 16-word reply, state is post-op:
//   w0 tag "NRO2EXEC", w1 sub, w2 status (0 = ok),
//   w3 cave address, w4 cave size,
//   w5 expected | offset<<16 | committed<<32 | runs<<40,
//   w6 checksum, w7 detail, w8..w15 run results.
//
// Usage (netns-wrapped, live session):
//   node rig-harness.cjs info                        monitor + cave state
//   node rig-harness.cjs rig <1|2|3|4> [arg]         payload-resident rig subs
//   node rig-harness.cjs load experiments/foo.c      rebuild + upload blob
//   node rig-harness.cjs run experiments/foo.c [n..] upload if stale, execute
//   node rig-harness.cjs clear                       wipe the cave
const path = require('node:path');
const fs = require('node:fs');
const {buildBlob, fnv} = require('../../engine/build-experiment.cjs');

const TAG_EXEC = 0x43584532464f524en; // "NRO2EXEC"
const TAG_RIG = 0x47495232464f524en;  // "NR2FR2IG"
const CHUNK = 184;
const RIG_OUT = {1: 16, 2: 4, 3: 3, 4: 6, 6: 8, 7: 8, 8: 8, 9: 8, 10: 8, 11: 8, 12: 8, 13: 8, 14: 8, 15: 8, 17: 2, 18: 17, 19: 21, 20: 5}; // defined output words per rig sub

// Resolve the live session the way every probe does: latest-session.json.
const latest = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json')));
const {connect} = require(path.join(latest.directory, 'switch2', 'tools', 'fs-memory.cjs'));

let memory;
async function req(command) {
  memory ||= await connect();
  return memory.request(command);
}

function argHex(words) {
  const b = Buffer.alloc(words.length * 8);
  words.forEach((w, i) => b.writeBigUInt64LE(BigInt(w), i * 8));
  return b.toString('hex');
}

function words(data) {
  const out = [];
  for (let i = 0; i + 8 <= data.length; i += 8) out.push(data.readBigUInt64LE(i));
  return out;
}

async function runWorker(request, timeoutMs) {
  await req({command: 'root-native-worker-prepare', ...request});
  await req({command: 'root-native-worker-release'});
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const state = await req({command: 'root-native-worker-state'});
    if (state.finished) break;
    if (Date.now() > deadline) throw Error('rig worker deadline; monitor may be wedged (redeploy the monitor)');
    await new Promise(r => setTimeout(r, 50));
  }
  const joined = await req({command: 'root-native-worker-join'});
  const reply = joined.responses?.[0];
  if (!reply) throw Error('rig worker produced no response');
  return reply;
}

async function worker(hex, timeoutMs, kind = 'ro-exec') {
  const reply = await runWorker({kind, handle: await roHandle(), hex}, timeoutMs);
  if (reply.transport) throw Error('rig request transport error: 0x' + reply.transport.toString(16) +
    ' (monitor session died?)');
  if (reply.result !== 0) throw Error('rig command failed: 0x' + reply.result.toString(16));
  return words(Buffer.from(reply.data, 'hex'));
}

let cachedHandle;
async function roHandle() {
  // One session per harness invocation, closed on exit: the monitor's port
  // accepts only a handful of sessions and leaked handles exhaust it.
  if (cachedHandle !== undefined) return cachedHandle;
  // Wedge gate (v3.6 lesson): sm:GetService('ro:dmnt') BLOCKS until the name
  // registers. If the monitor died after launch, a fresh lookup wedges the
  // fs native worker forever, which wedges the console BASIC loop. Gate on
  // process liveness via pm:dmnt GetProcessInfo BEFORE any sm-get: a dead
  // monitor must fail here, never downstream.
  const info0 = await req({command: 'root-native-info'});
  const executionFile = path.join(latest.directory, 'switch2', 'ro', 'current-execution.json');
  const execution = JSON.parse(fs.readFileSync(executionFile, 'utf8'));
  const pmDmnt = info0.services?.find(s => s.name === 'pm:dmnt')?.handle;
  if (pmDmnt === undefined || !Number(execution.pid))
    throw Error('no pm:dmnt session or execution record for a liveness gate');
  const liveness = await req({command: 'root-native-ipc', handle: pmDmnt, id: 7,
    hex: require(path.join(latest.directory, 'switch2', 'tools', 'fs-memory.cjs'))
      .encodeU64(BigInt(execution.pid)).toString('hex')});
  if (liveness.result) throw Error('monitor pid ' + execution.pid +
    ' is dead (pm:dmnt 0x' + liveness.result.toString(16) + '); redeploy before any sm-get');
  const sm = info0.services?.find(s => s.name === 'pm:shell')?.sm;
  if (!sm) throw Error('no borrowed SM client for the ro:dmnt lookup');
  const reply = await runWorker({kind: 'sm-get', handle: sm, name: 'ro:dmnt'}, 15000);
  if (reply.transport || reply.result) throw Error('ro:dmnt lookup failed: 0x' +
    (reply.result ?? reply.transport).toString(16));
  cachedHandle = reply.handle;
  return cachedHandle;
}

async function closeSession() {
  if (cachedHandle === undefined) return;
  await req({command: 'root-native-close-handle', handle: cachedHandle}).catch(() => {});
  cachedHandle = undefined;
}

function state(w) {
  return {cave: w[3], caveSize: w[4], expected: w[5] & 0xffffn, offset: (w[5] >> 16n) & 0xffffn,
    committed: (w[5] >> 32n) & 0xffn, runs: (w[5] >> 40n) & 0xffffffn,
    checksum: w[6], detail: w[7]};
}

async function execCall(sub, args, timeoutMs = 30000, extraHex = '') {
  const w = await worker(argHex([sub, ...args]) + extraHex, timeoutMs);
  if (w[0] !== TAG_EXEC) throw Error('unexpected reply tag 0x' + w[0].toString(16) + ' (monitor predates the exec rig)');
  if (w[2] !== 0n) throw Error('exec sub ' + sub + ' status 0x' + w[2].toString(16) +
    ' detail 0x' + w[7].toString(16) + ' codes ' +
    [w[16], w[17], w[18] & 0xffffffffn].map(v => '0x' + v.toString(16)).join(' | '));
  return w;
}

function buildBlobChecked(source) {
  const image = buildBlob(source);
  return {image, digest: '0x' + fnv(image).toString(16)};
}

async function upload(source) {
  const {image, digest} = buildBlobChecked(source);
  let w = await execCall(1, [BigInt(image.length)]);
  let s = state(w);
  if (s.expected !== BigInt(image.length) || s.offset !== 0n)
    throw Error('begin post-state differs: ' + JSON.stringify(s, (k, v) => typeof v === 'bigint' ? String(v) : v));
  for (let offset = 0; offset < image.length; offset += CHUNK) {
    const part = image.subarray(offset, Math.min(offset + CHUNK, image.length));
    w = await execCall(2, [BigInt(offset), BigInt(part.length)], 30000, part.toString('hex'));
    s = state(w);
    if (s.offset !== BigInt(offset + part.length))
      throw Error('chunk post-state differs at offset ' + offset + ': ' +
        JSON.stringify(s, (k, v) => typeof v === 'bigint' ? String(v) : v));
  }
  w = await execCall(3, [BigInt(image.length), digest]);
  s = state(w);
  if (s.checksum !== BigInt(digest)) throw Error('blob checksum mismatch: monitor saw 0x' + s.checksum.toString(16));
  if (s.committed !== 1n) throw Error('commit did not verify: ' + JSON.stringify(s, (k, v) => typeof v === 'bigint' ? String(v) : v));
  return {size: image.length, digest, state: s};
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  if (command === 'info') {
    const s = state(await execCall(0, []));
    console.log(JSON.stringify({cave: '0x' + s.cave.toString(16), caveSize: s.caveSize.toString(),
      expected: s.expected.toString(), uploaded: s.offset.toString(), committed: s.committed.toString(),
      runs: s.runs.toString(), checksum: '0x' + s.checksum.toString(16)}, null, 2));
  } else if (command === 'rig') {
    const sub = Number(rest[0]), arg = rest[1] ? BigInt(rest[1]) : 0n;
    if (!RIG_OUT[sub]) throw Error('rig sub must be 1..4, 6..15');
    const w = await worker(argHex([sub, arg]), 60000, 'ro-rig');
    if (w[0] !== TAG_RIG) throw Error('unexpected rig reply tag');
    const out = w.slice(3, 3 + RIG_OUT[sub]);
    console.log(JSON.stringify({sub, arg: arg.toString(), out: out.map(String)}, null, 2));
    if (sub === 2) console.log(JSON.stringify({regs: {ctr: '0x' + out[0].toString(16),
      cntfrq: out[1].toString(), dczid: out[2].toString(), tpidrro: '0x' + out[3].toString(16)}}));
    if (sub === 7) console.log(JSON.stringify({evictProbe: {cntfrq: out[0].toString(),
      hot: out[1].toString(), hotControl: out[2].toString(), postStoreEvict: out[3].toString(),
      postLoadEvict: out[4].toString(), evictStoreCost: out[5].toString(),
      evictLoadCost: out[6].toString(), liveness: out[7].toString()}}));
    if (sub === 8) console.log(JSON.stringify({chaseEvict: {cntfrq: out[0].toString(),
      hotMin: out[1].toString(), postChaseMin: out[2].toString(), postStrideMin: out[3].toString(),
      rewarmMin: out[4].toString(), chaseCost: out[5].toString(),
      strideCost: out[6].toString(), liveness: out[7].toString()}}));
    if (sub === 11) console.log(JSON.stringify({fullChase: {cntfrq: out[0].toString(),
      hotMin: out[1].toString(), postWalkMin: out[2].toString(), postStrideMin: out[3].toString(),
      walkMin: out[4].toString(), strideMin: out[5].toString(), sameLineMin: out[6].toString(),
      liveness: out[7].toString()}}));
    if (sub === 15) console.log(JSON.stringify({debugProbe: {dbgHandle: out[0].toString(),
      activeResult: out[1].toString(), readResult: out[2].toString(), writeResult: out[3].toString(),
      listResult: out[4].toString(), readLo: out[5].toString(), readHi: out[6].toString(),
      listCount: out[7].toString()}}));
    if (sub === 14) console.log(JSON.stringify({l3pp: {cycles: out[0].toString(),
      minPrime: out[1].toString(), minProbe: out[2].toString(), maxProbe: out[3].toString(),
      sumProbe: out[4].toString(), countHigh: out[5].toString(), maxDelta: out[6].toString(),
      liveness: out[7].toString()}}));
    if (sub === 13) console.log(JSON.stringify({capacity: {cntfrq: out[0].toString(),
      lines1024: out[1].toString(), lines2048: out[2].toString(),
      lines4096: out[3].toString(), lines8192: out[4].toString(),
      lines16384: out[5].toString(), sameLineMin: out[6].toString(),
      liveness: out[7].toString()}}));
    if (sub === 10) console.log(JSON.stringify({allocDiscrim: {cntfrq: out[0].toString(),
      sameLineMin: out[1].toString(), walkP1: out[2].toString(), walkP2: out[3].toString(),
      walkP3: out[4].toString(), hotMin: out[5].toString(), postWalkMin: out[6].toString(),
      liveness: out[7].toString()}}));
    if (sub === 9) console.log(JSON.stringify({evictCycle: {cntfrq: out[0].toString(),
      hotMin: out[1].toString(), postChaseMin: out[2].toString(), postStrideMin: out[3].toString(),
      chaseMin: out[4].toString(), strideMin: out[5].toString(),
      dczid: out[6].toString(), liveness: out[7].toString()}}));
    if (sub === 4) console.log(JSON.stringify({spectre: {bestSlot: out[0].toString(), best: out[1].toString(),
      secondSlot: out[2].toString(), second: out[3].toString(), hits: out[4].toString(),
      secret: out[5].toString(), expected: arg.toString()}}));
  } else if (command === 'load') {
    const source = rest[0];
    if (!source?.endsWith('.c')) throw Error('load needs an experiments/*.c source');
    console.log(JSON.stringify({uploaded: await upload(path.resolve(source))}, (k, v) => typeof v === 'bigint' ? String(v) : v));
  } else if (command === 'run') {
    const source = rest[0];
    if (!source?.endsWith('.c')) throw Error('run needs an experiments/*.c source');
    const args = rest.slice(1).map(v => BigInt(v.startsWith('0x') ? v : v));
    while (args.length < 8) args.push(0n);
    console.log(JSON.stringify({uploaded: await upload(path.resolve(source))}, (k, v) => typeof v === 'bigint' ? String(v) : v));
    const w = await execCall(4, args, 60000);
    const detail = w[7];
    console.log(JSON.stringify({run: {mode: detail.toString(),
      codes: [w[16], w[17], w[18] & 0xffffffffn].map(v => '0x' + v.toString(16)),
      mappedFallback: (w[18] >> 32n).toString(),
      out: w.slice(8, 16).map(String), outHex: w.slice(8, 16).map(v => '0x' + v.toString(16))}}, null, 2));
  } else if (command === 'probe') {
    const out = await worker('a1b2c3d4e5f60718', 60000, 'ro-probe');
    console.log(JSON.stringify({tag: '0x' + out[0].toString(16), echo: '0x' + out[1].toString(16),
      pid: out[2].toString(), tid: out[3].toString(), tick: out[4].toString(),
      registration: '0x' + out[5].toString(16),
      ro1Low32: '0x' + (out[5] & 0xffffffffn).toString(16),
      rodmntHigh32: '0x' + (out[5] >> 32n).toString(16)}));
  } else if (command === 'clear') {
    const s = state(await execCall(5, []));
    console.log(JSON.stringify({cleared: true, committed: s.committed.toString()}));
  } else {
    throw Error('usage: rig-harness.cjs info|rig|load|run|clear');
  }
}

main().then(closeSession).catch(async e => {console.error(e.message); await closeSession(); process.exitCode = 1;});
