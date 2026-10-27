// Debug-relay driver: commands the creport-policy executor through the RO
// monitor. The executor (second process, title 0x0400000000000036) attaches
// to processes with DebugActiveProcess(0x60) and reads them with
// ReadDebugProcessMemory(0x6A) - the strongest policy on the console.
//
// Path: PC -> console app worker -> ro:dmnt session -> monitor rig subs:
//   sub 17 (put): queue {op, a0, a1, a2} for the executor's next poll
//   sub 18 (get): read the latest executor report {seq, status, op,
//                 result, value, data[12]}
//
// Usage (netns-wrapped, live session with a deployed executor):
//   node debug-relay.cjs status                 show the latest report
//   node debug-relay.cjs ping                    executor self-test
//   node debug-relay.cjs attach <pid>            DebugActiveProcess
//   node debug-relay.cjs read <handle> <addr> <size>
//   node debug-relay.cjs close <handle>          detach (frees the target)
//   node debug-relay.cjs event <handle>          GetDebugEvent
//   node debug-relay.cjs query <handle> <addr>    QueryDebugProcessMemory
//
// Report status bits: 0x1 sm connected, 0x2 ro:dmnt session, 0x4 transport
// error, 0x8 reply error, 0x10 sm connect failed.
const path = require('node:path');
const fs = require('node:fs');
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
    if (Date.now() > deadline) throw Error('relay worker deadline');
    await new Promise(r => setTimeout(r, 50));
  }
  const joined = await req({command: 'root-native-worker-join'});
  const reply = joined.responses?.[0];
  if (!reply) throw Error('relay worker produced no response');
  return reply;
}

let cachedHandle;
let relayClient;
async function roHandle() {
  if (cachedHandle !== undefined) return cachedHandle;
  const info0 = await req({command: 'root-native-info'});
  // Liveness gate (v3.6 lesson): never sm-get through a dead monitor.
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
  // The OWNED qualification ro:dmnt session (the rig session the walk and all
  // rig probes use) carries relay packets too — the worker's ro-relay kind
  // accepts exactly this handle. The sm-get path burns the fs process's
  // ro:dmnt session budget (0x615 on live sessions) — never open a fresh one.
  let owned = info0.services?.find(s => s.name === 'ro:dmnt')?.handle;
  if (owned === undefined) {
    // The deploys cycle the donor and invalidate the wave-side captured
    // sessions. Fall back to the Client-based owned session (the same
    // ro:dmnt qualification session the rig client uses).
    const {Client} = require(path.join(latest.directory, 'switch2', 'process', 'client.cjs'));
    const client = new Client();
    await client.open();
    cachedHandle = client.handle;
    relayClient = client;
    return cachedHandle;
  }
  if (owned === undefined) throw Error('no owned ro:dmnt rig session in state.services');
  cachedHandle = owned;
  return cachedHandle;
}

async function relay(hex, timeoutMs = 30000) {
  const reply = await runWorker({kind: 'ro-relay', handle: await roHandle(), hex}, timeoutMs);
  if (reply.transport) throw Error('relay transport error 0x' + reply.transport.toString(16));
  if (reply.result !== 0) throw Error('relay command failed 0x' + reply.result.toString(16));
  return words(Buffer.from(reply.data, 'hex'));
}

async function relayPut(op, a0 = 0n, a1 = 0n, a2 = 0n) {
  return relay(argHex([17n, op, a0, a1, a2]));
}

async function relayGet() {
  const w = await relay(argHex([18n, 0n, 0n, 0n, 0n]));
  // w = [tag, sub, status, seq, report[0..15]]
  return {seq: w[3], report: w.slice(4)};
}

async function awaitReport(lastSeq, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const {seq, report} = await relayGet();
    if (seq > lastSeq) return {seq, report};
    if (Date.now() > deadline) throw Error('executor report timeout (is the executor running? node deploy-monitor.cjs --second --policy=0400000000000036)');
    await new Promise(r => setTimeout(r, 100));
  }
}

const json = value => JSON.stringify(value, (_, v) => typeof v === 'bigint' ? '0x' + v.toString(16) : v, 1);

function describe(report) {
  const status = Number(report[1]), op = Number(report[2]);
  const bits = [];
  if (status & 1) bits.push('sm');
  if (status & 2) bits.push('session');
  if (status & 4) bits.push('transport-err');
  if (status & 8) bits.push('reply-err');
  if (status & 0x10) bits.push('sm-failed');
  return {status: '0x' + status.toString(16), bits, op,
    result: '0x' + Number(report[3] & 0xffffffffn).toString(16),
    value: '0x' + report[4].toString(16),
    data: report.slice(5).map(w => '0x' + w.toString(16))};
}

async function main() {
  const [cmd, ...args] = process.argv.slice(2);
  try {
    if (!cmd || cmd === 'status') {
      const {seq, report} = await relayGet();
      console.log(json({seq, ...describe(report)}));
    } else if (cmd === 'ping') {
      const {seq} = await relayGet();
      await relayPut(4n);
      const {report} = await awaitReport(seq);
      console.log(json({ping: report[9] === 0x32474e5050415045n ? 'OK' : 'BAD', ...describe(report)}));
    } else if (cmd === 'attach') {
      const pid = BigInt(args[0]);
      const {seq} = await relayGet();
      await relayPut(1n, pid);
      const {report} = await awaitReport(seq);
      const d = describe(report);
      console.log(json({...d,
        attached: Number(report[3]) === 0, debugHandle: report[4]}));
    } else if (cmd === 'read') {
      const handle = BigInt(args[0]), addr = BigInt(args[1]), size = BigInt(args[2] || 8n);
      const {seq} = await relayGet();
      await relayPut(2n, handle, addr, size);
      const {report} = await awaitReport(seq);
      console.log(json(describe(report)));
    } else if (cmd === 'close') {
      const handle = BigInt(args[0]);
      const {seq} = await relayGet();
      await relayPut(3n, handle);
      const {report} = await awaitReport(seq);
      console.log(json(describe(report)));
    } else if (cmd === 'event' || cmd === 'query' || cmd === 'ctx') {
      const handle = BigInt(args[0]), a1 = BigInt(args[1] || 0n);
      const op = cmd === 'event' ? 5n : cmd === 'query' ? 6n : 7n;
      const {seq} = await relayGet();
      await relayPut(op, handle, a1);
      const {report} = await awaitReport(seq);
      console.log(json(describe(report)));
    } else if (cmd === 'gsh') {
      // OP_GSH: the executor-process GSH (the only GSH recipe proven on
      // fw23). result = init_t<<32 | gsh_t, value = init_echo<<32 | handle.
      const name = args[0];
      if (!/^[a-z0-9:-]{1,8}$/.test(name)) throw Error('name must be <= 8 chars');
      let nameU64 = 0n;
      for (let i = 0; i < name.length; i++) nameU64 |= BigInt(name.charCodeAt(i)) << BigInt(8 * i);
      const {seq} = await relayGet();
      await relayPut(8n, nameU64);
      const {report} = await awaitReport(seq, 30000);
      const d = describe(report);
      const r0 = report[3];
      console.log(json({...d,
        init_t: '0x' + (r0 >> 32n).toString(16), gsh_t: '0x' + (r0 & 0xffffffffn).toString(16),
        init_echo: '0x' + (report[4] >> 32n).toString(16),
        session: '0x' + (report[4] & 0xffffffffn).toString(16)}));
    } else if (cmd === 'cmif') {
      // OP_CMIF: arbitrary TIPC send from the executor: handle, {cmd|token<<32}, arg.
      const handle = BigInt(args[0]), command = BigInt(args[1]), arg = BigInt(args[2] || 0n);
      const token = BigInt(args[3] || 2n);
      const {seq} = await relayGet();
      await relayPut(9n, handle, command | (token << 32n), arg);
      const {report} = await awaitReport(seq, 30000);
      console.log(json(describe(report)));
    } else throw Error('unknown command: ' + cmd);
  } finally {
    if (relayClient) await relayClient.close().catch(() => {});
    else if (cachedHandle !== undefined)
      await req({command: 'root-native-close-handle', handle: cachedHandle}).catch(() => {});
  }
}

main().catch(e => {console.error(e.stack ?? e.message); process.exitCode = 1;});
