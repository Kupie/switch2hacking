'use strict';
// HIPC2 via the fs-text patch sender.
//
// The fw23 W^X wall kills self-execution (the exec cave) and the SDK has no
// sender (pre-HIPC2) — but the fs process holds the service handles, has a
// correct OS TLS, and the 0x524F0014 patch op is proven (the boot's own
// instruction challenge). Design: a 48-byte stub (3 patch blocks) replaces
// the owned notifier's GetEventHandle head; the notifier-probe trigger
// executes it IN THE FS PROCESS; the stub sends the staged HIPC2 frame via
// svc #0x22 (x0=frame, x1=wc*4, w2=handle — the executor-proven ABI, no TLS
// needed); the reply lands in the staged buffer; we fetch + restore.
//
// Usage: node hipc2-fs-patch-client.cjs <service> <cmd> [u64 args...]
//   node hipc2-fs-patch-client.cjs pm:shell 6          # the control (cmif-known answer)
//   node hipc2-fs-patch-client.cjs nvdrv:t 3 0 0x1234   # the ioctl sweep
const fs = require('node:fs/promises');
const path = require('node:path');
// The run dir is self-contained (connection.json + engine copies); resolve
// everything through latest-session.json like the other drivers.
const latest = JSON.parse(require('node:fs').readFileSync(path.join(__dirname, '..', '..', 'latest-session.json'), 'utf8'));
const RUN = latest.directory;
const {Client, check, read} = require(path.join(RUN, 'switch2', 'process', 'client.cjs'));

function buildStub(frameAddr, sendSize, handle) {
  // 12 instructions = 48 bytes = 3 x 16-byte patch blocks.
  const A = BigInt(frameAddr), S = BigInt(sendSize), H = BigInt(handle);
  const w = [];
  const movz = (imm, rd, sf) => ((sf ? 0xD2800000 : 0x52800000) | ((Number(imm) & 0xffff) << 5) | rd) >>> 0;
  const movk = (imm, rd, sf, hw) => (((sf ? 0xF2800000 : 0x72800000) | (hw << 21) | ((Number(imm) & 0xffff) << 5) | rd)) >>> 0;
  w.push(0xd503245f);                       // the proven landing hint (author's stub head)
  w.push(movz(A & 0xffffn, 0, 1));          // x0 = frame
  w.push(movk((A >> 16n) & 0xffffn, 0, 1, 1));
  w.push(movk((A >> 32n) & 0xffffn, 0, 1, 2));
  w.push(movk((A >> 48n) & 0xffffn, 0, 1, 3));
  w.push(movz(S & 0xffffn, 1, 1));          // x1 = send size (wc*4, < 64KB)
  w.push(movz(H & 0xffffn, 2, 0));         // w2 = session handle
  w.push(movk((H >> 16n) & 0xffffn, 2, 0, 1));
  w.push(0xd4000440);                       // svc #0x22
  w.push(0xd65f03c0);                       // ret — w0 = the svc result
  w.push(0xd503201f, 0xd503201f);           // pad
  const buf = Buffer.alloc(48);
  w.forEach((word, i) => buf.writeUInt32LE(word, i * 4));
  return [buf.subarray(0, 16), buf.subarray(16, 32), buf.subarray(32, 48)];
}

function buildFrame(cmd, args) {
  const wc = 8 + 2 * args.length;
  const b = Buffer.alloc(0x40);
  b.writeUInt32LE(6, 0); b.writeUInt32LE(wc, 4);      // {6, wc}
  b.write('SFCI', 0x10); b.writeUInt32LE(1, 0x14);   // magic + token
  b.writeUInt32LE(cmd, 0x18); b.writeUInt32LE(0, 0x1c);
  args.forEach((a, i) => b.writeBigUInt64LE(BigInt(a), 0x20 + 8 * i));
  return {buffer: b, sendSize: wc * 4};
}

async function main() {
  const invalidMode = process.argv.includes('--invalid');
  const rest = process.argv.slice(2).filter(a => a !== '--invalid');
  const service = rest[0] ?? 'pm:shell';
  const cmd = Number(rest[1] ?? 6);
  const args = rest.slice(2).map(a => BigInt(a));
  check(Number.isInteger(cmd) && cmd >= 0 && cmd <= 0xffff && args.length <= 4, 'Bad command line');
  // --invalid: the no-wedge control. The stub sends to a deliberately bogus
  // handle: svc 0x22 must return a clean error immediately, the probe must
  // complete (no pending worker), and the restore must run. If THIS wedges,
  // the block is in our stub/svc, not the target service's dispatch.
  const INVALID_HANDLE = 0x7bad0001;

  const c = await new Client().open(), m = c.memory;
  const record = {service, cmd, args: args.map(String), started: new Date().toISOString()};
  const log = o => { Object.assign(record, o); console.log(JSON.stringify(o)); };
  await log({stage: 'open', session: m.info.session});

  const fsHandle = await c.fsProcess();
  const identity = await c.info(fsHandle);
  check(!identity.result && identity.programId === '0400000000000000', 'Target is not native FS');
  const pid = identity.pid;
  await log({stage: 'fs-identity', pid});

  const notifier = await read(path.join(RUN, 'switch2', 'ro', m.info.session + '-notifier-proof.json'));
  check(notifier.identityVerified && notifier.session === m.info.session, 'Notifier proof mismatch');
  const state = await m.request({command: 'root-native-info'});
  const notifierHandle = state.notifiers[0];
  check(notifierHandle && state.worker.joined, 'Notifier or worker state missing');
  const table = await m.pointer(notifier.E);
  const targetAddr = BigInt(await m.pointer(table + 4 * 8));
  check((targetAddr & 0xfffn) + 48n <= 0x1000n, 'The 48-byte stub would cross a page');
  await log({stage: 'target', target: targetAddr.toString()});

  const orig = await c.read(fsHandle, pid, targetAddr, 48);
  check(!orig.result, 'Read of the stub site failed');
  const blocks = [0, 16, 32].map(o => Buffer.from(orig.hex.slice(o * 2, (o + 16) * 2), 'hex'));
  await log({stage: 'original', hex: orig.hex});

  let handle;
  if (invalidMode) {
    handle = INVALID_HANDLE;
    await log({stage: 'service', name: service, handle, invalidMode: true});
  } else {
    // The proven service-open path (the dispatch command, unlike the RO-worker sm-get).
    const info2 = await m.request({command: 'root-native-info'});
    const sm = info2.services.find(s => s.name === 'pm:shell')?.sm;
    check(sm, 'The borrowed initialized FS SM client is missing');
    const open = await m.request({command: 'root-native-sm-service', handle: sm, name: service});
    check(!open.result && open.moves?.length, 'Service open failed: 0x' + (open.result >>> 0).toString(16));
    handle = open.moves[0];
    await log({stage: 'service', name: service, handle});
  }

  const frame = buildFrame(cmd, args);
  const staged = await m.request({command: 'root-hipc2-stage', hex: frame.buffer.toString('hex')});
  const frameAddr = BigInt(staged.address);
  await log({stage: 'staged', address: staged.address, sendSize: frame.sendSize});

  const stub = buildStub(frameAddr, frame.sendSize, handle);
  const installed = [];
  let trigger = null, triggerError = null;
  try {
    for (let i = 0; i < 3; i++) {
      const reply = await c.patch(fsHandle, pid, targetAddr + 16n * BigInt(i), blocks[i], stub[i]);
      check(!reply.result && reply.expectedMatched && reply.readbackMatched, 'Patch install failed at block ' + i);
      installed.push(i);
    }
    await log({stage: 'installed', blocks: installed.length});
    try { trigger = await c.worker({kind: 'notifier-probe', handle: notifierHandle}); }
    catch (e) { triggerError = e; }
    const fetched = await m.request({command: 'root-hipc2-fetch',
      address: Number(frameAddr), length: 0x40});
    await log({stage: 'trigger',
      svcResult: trigger ? trigger.result : null,
      transport: trigger?.transport ?? null,
      copies: trigger?.copies?.length ?? null,
      triggerError: triggerError ? String(triggerError.message).slice(0, 120) : null,
      replyFrame: fetched.hex});
  } finally {
    for (const i of installed.reverse()) {
      const reply = await c.patch(fsHandle, pid, targetAddr + 16n * BigInt(i), stub[i], blocks[i]);
      check(!reply.result && reply.readbackMatched, 'RESTORE FAILED at block ' + i);
    }
    const back = await c.read(fsHandle, pid, targetAddr, 48);
    await log({stage: 'restored', ok: back.hex === orig.hex});
    check(back.hex === orig.hex, 'Restored bytes differ');
  }
  await c.close();
  console.log(JSON.stringify({done: true, service, cmd, session: m.info.session}));
}

main().catch(e => { console.error(JSON.stringify({error: String(e.message).slice(0, 200)})); process.exitCode = 1; });
