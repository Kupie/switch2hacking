'use strict';
// HIPC2 round 7 — the sender-call stub (the fs binary's OWN sender).
//
// The fw23 transport = svc 0x21 with the handle in x0 (the old register
// ABI — svc 0x22 from fs = the wedge, round 5/6). Instead of hand-rolling
// the TLS dance, the stub CALLS the fs's own HIPC2 sender function:
//   noarg sender entry @ fs-text+0x212ea0 (FUN_5992212ea0, live base):
//     (x0 = proxy, x1 = outPtr [receives 13 reply bytes], x2 = cmd)
//     reads the handle from [x0+4], builds {6,8}+SFCI+cmd+seq in the
//     CALLING THREAD'S TLS, svc 0x21 (x0=handle) via the +0x1280 wrapper,
//     parses the reply, copies the first 13 payload bytes to [x1],
//     returns w0 = the result. The fake proxy = 8 bytes {0, handle}.
//
// The stub = EXACTLY 16 instructions = 4 patch blocks:
//   hint; x0=proxy (4); x1=out (4); w2=cmd (1); x16=sender (4); blr x16; ret
//
// Usage: node hipc2-sender-stub.cjs <service> <cmd>
//   node hipc2-sender-stub.cjs pm:shell 6     # the control (expect pid 207)
//   node hipc2-sender-stub.cjs nvdrv:t 0      # the first real target
const fsSync = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fsSync.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json'), 'utf8'));
const RUN = latest.directory;
const {Client, check, read} = require(path.join(RUN, 'switch2', 'process', 'client.cjs'));

const NOARG_SENDER = 0x212ea0n;         // FUN_5992212ea0 entry (offset within the text region)
const SENDER_PROLOGUE = '7f2303d5ff4301d1fd7b03a9f44f04a9fdc30091'; // + the core head mov x9,#6

function buildStub(proxyAddr, outAddr, cmd, senderAddr) {
  const w = [];
  const movz = (imm, rd, sf) => ((sf ? 0xD2800000 : 0x52800000) | ((Number(imm) & 0xffff) << 5) | rd) >>> 0;
  const movk = (imm, rd, sf, hw) => (((sf ? 0xF2800000 : 0x72800000) | (hw << 21) | ((Number(imm) & 0xffff) << 5) | rd)) >>> 0;
  const P = BigInt(proxyAddr), O = BigInt(outAddr), S = BigInt(senderAddr), C = BigInt(cmd);
  w.push(0xd503245f);                                    // the proven landing hint
  w.push(movz(P & 0xffffn, 0, 1)); w.push(movk((P >> 16n) & 0xffffn, 0, 1, 1));
  w.push(movk((P >> 32n) & 0xffffn, 0, 1, 2)); w.push(movk((P >> 48n) & 0xffffn, 0, 1, 3));
  w.push(movz(O & 0xffffn, 1, 1)); w.push(movk((O >> 16n) & 0xffffn, 1, 1, 1));
  w.push(movk((O >> 32n) & 0xffffn, 1, 1, 2)); w.push(movk((O >> 48n) & 0xffffn, 1, 1, 3));
  w.push(movz(C & 0xffffn, 2, 0));
  w.push(movz(S & 0xffffn, 16, 1)); w.push(movk((S >> 16n) & 0xffffn, 16, 1, 1));
  w.push(movk((S >> 32n) & 0xffffn, 16, 1, 2)); w.push(movk((S >> 48n) & 0xffffn, 16, 1, 3));
  w.push(0xd63f0200);                                    // blr x16
  w.push(0xd65f03c0);                                    // ret — w0 = the sender's result
  const buf = Buffer.alloc(64);
  w.forEach((word, i) => buf.writeUInt32LE(word, i * 4));
  return [buf.subarray(0, 16), buf.subarray(16, 32), buf.subarray(32, 48), buf.subarray(48, 64)];
}

async function main() {
  const service = process.argv[2] ?? 'pm:shell';
  const cmd = Number(process.argv[3] ?? 6);
  check(Number.isInteger(cmd) && cmd >= 0 && cmd <= 0xffff, 'Bad command line');

  const c = await new Client().open(), m = c.memory;
  const log = o => console.log(JSON.stringify(o));
  await log({stage: 'open', session: m.info.session});

  const fsHandle = await c.fsProcess();
  const identity = await c.info(fsHandle);
  check(!identity.result && identity.programId === '0400000000000000', 'Target is not native FS');
  const pid = identity.pid;
  await log({stage: 'fs-identity', pid});

  // The fs text base = ASLR'd per boot: derive it from the live region
  // containing the vtable target (same firmware = same region offsets).
  const notifier0 = await read(path.join(RUN, 'switch2', 'ro', m.info.session + '-notifier-proof.json'));
  const table0 = await m.pointer(notifier0.E);
  const target0 = BigInt(await m.pointer(table0 + 4 * 8));
  const targetRegion = await c.info(fsHandle, target0, pid);
  check(!targetRegion.result && targetRegion.memory?.type === 3 && targetRegion.memory?.permissions === 4,
    'The vtable target is not in X-only fs text: ' + JSON.stringify(targetRegion.memory));
  const senderAddr = BigInt(targetRegion.memory.address) + NOARG_SENDER;
  const senderRead = await c.read(fsHandle, pid, senderAddr, 0x18);
  check(!senderRead.result, 'The sender read failed');
  check(senderRead.hex === SENDER_PROLOGUE + 'c90080d2',
    'The live sender prologue differs from the banked binary: ' + senderRead.hex);
  await log({stage: 'sender-verified', sender: senderAddr.toString()});

  // The notifier stub site (the proven trigger).
  const notifier = await read(path.join(RUN, 'switch2', 'ro', m.info.session + '-notifier-proof.json'));
  check(notifier.identityVerified && notifier.session === m.info.session, 'Notifier proof mismatch');
  const state = await m.request({command: 'root-native-info'});
  const notifierHandle = state.notifiers[0];
  check(notifierHandle && state.worker.joined, 'Notifier or worker state missing');
  const table = await m.pointer(notifier.E);
  const targetAddr = BigInt(await m.pointer(table + 4 * 8));
  check((targetAddr & 0xfffn) + 64n <= 0x1000n, 'The 64-byte stub would cross a page');
  const orig = await c.read(fsHandle, pid, targetAddr, 64);
  check(!orig.result, 'The stub-site read failed');
  const blocks = [0, 16, 32, 48].map(o => Buffer.from(orig.hex.slice(o * 2, (o + 16) * 2), 'hex'));
  await log({stage: 'target', target: targetAddr.toString()});

  // The service handle via the NATIVE WORKER's sm-get = the FS process's
  // own sm (the rig runs in the fs process — exportHandle(SELF)'s identity
  // is native fs). Round 7's wedge = the RO-pivot wave open (monitor table).
  const handle = await c.service(service);
  await log({stage: 'service', name: service, handle});

  // Stage the proxy {0, handle} + the 16-byte out buffer at the staging area.
  const proxyBuf = Buffer.alloc(8); proxyBuf.writeBigUInt64LE(0n);
  proxyBuf.writeUInt32LE(Number(handle) >>> 0, 4);
  const staged = await m.request({command: 'root-hipc2-stage',
    hex: proxyBuf.toString('hex') + Buffer.alloc(16).toString('hex')});
  const base = BigInt(staged.address);
  const proxyAddr = base, outAddr = base + 8n;
  await log({stage: 'staged', proxy: proxyAddr.toString(), out: outAddr.toString()});

  const stub = buildStub(proxyAddr, outAddr, cmd, senderAddr);
  const installed = [];
  let trigger = null, triggerError = null;
  try {
    for (let i = 0; i < 4; i++) {
      const reply = await c.patch(fsHandle, pid, targetAddr + 16n * BigInt(i), blocks[i], stub[i]);
      check(!reply.result && reply.expectedMatched && reply.readbackMatched, 'Patch install failed at block ' + i);
      installed.push(i);
    }
    await log({stage: 'installed', blocks: installed.length});
    try { trigger = await c.worker({kind: 'notifier-probe', handle: notifierHandle}); }
    catch (e) { triggerError = e; }
    const fetched = await m.request({command: 'root-hipc2-fetch',
      address: Number(base), length: 24});
    await log({stage: 'trigger',
      senderResult: trigger ? trigger.result : null,
      transport: trigger?.transport ?? null,
      triggerError: triggerError ? String(triggerError.message).slice(0, 120) : null,
      outHex: fetched.hex.slice(16 * 2)}); // the 16 out bytes after the proxy
  } finally {
    for (const i of installed.reverse()) {
      const reply = await c.patch(fsHandle, pid, targetAddr + 16n * BigInt(i), stub[i], blocks[i]);
      check(!reply.result && reply.readbackMatched, 'RESTORE FAILED at block ' + i);
    }
    const back = await c.read(fsHandle, pid, targetAddr, 64);
    await log({stage: 'restored', ok: back.hex === orig.hex});
    check(back.hex === orig.hex, 'Restored bytes differ');
  }
  await c.close();
  console.log(JSON.stringify({done: true, service, cmd, session: m.info.session}));
}

main().catch(e => { console.error(JSON.stringify({error: String(e.message).slice(0, 200)})); process.exitCode = 1; });
