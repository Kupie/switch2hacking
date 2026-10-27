'use strict';
// Round 9 — HIPC2 via the payload's OWN sender (rig sub 21), on the
// monitor's worker thread with the monitor's table handles. Zero foreign
// context: the sender = payload code (RX, no W^X), the thread = the rig
// worker's own (no dispatcher nesting), the handle = the sm-get open in
// the same process that sends. Wedge risk: none — real services reply.
//
// Usage: node hipc2-rig-client.cjs <service> <cmd> [u64 args...]
const fsSync = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fsSync.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json'), 'utf8'));
const RUN = latest.directory;
const {Client, check} = require(path.join(RUN, 'switch2', 'process', 'client.cjs'));

const hexIn = arr => arr.map(v => BigInt.asUintN(64, BigInt(v)).toString(16).padStart(16, '0')).join('');

async function main() {
  const tlsMode = process.argv.includes('--tls');
  const gshMode = process.argv.includes('--gsh');
  const gshxMode = process.argv.includes('--gshx');
  const smMode = process.argv.includes('--sm');
  const cmif = process.argv.includes('--cmif');
  const rest = process.argv.slice(2).filter(a => a !== '--cmif' && a !== '--sm' && a !== '--tls' && a !== '--combo' && a !== '--gsh' && a !== '--gshx');
  const service = rest[0] ?? 'pm:shell';
  const cmd = Number(rest[1] ?? 6);
  const args = rest.slice(2).map(a => BigInt(a));
  check(Number.isInteger(cmd) && cmd >= 0 && cmd <= 0xffff && args.length <= 3, 'Bad command line');
  // cmif: tag 4, wc = ceil((32+8n)/4); HIPC2: tag 6, wc = 8+2n.
  const tag = smMode ? 0x11n : (cmif ? 4n : 6n);
  const wc = smMode ? 2n : (cmif ? BigInt(Math.ceil((32 + 8 * args.length) / 4)) : BigInt(8 + 2 * args.length));

  if (gshMode || gshxMode) {
    // The deferred GSH: sub 25 (boot-port legacy/evolved shapes) or sub 29
    // (--gshx: the EXECUTOR recipe — fresh connect + init + svc 0x22 buffer
    // send, the only GSH recipe ever proven live on fw23). Sub 28 polls.
    const sub = gshxMode ? 29n : 25n;
    // The deferred GSH: sub 25 queues (main's clean loop executes it),
    // sub 28 polls the result. A monitor-table session.
    const name = rest[0] ?? 'pm:shell';
    const space = rest[1] === undefined ? 1n : BigInt(rest[1]); // sub 25 only: 0 = legacy shape, 1/2 = evolved TIPC shape
    check(/^[a-z0-9:-]{1,8}$/.test(name), 'GSH name must be <= 8 chars');
    check(space === 0n || space === 1n || space === 2n, 'space must be 0, 1 or 2');
    const c = await new Client().open();
    let nameU64 = 0n;
    for (let i = 0; i < name.length; i++) nameU64 |= BigInt(name.charCodeAt(i)) << BigInt(8 * i);
    const hex = arr => arr.map(v => BigInt.asUintN(64, BigInt(v)).toString(16).padStart(16, '0')).join('');
    const qreply = await c.worker({kind: 'ro-rig', handle: c.handle,
      hex: hex(gshxMode ? [29n, nameU64] : [25n, nameU64, space])});
    console.log('QUEUE REPLY:', (qreply.data ?? '').slice(0, 64));
    await new Promise(r => setTimeout(r, 500));
    const reply = await c.worker({kind: 'ro-rig', handle: c.handle, hex: hex([28n, 0n])});
    const d = Buffer.from(reply.data ?? '', 'hex');
    const w = [];
    for (let i = 0; i + 8 <= d.length; i += 8) w.push(d.readBigUInt64LE(i));
    const J = (k, v) => typeof v === 'bigint' ? v.toString(16) : v;
    if (gshxMode) {
      // sub 29 layout: r0 = init_t<<32 | gsh_t, r1 = init_echo,
      // r2..r7 = the raw buffer words (echo at r2, handle at r3 low, result at r3 high)
      console.log(JSON.stringify({state: w[3], init_t: w[4] >> 32n, gsh_t: w[4] & 0xffffffffn,
        init_echo: w[5], buf0: w[6], buf1: w[7], buf2: w[8],
        bufHex: d.subarray(32, 32 + 64).toString('hex')}, J));
    } else {
      console.log(JSON.stringify({state: w[3], transport: w[4] >> 32n, p2: w[4] & 0xffffffffn,
        session: w[5] & 0xffffffffn, err: w[5] >> 32n,
        rawTLS: d.subarray(32, 32 + 64).toString('hex')}, J));
    }
    await c.close();
    return;
  }
  const c = await new Client().open();
  let handle;
  if (smMode) {
    // The borrowed sm session itself — the known-answer calibration target.
    const info = await c.memory.request({command: 'root-native-info'});
    const sm = info.services?.find(s => s.name === 'pm:shell')?.sm;
    check(sm, 'The borrowed initialized FS SM client is missing');
    handle = sm;
    console.log(JSON.stringify({stage: 'sm-mode', sm: handle}));
  } else {
    handle = await c.service(service);
    console.log(JSON.stringify({stage: 'service', name: service, handle}));
  }

  const comboMode = process.argv.includes('--combo');
  const sub = comboMode ? 24n : (tlsMode ? 23n : 21n); // 24 = buffer request + TLS reply
  const input = [sub, BigInt(handle) | (BigInt(wc) << 32n), BigInt(cmd), ...args,
    ...Array(3 - args.length).fill(0n), tag];
  const reply = await c.worker({kind: 'ro-rig', handle: c.handle, hex: hexIn(input)});
  const data = Buffer.from(reply.data ?? '', 'hex');
  const words = [];
  for (let i = 0; i + 8 <= data.length; i += 8) words.push(data.readBigUInt64LE(i));
  console.log('RAW DATA:', (reply.data ?? '').length / 2, 'bytes:', reply.data ?? '');
  const J = (k, v) => typeof v === 'bigint' ? v.toString(16) : v;
  console.log(JSON.stringify({stage: 'reply', transport: reply.transport,
    tag: words[0], sub: words[1], arg: words[2], out0: words[3], out1: words[4],
    frame: words.slice(5, 13)}, J));
  // out0 = transport<<32 | frame[0x10] word ; out[2..13] = the raw reply frame.
  const out0 = words[3];
  const transport = Number(out0 >> 32n);
  const frameHex = words.slice(5, 24).map(w => w.toString(16).padStart(16, '0')).join('');
  const raw = Buffer.from(frameHex, 'hex');
  const sfcoAt = raw.indexOf(Buffer.from('SFCO', 'ascii'));
  const result = sfcoAt >= 0 && sfcoAt % 4 === 0 ? raw.readUInt32LE(sfcoAt + 8) : null;
  console.log(JSON.stringify({stage: 'parsed', transport,
    sfcoAt: sfcoAt >= 0 ? '0x' + sfcoAt.toString(16) : null,
    result: result === null ? null : '0x' + result.toString(16),
    EUREKA: transport === 0 && sfcoAt >= 0,
    replyHex: frameHex}));
  await c.close();
}

main().catch(e => { console.error(JSON.stringify({error: String(e.message).slice(0, 200)})); process.exitCode = 1; });
