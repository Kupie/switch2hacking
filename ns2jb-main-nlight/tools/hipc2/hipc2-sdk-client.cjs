// HIPC2 via the fs SDK's OWN client sender — the OS code path (v4).
//
// Recipe (FIRMWARE_FINDINGS 7.2d): the SDK sender builds the HIPC2 frame in
// the CALLING THREAD'S OWN TLS and sends via svc 0x21 — the exact pattern
// the OS uses constantly. The sender only reads [proxy+4] = the raw session
// handle, so an 8-byte owned {0, handle} fake proxy suffices.
//
// Steps (all read-only or OS-pattern; no workers, no synthetic frames):
//   1. Read the fs SDK text (~6MB, memory.read — the boot's primitive) and
//      locate the sender by byte pattern; VERIFY the full shape PC-side.
//   2. Snapshot the 7 executor TLS areas (ring structs -> tpidr).
//   3. Open the target service (proven sm-service). Write the fake proxy.
//   4. s.rpc-style call... via root-native thread-id-class machinery? NO:
//      the call = the dispatch's rpc.call3 — exposed as the 'hipc2-sdk-send'
//      dispatch command (below) so the verification + call happen in one
//      serialized request with byte-checks.
//   5. Diff the TLS snapshots -> the fresh SFCO reply block.
//
// Usage (netns-wrapped, live READY session, >=90s settled):
//   sudo -n ip netns exec switchlab runuser -u nlight -- node hipc2-sdk-client.cjs [service] [cmd] [arg]
'use strict';
const fsSync = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fsSync.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json')));
const {connect} = require(path.join(latest.directory, 'switch2', 'tools', 'fs-memory.cjs'));

// pgl 0xb0f0 sender — the full byte shape (fw23 SDK).
const SENDER_SHAPE = Buffer.from('7f2303d5ff4301d1fd7b03a9f32300f9fdc30091c90080d2e803022a020440b9' +
  '73d03bd5ea0313aae803082a4901c0f2497501f8', 'hex');
const CORE = Buffer.from('c90080d2e803022a020440b9', 'hex');  // movz w9,#6 / mov w8,w2 / ldr w2,[x0,#4]

async function main() {
  const name = process.argv[2] || 'nvdrv:t';
  const cmd = Number(process.argv[3] || 0);
  const arg = BigInt(process.argv[4] || 0);

  const memory = await connect();
  const req = c => memory.request(c);
  const info = await req({command: 'root-native-info'});
  console.log('session', info.session);

  // 1. SDK scan: locate the sender pattern (read-only; the SDK block comes
  //    from the report's sdk base + size).
  const sdkBase = info.sdk || info.base && undefined; // dispatch info shape varies; use the report
  const rep = JSON.parse(fsSync.readFileSync(path.join(latest.directory, 'switch2',
    'current-acquisition.json')));
  const live = rep.retainedMemory ? rep : rep; // fallthrough; the dispatch computes from live
  console.log('(SDK scan + verification happens in the dispatch — one serialized request)');

  // 2-4. The dispatch does the verified scan + fake proxy + sender call.
  const svc = await (async () => {
    const sm = info.services?.find(s => s.name === 'pm:shell')?.sm;
    const open = await req({command: 'root-native-sm-service', handle: sm, name});
    console.log(`${name}: result 0x${((open.result ?? 0) >>> 0).toString(16)} handle ${open.moves?.[0]}`);
    return open.moves?.[0];
  })();
  if (!svc) throw Error('service open failed');

  const send = (handle, cmd, arg, shape) => req({command: 'root-native-hipc2-sdk-send', handle,
    cmd, arg: String(arg), shape: shape || '1arg'});

  // CONTROL first: the SDK sender to a CMIF service (pm:shell cmd 6).
  // The sender speaks HIPC2 — pm answers cmif AND hipc2 (fw23 dual-stack?);
  // if pm rejects hipc2, the control tells us before touching nvdrv.
  const sm0 = info.services?.find(s => s.name === 'pm:shell')?.sm;
  const pmOpen = await req({command: 'root-native-sm-service', handle: sm0, name: 'pm:shell'});
  const pmHandle = pmOpen.moves?.[0];
  if (pmHandle) {
    const c = await send(pmHandle, 6, 0, 'noarg');
    console.log('CONTROL pm:shell cmd6:', JSON.stringify(c).slice(0, 300));
    if (c.sfcoFound) {
      const reply = Buffer.from(c.replyHex, 'hex');
      const pid = reply.length >= 0x28 ? reply.readBigUInt64LE(0x20) : null;
      console.log('  SFCO ✓ result 0x' + (c.result >>> 0).toString(16), 'pid', pid,
        pid === 207n ? '<<< CONTROL PASSED' : '(unexpected pid — inspect)');
    } else console.log('  (no SFCO on control — inspect before nvdrv)');
    await req({command: 'root-native-close-handle', handle: pmHandle}).catch(() => {});
  }

  if (process.argv.includes('--control-only')) { console.log('(control-only mode)'); return; }

  // THE TEST: the target service.
  // Default target sweep: no-arg commands first (least surface), then 1-arg.
  const variants = name.includes('nvdrv') ? [
    [0, 0, 'noarg'], [2, 0, 'noarg'], [3, 3, '1arg'], [4, 0, 'noarg'],
  ] : [[cmd, arg, arg ? '1arg' : 'noarg']];
  for (const [c, a, shape] of variants) {
    const r = await send(svc, c, a, shape);
    console.log(`sdk-send cmd ${c} (${shape}):`, JSON.stringify(r).slice(0, 300));
    if (r.sfcoFound) { console.log('  <<<*** EUREKA: HIPC2 VIA THE REAL SDK SENDER ***>>>'); break; }
  }
  await req({command: 'root-native-close-handle', handle: svc}).catch(() => {});
}

main().catch(e => {console.error(e.stack || e); process.exitCode = 1;});
