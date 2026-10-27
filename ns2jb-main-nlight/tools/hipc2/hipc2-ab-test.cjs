// A/B diagnostic for the repeated post-READY worker deaths (Jer6aO, 0dSsB1,
// vEkYmj all died at/after the worker's pthread_create in the hipc2 prepare).
//
// Step A: spawn a worker through the PROVEN pipeline path — root-native-worker-prepare
// with kind='control-test' (the exact machinery the boot itself uses, same
// area/gate/slot, verified harmless call sequence). Nothing hipc2-specific.
//   - If the session DIES here: worker spawns post-READY are systemically
//     lethal → stop worker work entirely, re-plan (report exactly which op).
//   - If it survives: proceed.
// Step B: join it cleanly (release + poll + join), confirming the whole
// worker lifecycle works post-READY.
// Step C (only if A+B survive): the hipc2 frame patch approach on a SECOND
// control-test worker — patch its parked frame with the TLS memcpy/send/memcpy
// calls, then release. (Kept behind --step3 to allow staging.)
//
// Usage (netns-wrapped, live READY session, >=90s settled):
//   sudo -n ip netns exec switchlab runuser -u nlight -- node hipc2-ab-test.cjs [--step3]
'use strict';
const fsSync = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fsSync.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json')));
const {connect} = require(path.join(latest.directory, 'switch2', 'tools', 'fs-memory.cjs'));

async function main() {
  const step3 = process.argv.includes('--step3');
  const memory = await connect();
  const req = c => memory.request(c);
  const info = await req({command: 'root-native-info'});
  console.log('session', info.session, '| services:', (info.services || []).map(s => s.name).join(','));

  const pmShell = info.services?.find(s => s.name === 'pm:shell')?.handle;

  // STEP A: the proven pipeline worker (control-test).
  console.log('--- STEP A: proven control-test worker prepare ---');
  const prep = await req({command: 'root-native-worker-prepare',
    kind: 'control-test', handle: pmShell});
  console.log('A: worker prepared:', JSON.stringify({thread: prep.thread, gate: prep.gate, count: prep.count}));
  console.log('A: still alive after prepare — bridge answers info:', !!(await req({command: 'root-native-info'})).session);

  // STEP B: full lifecycle.
  console.log('--- STEP B: release + join ---');
  await req({command: 'root-native-worker-release'});
  const deadline = Date.now() + 20000;
  for (;;) {
    const st = await req({command: 'root-native-worker-state'});
    if (st.finished) break;
    if (Date.now() > deadline) throw Error('control-test worker did not finish');
    await new Promise(r => setTimeout(r, 100));
  }
  const joined = await req({command: 'root-native-worker-join'});
  console.log('B: joined. values:', JSON.stringify(joined.values));
  console.log('B: still alive after join:', !!(await req({command: 'root-native-info'})).session);
  console.log('=== A/B PASS: worker spawn + release + join are safe post-READY ===');

  if (!step3) { console.log('(--step3 not given: stopping here)'); return; }

  // STEP C: a second control-test worker, its parked frame PATCHED with the
  // hipc2 call sequence before release.
  console.log('--- STEP C: patched hipc2 release on a second worker ---');
  const prep2 = await req({command: 'root-native-worker-prepare',
    kind: 'control-test', handle: pmShell});
  const w = (await req({command: 'root-native-info'})).worker || {};
  // The control-test worker's frame layout comes from the shared builder; the
  // worker object in state carries base/stackOffset/resultOffsets. Patch the
  // parked frame's first two calls to: memcpy(cfg->TLS?) — NOT YET: without a
  // validated TLS pointer this is unsafe. This step stays manual until the
  // tpidr scan is proven safe standalone.
  console.log('C: parked worker available for patch:', JSON.stringify({thread: prep2.thread, base: w.base, stackOffset: w.stackOffset}));
  console.log('C: NOT patching (no validated TLS yet) — join the second worker cleanly instead.');
  await req({command: 'root-native-worker-release'});
  const d2 = Date.now() + 20000;
  for (;;) {
    const st = await req({command: 'root-native-worker-state'});
    if (st.finished) break;
    if (Date.now() > d2) throw Error('second worker did not finish');
    await new Promise(r => setTimeout(r, 100));
  }
  await req({command: 'root-native-worker-join'});
  console.log('=== C done: second worker lifecycle clean ===');
}

main().catch(e => {console.error(e.stack || e); process.exitCode = 1;});
