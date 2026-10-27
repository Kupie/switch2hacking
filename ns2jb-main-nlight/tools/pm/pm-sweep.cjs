// pm handle-return sweep — the "breaks everything open" primitive hunt.
//
// Goal: find a pm:dmnt / pm:shell command that RETURNS A PROCESS HANDLE for
// a pid (reply carrying a moves/copies descriptor). Rig subs 0010/0016
// operate on IPC-TRANSFERRED process handles (the fs-handle export path is
// proven), so a handle-returning pm command = pm text/rodata dumpable with
// the CURRENT monitor, no svc 0x60 (fw23 svc-debug is closed — caller-
// authorized; see FINDINGS 2026-10-25).
//
// Usage (netns-wrapped):
//   node pm-sweep.cjs                       # pm:dmnt, ids 0..63
//   node pm-sweep.cjs --svc=pm:shell --ids=0,63 --pid=211
//
// Discipline (hard rules):
// - ONE command id per RPC round-trip; results persisted after EVERY id
//   (a wedge loses at most the current id).
// - id-7 liveness oracle (GetProcessInfo, proven shape [pid u64]) re-run
//   after EVERY swept id: transport error = session dead -> ABORT.
// - pid input = the monitor's own pid (211) — self-owned, safe.
// - The input shape is a GUESS ([pid u64], the id-7 shape). Errors are data,
//   not failure. Watch: transport, result, copies, moves, data head.
// - KNOWN RISK (accepted): unknown commands can kill sessions (fsp-srv
//   cmd 7/8 class). This boot's ro:dmnt is already name-wedged; the worst
//   case is the reboot + dance we need anyway for a fresh monitor.
'use strict';
const fsSync = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fsSync.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json')));

async function main() {
  const arg = (name, fallback) => {
    const hit = process.argv.find(a => a.startsWith('--' + name + '='));
    return hit ? hit.slice(name.length + 3) : fallback;
  };
  const svcName = arg('svc', 'pm:dmnt');
  const [lo, hi] = arg('ids', '3,63').split(',').map(Number);
  const pid = BigInt(arg('pid', '211'));
  // Baseline pair: a known-answer call proving the session lives. For
  // pm:shell: cmd 1 (TerminateProcess) on a DEAD pid => 0x20f, no side
  // effect. For pm:dmnt: cmd 7 (GetProcessInfo) on the live pid => 0.
  const baseline = arg('baseline', svcName === 'pm:shell' ? '1:210' : '7:' + pid.toString());
  const [baseId, basePid] = baseline.split(':');
  const baseHex = Buffer.alloc(8); baseHex.writeBigUInt64LE(BigInt(basePid));
  const basePayload = baseHex.toString('hex');
  const skip = arg('skip', '0,1,2').split(',').map(Number);
  const outFile = path.join(latest.directory, 'pm-sweep-' + svcName.replace(':', '') + '.json');
  let results = {};
  if (fsSync.existsSync(outFile)) {
    try {results = JSON.parse(fsSync.readFileSync(outFile));} catch {results = {};}
  }
  const {connect} = require(path.join(latest.directory, 'switch2', 'tools', 'fs-memory.cjs'));
  const memory = await connect();
  const info = await memory.request({command: 'root-native-info'});
  const svc = (info.services || []).find(x => x.name === svcName);
  if (!svc) throw Error(svcName + ' is not held');
  const handle = svc.handle;
  const hex = Buffer.alloc(8); hex.writeBigUInt64LE(pid);
  const payload = hex.toString('hex');
  const call = async id => {
    const r = await memory.request({command: 'root-native-ipc', handle, id,
      hex: id === Number(baseId) ? basePayload : payload});
    return {transport: Number(r.transport ?? 0), result: r.result,
      canonicalResult: r.canonicalResult, copies: r.copies ?? [], moves: r.moves ?? [],
      data: (r.hex || r.data || '').slice(0, 96)};
  };
  console.log(JSON.stringify({stage: 'start', svc: svcName, handle, pid: pid.toString(),
    ids: [lo, hi], out: outFile, session: latest.session}));
  // Baseline: the known-answer pair must answer.
  const base = await call(Number(baseId));
  if (base.transport) throw Error('baseline transport error before the sweep: session is dead');
  console.log(JSON.stringify({stage: 'baseline-ok', id: Number(baseId), pid: basePid, result: base.result}));
  let dead = false;
  for (let id = lo; id <= hi; id++) {
    if (skip.includes(id) || id === Number(baseId) || results[id]) continue;
    let entry;
    try {entry = await call(id);}
    catch (e) {entry = {error: String(e.message || e)};}
    entry.at = new Date().toISOString();
    results[id] = entry;
    fsSync.writeFileSync(outFile, JSON.stringify(results, null, 1));
    console.log('id', id, JSON.stringify({transport: entry.transport, result: entry.result,
      copies: entry.copies, moves: entry.moves, error: entry.error, data: entry.data}));
    if ((entry.moves || []).length || (entry.copies || []).length)
      console.log('*** CANDIDATE id', id, '- handle descriptor in reply');
    // Liveness oracle after every id (the baseline call: cmd 1 on the dead pid).
    try {
      const live = await call(Number(baseId));
      if (live.transport) {console.log('*** BASELINE DIED after id', id, '- ABORT'); dead = true;}
    } catch (e) {console.log('*** BASELINE THREW after id', id, '- ABORT:', e.message); dead = true;}
    if (dead) break;
  }
  console.log(JSON.stringify({stage: dead ? 'aborted' : 'done', swept: Object.keys(results).length, out: outFile}));
}

main().catch(e => {console.error(e.stack || e); process.exitCode = 1;});