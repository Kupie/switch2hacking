// pm handle-command sweep v2. FRESH pm:dmnt/pm:shell session per command id
// (id-0 GetJitDebugProcessIdList wedged its session — one bad shape poisons
// it, so never reuse a session across probes). Sessions are re-openable via
// the borrowed SM at will (proven with nvdrv etc.).
//
// fw23 pm:dmnt CONFIRMED HOS1-numbered: id 7 = GetProgramId(pid) — the
// monitor pid 209 answered 0x0400000000000037 (its ro-policy program id).
// So the expected table is: 0 GetJitDebugProcessIdList(buf), 1 StartProcess,
// 2 GetProcessId(prog), 3 HookToCreateProcess(event!), 4 GetAppPid,
// 5 HookToCreateAppProcess(event!), 6 ClearHook, 7 GetProgramId(pid).
// Sweeping beyond 7 for NEW fw23 commands is the actual question.
//
// Usage: netns-wrapped, live session:
//   sudo -n ip netns exec switchlab runuser -u nlight -- node pm-handle-sweep.cjs pm:dmnt [startId] [endId]
'use strict';
const path = require('node:path');
const fs = require('node:fs');
const latest = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json')));
const {connect} = require(path.join(latest.directory, 'switch2', 'tools', 'fs-memory.cjs'));

function u64(v) { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return b.toString('hex'); }

async function main() {
  const wanted = process.argv[2] || 'pm:dmnt';
  const startId = Number(process.argv[3] || 0);
  const endId = Number(process.argv[4] || 16);
  const memory = await connect();
  const info = await memory.request({command: 'root-native-info'});
  const sm = info.services?.find(s => s.name === 'pm:shell')?.sm;
  if (!sm) throw Error('no borrowed SM client');
  const execution = JSON.parse(fs.readFileSync(
    path.join(latest.directory, 'switch2', 'ro', 'current-execution.json'), 'utf8'));
  const pid = Number(execution.pid) || 0;
  if (!pid) throw Error('no monitor pid');
  console.log(`${wanted}: fresh session per command, monitor pid ${pid}`);

  for (let id = startId; id <= endId; id++) {
    let handle;
    try {
      const svc = await memory.request({command: 'root-native-sm-service', handle: sm, name: wanted});
      handle = svc.moves?.[0];
      if (handle === undefined)
        console.log(`id ${id}: open result 0x${((svc.result ?? 0) >>> 0).toString(16)} transport 0x${((svc.transport ?? 0) >>> 0).toString(16)} moves ${JSON.stringify(svc.moves || [])}`);
    } catch (e) {
      console.log(`id ${id}: SM reopen failed (${e.message}) — stopping`);
      return;
    }
    if (handle === undefined) continue;
    let r;
    try {
      r = await memory.request({command: 'root-native-ipc', handle, id, hex: u64(pid)});
    } catch (e) {
      const msg = String(e.message || e);
      if (/0xf601/i.test(msg)) {
        console.log(`id ${id}: 0xf601 (bad shape — expected on buffer cmds; session discarded)`);
        await new Promise(res => setTimeout(res, 150));
        continue;
      }
      console.log(`id ${id}: HARD ERROR ${msg}`);
      console.log('  — probing whether the bridge still answers...');
      try {
        await memory.request({command: 'root-native-info'});
        console.log('  bridge alive, continuing sweep');
        await new Promise(res => setTimeout(res, 150));
        continue;
      } catch {
        console.log('  BRIDGE DEAD — stopping');
        break;
      }
    }
    const moves = r.moves?.length || 0, copies = r.copies?.length || 0;
    const result = r.result >>> 0;
    const tag = moves || copies ? '  <<< HANDLE?' : '';
    console.log(`id ${id}: transport 0x${(r.transport >>> 0).toString(16)} result 0x${result.toString(16)} moves ${JSON.stringify(r.moves || [])} copies ${JSON.stringify(r.copies || [])} hex ${(r.hex || '').slice(0, 40)}${tag}`);
    try { await memory.request({command: 'root-native-close-handle', handle}); } catch {}
    await new Promise(res => setTimeout(res, 150));
  }
  console.log('sweep complete');
}

main().catch(e => {console.error(e.stack || e); process.exitCode = 1;});
