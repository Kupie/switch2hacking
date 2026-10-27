// am-pid promotion → MKW content mount (game-dumping track).
//
// Per FINDINGS (final section): with the session identity promoted to am's
// pid (am = the content manager, authorized for all registered content),
// fsp-srv cmd-10 mounts of '@User:/Contents/registered/...' should pass the
// per-process content authorization. All operations here are PROVEN classes:
//   - pm:dmnt id-7 sweep on the PIPELINE's OWN session (no churn, read-only)
//   - fix-session-identity --pid (the proven promotion tool)
//   - root-list-bis (read-only BIS listing)
//   - root-native-content-mount (the monitor fsp-srv cmd-10 path)
// No workers, no TLS, no novel console code.
//
// Usage (netns-wrapped, live READY session, >=90s settled):
//   sudo -n ip netns exec switchlab runuser -u nlight -- node am-mount.cjs
'use strict';
const fsSync = require('node:fs');
const path = require('node:path');
const {execFile} = require('node:child_process');
const {promisify} = require('node:util');
const execFileAsync = promisify(execFile);
const latest = JSON.parse(fsSync.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json')));
const {connect} = require(path.join(latest.directory, 'switch2', 'tools', 'fs-memory.cjs'));

const MKW = 0x0400c3f00006e000n;
const AM_PROGRAM = 0x0400000000000023n;   // am sysmodule title id

function u64(v) { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return b.toString('hex'); }

async function main() {
  const memory = await connect();
  const req = c => memory.request(c);
  const info = await req({command: 'root-native-info'});
  console.log('session', info.session);

  const pmDmnt = info.services?.find(s => s.name === 'pm:dmnt')?.handle;
  if (!pmDmnt) throw Error('no pipeline pm:dmnt session (needed for the sweep — do not open new ones)');
  let fspSrv = info.services?.find(s => s.name === 'fsp-srv')?.handle;
  if (!fspSrv) {
    // ueJtpC lesson: the monitor's fsp-srv may not be in state.services —
    // open one via the borrowed SM (proven, single session, closed at end).
    const sm = info.services?.find(s => s.name === 'pm:shell')?.sm;
    const open = await req({command: 'root-native-sm-service', handle: sm, name: 'fsp-srv'});
    fspSrv = open.moves?.[0];
    console.log('opened fsp-srv:', fspSrv, 'result 0x' + ((open.result ?? 0) >>> 0).toString(16));
  }
  console.log('pm:dmnt', pmDmnt, '| fsp-srv', fspSrv);

  // 1. id-7 sweep for am's pid (GetProcessId... id7 = GetProgramId(pid))
  console.log('--- sweep pids for am (program 0x' + AM_PROGRAM.toString(16) + ') ---');
  let amPid = 0;
  for (let pid = 1; pid <= 300; pid++) {
    let r;
    try {
      r = await req({command: 'root-native-ipc', handle: pmDmnt, id: 7, hex: u64(pid)});
    } catch (e) { break; }
    if (r.result === 0 && r.hex) {
      const raw = Buffer.from(r.hex, 'hex');
      const prog = raw.readBigUInt64LE(0);
      if (prog === AM_PROGRAM) { amPid = pid; console.log(`  am pid ${pid} (0x${pid.toString(16)})`); }
      else if (prog > 0x0400000000000000n && prog < 0x0500000000000000n)
        console.log(`  pid ${pid}: program 0x${prog.toString(16)}`);
    }
  }
  if (!amPid) throw Error('am pid not found in 1..300');
  await new Promise(r => setTimeout(r, 500));

  // 2. promote the session identity to am
  console.log('--- fix-session-identity --pid ' + amPid + ' ---');
  const idres = await execFileAsync('node', [path.join(__dirname, 'fix-session-identity.cjs'), '--pid', String(amPid)],
    {cwd: __dirname}).catch(e => ({stdout: '', stderr: e.message}));
  console.log((idres.stdout || idres.stderr || '').trim().slice(-300));

  // 3. list the registered content dir
  console.log('--- BIS list @User:/Contents/registered ---');
  const list = await req({command: 'root-list-bis', id: 30, path: '/Contents/registered'});
  console.log(JSON.stringify(list).slice(0, 600));

  // 4. the mount attempt (the FINDINGS shape: fsType 6 + '@User:' path)
  const subdir = list.entries?.[0]?.name || '00000061';
  console.log('--- content-mount probe on subdir ' + subdir + ' ---');
  if (!fspSrv) { console.log('no monitor fsp-srv session — check state.services'); return; }
  for (const entry of (list.entries || []).slice(0, 6)) {
    const sub = await req({command: 'root-list-bis', id: 30,
      path: '/Contents/registered/' + (entry.name || entry)});
    for (const nca of (sub.entries || []).slice(0, 8)) {
      const name = nca.name || nca;
      if (!/\.nca$/i.test(String(name))) continue;
      const p = '@User:/Contents/registered/' + (entry.name || entry) + '/' + name;
      const m = await req({command: 'root-native-content-mount', handle: fspSrv,
        tid: MKW.toString(), fsType: 6, path: p});
      console.log(`  ${p} -> 0x${(m.result >>> 0).toString(16)}` +
        (m.result === 0 ? '  <<<*** MOUNT OPENED ***>>>' : ''));
      if (m.result === 0) {
        console.log('EUREKA: content mount succeeded — dumping machinery unlocked');
        return;
      }
      await new Promise(r => setTimeout(r, 300));
    }
  }
  console.log('mount sweep complete (all results above)');
}

main().catch(e => {console.error(e.stack || e); process.exitCode = 1;});
