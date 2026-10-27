'use strict';
// Game-content mount probes under the STRONG identity (death #9 lesson:
// NO pid promotion — the strong boot's internal-trust fallback is the path).
// fsp-srv cmd 10 (MountContent), fsType 6, '@User:/Contents/registered/...'
// via the monitor fsp-srv session (root-native-content-mount, proven class).
const fsSync = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fsSync.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json')));
const {connect} = require(path.join(latest.directory, 'switch2', 'tools', 'fs-memory.cjs'));
const MKW = 0x0400c3f00006e000n;

async function main() {
  const m = await connect();
  const req = c => m.request(c);
  const info = await req({command: 'root-native-info'});
  console.log('session', info.session);
  let fspSrv = info.services?.find(s => s.name === 'fsp-srv')?.handle;
  if (!fspSrv) {
    const sm = info.services?.find(s => s.name === 'pm:shell')?.sm;
    const open = await req({command: 'root-native-sm-service', handle: sm, name: 'fsp-srv'});
    fspSrv = open.moves?.[0];
    console.log('opened fsp-srv', fspSrv, 'result 0x' + ((open.result ?? 0) >>> 0).toString(16));
  }
  console.log('--- registered content ---');
  const list = await req({command: 'root-list-bis', id: 30, path: '/Contents/registered'});
  const dirs = (list.entries || []).map(e => e.name || e);
  console.log(dirs.slice(0, 8).join(', '), '...', dirs.length, 'subdirs');
  let tried = 0;
  for (const d of dirs.slice(0, 6)) {
    let sub;
    try { sub = await req({command: 'root-list-bis', id: 30, path: '/Contents/registered/' + d}); }
    catch (e) { console.log('  list', d, 'failed:', String(e.message).slice(0, 60)); continue; }
    for (const nca of (sub.entries || []).map(e => e.name || e).slice(0, 8)) {
      if (!/\.nca$/i.test(String(nca))) continue;
      const p = '@User:/Contents/registered/' + d + '/' + nca;
      const r = await req({command: 'root-native-content-mount', handle: fspSrv,
        tid: MKW.toString(), fsType: 6, path: p});
      console.log(`  ${p} -> 0x${(r.result >>> 0).toString(16)}` +
        (r.result === 0 ? '   <<<<<*** MOUNT OPENED ***>>>>>' : ''));
      tried++;
      if (r.result === 0) { console.log('EUREKA: content mount OPEN'); return; }
      await new Promise(r2 => setTimeout(r2, 250));
    }
  }
  console.log('probed', tried, 'ncas');
}
main().catch(e => { console.error(String(e.stack || e).slice(0, 300)); process.exitCode = 1; });
