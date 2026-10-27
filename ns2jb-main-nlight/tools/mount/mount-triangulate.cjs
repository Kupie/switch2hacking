'use strict';
// The E002 gate triangulation: same content path, varying the id argument.
//  - id = MKW tid (known E002)      -> the content-authorization class
//  - id = 0x37 (the monitor's OWN)  -> if the gate is a self-tid check, this
//    passes the authorization and fails LATER (different error code).
//  - id = MK8D (another app)        -> class control
const fsSync = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fsSync.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json')));
const {connect} = require(path.join(latest.directory, 'switch2', 'tools', 'fs-memory.cjs'));

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
    console.log('opened fsp-srv via sm:', fspSrv, 'result 0x' + ((open.result ?? 0) >>> 0).toString(16));
  }
  if (!fspSrv) { console.log('NO fsp-srv handle'); return; }
  await req({command: 'root-probe-bis-filesystem', id: 30}).catch(e => console.log('bis-fs open:', String(e.message).slice(0, 80)));
  const list = await req({command: 'root-list-bis', id: 30, path: '/Contents/registered'});
  const dirs = (list.entries || []).map(e => e.name || e);
  // pick the first registered dir with an .nca
  let ncaPath = null;
  outer: for (const d of dirs.slice(0, 8)) {
    try {
      const sub = await req({command: 'root-list-bis', id: 30, path: '/Contents/registered/' + d});
      for (const n of (sub.entries || []).map(e => e.name || e)) {
        if (/\.nca$/i.test(String(n))) { ncaPath = '@User:/Contents/registered/' + d + '/' + n; break outer; }
      }
    } catch (e) {}
  }
  console.log('probe path:', ncaPath);
  if (!ncaPath) return;
  const ids = [
    ['MKW  0x0400c3f00006e000', '173723308538626048'],
    ['self 0x0400000000000037', '281474976710711'],
    ['MK8D 0x0100152000022000', '72057597963266560'],
  ];
  for (const [label, id] of ids) {
    const r = await req({command: 'root-native-content-mount', handle: fspSrv,
      tid: id, fsType: 6, path: ncaPath});
    console.log(`id=${label} -> 0x${(r.result >>> 0).toString(16)}`);
    await new Promise(r2 => setTimeout(r2, 300));
  }
}
main().catch(e => { console.error(String(e.stack || e).slice(0, 300)); process.exitCode = 1; });
