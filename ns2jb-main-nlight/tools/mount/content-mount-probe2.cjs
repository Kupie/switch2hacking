'use strict';
const fsSync = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fsSync.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json')));
const {connect} = require(path.join(latest.directory, 'switch2', 'tools', 'fs-memory.cjs'));
const MKW = 0x0400c3f00006e000n;
async function main() {
  const m = await connect();
  const req = c => m.request(c);
  const info = await req({command: 'root-native-info'});
  let fspSrv = info.services?.find(s => s.name === 'fsp-srv')?.handle;
  if (!fspSrv) {
    const sm = info.services?.find(s => s.name === 'pm:shell')?.sm;
    const open = await req({command: 'root-native-sm-service', handle: sm, name: 'fsp-srv'});
    fspSrv = open.moves?.[0];
  }
  // the FINDINGS shape: fsType 6 + '@User0:<data-nca>' — try the variants
  const variants = [];
  const list = await req({command: 'root-list-bis', id: 30, path: '/Contents/registered'});
  const d = (list.entries || []).map(e => e.name || e).find(x => x === '00000061') || (list.entries || [])[0];
  let sub = await req({command: 'root-list-bis', id: 30, path: '/Contents/registered/' + (d.name || d)});
  const nca = (sub.entries || []).map(e => e.name || e).find(n => /\.nca$/i.test(String(n)));
  variants.push(['user0-full', '@User0:/Contents/registered/' + (d.name || d) + '/' + nca]);
  variants.push(['user0-flat', '@User0:/' + nca]);
  variants.push(['user0-bare', '@User0:' + nca]);
  for (const [tag, p] of variants) {
    const r = await req({command: 'root-native-content-mount', handle: fspSrv,
      tid: MKW.toString(), fsType: 6, path: p});
    console.log(tag, p, '-> 0x' + (r.result >>> 0).toString(16) +
      (r.result === 0 ? '   <<<<<*** MOUNT OPENED ***>>>>>' : ''));
    await new Promise(r2 => setTimeout(r2, 300));
  }
}
main().catch(e => { console.error(String(e.stack || e).slice(0, 200)); process.exitCode = 1; });
