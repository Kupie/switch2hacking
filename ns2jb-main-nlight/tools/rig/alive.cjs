'use strict';
const fs = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json'), 'utf8'));
const {connect} = require(path.join(latest.directory, 'switch2', 'tools', 'fs-memory.cjs'));
(async () => {
  const m = await connect();
  const info = await m.request({command: 'root-native-info'});
  const pmDmnt = info.services?.find(s => s.name === 'pm:dmnt')?.handle;
  for (const pid of [209, 210]) {
    const r = await m.request({command: 'root-native-ipc', handle: pmDmnt, id: 7,
      hex: require(path.join(latest.directory, 'switch2', 'tools', 'fs-memory.cjs'))
        .encodeU64(BigInt(pid)).toString('hex')});
    console.log('pid', pid, '->', JSON.stringify(r).slice(0, 120));
  }
  process.exit(0);
})().catch(e => { console.error(String(e.message).slice(0, 200)); process.exit(1); });
