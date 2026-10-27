'use strict';
const fs = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json'), 'utf8'));
const {Client} = require(path.join(latest.directory, 'switch2', 'process', 'client.cjs'));
const hex = arr => arr.map(v => BigInt.asUintN(64, BigInt(v)).toString(16).padStart(16, '0')).join('');
const dump = (label, r) => {
  const d = Buffer.from(r.data ?? '', 'hex');
  const ws = [];
  for (let i = 0; i + 8 <= d.length; i += 8) ws.push('0x' + d.readBigUInt64LE(i).toString(16).padStart(16, '0'));
  console.log(`${label} (${d.length}B): ${ws.slice(0, 12).join(' ')}`);
};
(async () => {
  const c = await new Client().open();
  dump('sub25 queue', await c.worker({kind: 'ro-rig', handle: c.handle, hex: hex([25n, 0x3a6c61746166n, 0n])}));
  await new Promise(r => setTimeout(r, 3000));
  dump('sub25 poll ', await c.worker({kind: 'ro-rig', handle: c.handle, hex: hex([28n, 0n])}));
  await new Promise(r => setTimeout(r, 3000));
  dump('sub29 queue', await c.worker({kind: 'ro-rig', handle: c.handle, hex: hex([29n, 0x6c6c6568733a6d70n])}));
  await new Promise(r => setTimeout(r, 3000));
  dump('sub29 poll ', await c.worker({kind: 'ro-rig', handle: c.handle, hex: hex([28n, 0n])}));
  await c.close();
})().catch(e => { console.error(String(e.stack || e).slice(0, 300)); process.exit(1); });
