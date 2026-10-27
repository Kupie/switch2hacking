'use strict';
const fs = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(require('node:fs').readFileSync(path.join(__dirname, '..', '..', 'latest-session.json'), 'utf8'));
const RUN = latest.directory;
const {Client} = require(path.join(RUN, 'switch2', 'process', 'client.cjs'));
const hex = arr => arr.map(v => BigInt.asUintN(64, BigInt(v)).toString(16).padStart(16, '0')).join('');
(async () => {
  const c = await new Client().open();
  // poll sub 28 twice, raw
  for (let i = 0; i < 2; i++) {
    const r = await c.worker({kind: 'ro-rig', handle: c.handle, hex: hex([28n, 0n])});
    const d = Buffer.from(r.data ?? '', 'hex');
    console.log(`poll ${i}: len=${d.length}`);
    for (let w = 0; w + 8 <= d.length; w += 8)
      console.log(`  w[${w/8}] = 0x${d.readBigUInt64LE(w).toString(16).padStart(16, '0')}`);
    await new Promise(r2 => setTimeout(r2, 3000));
  }
  await c.close();
})().catch(e => { console.error(String(e.stack || e).slice(0, 300)); process.exit(1); });
