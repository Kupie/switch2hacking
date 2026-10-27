'use strict';
const fs = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json'), 'utf8'));
const {Client} = require(path.join(latest.directory, 'switch2', 'process', 'client.cjs'));
const swap = v => {let x = BigInt.asUintN(64, BigInt(v)); let r = 0n;
  for (let i = 0; i < 8; i++) { r = (r << 8n) | (x & 0xffn); x >>= 8n; } return r;};
const hex = arr => arr.map(v => BigInt.asUintN(64, BigInt(v)).toString(16).padStart(16, '0')).join('');
(async () => {
  const c = await new Client().open();
  // settle poll: read the full state + results from the earlier sub-29
  const r = await c.worker({kind: 'ro-rig', handle: c.handle, hex: hex([swap(28n), swap(0n)])});
  const d = Buffer.from(r.data ?? '', 'hex');
  for (let w = 0; w + 8 <= Math.min(d.length, 160); w += 8)
    console.log(`w[${w/8}] = 0x${d.readBigUInt64LE(w).toString(16).padStart(16, '0')}`);
  await c.close();
})().catch(e => { console.error(String(e.stack || e).slice(0, 300)); process.exit(1); });
