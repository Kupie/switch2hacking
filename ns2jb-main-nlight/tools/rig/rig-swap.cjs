'use strict';
const fs = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json'), 'utf8'));
const {Client} = require(path.join(latest.directory, 'switch2', 'process', 'client.cjs'));
// byte-swap each u64 so the monitor's LE read of the hex-decoded (BE) bytes
// reconstructs the intended value
const swap = v => {let x = BigInt.asUintN(64, BigInt(v)); let r = 0n;
  for (let i = 0; i < 8; i++) { r = (r << 8n) | (x & 0xffn); x >>= 8n; } return r;};
const hex = arr => arr.map(v => BigInt.asUintN(64, BigInt(v)).toString(16).padStart(16, '0')).join('');
const dump = (label, r) => {
  const d = Buffer.from(r.data ?? '', 'hex');
  const ws = [];
  for (let i = 0; i + 8 <= d.length; i += 8) ws.push('0x' + d.readBigUInt64LE(i).toString(16).padStart(16, '0'));
  console.log(`${label}: ${ws.slice(0, 12).join(' ')}`);
};
(async () => {
  const c = await new Client().open();
  const name = 0x3a6c61746166n; // "fatal:"
  dump('sub29 SWAP queue', await c.worker({kind: 'ro-rig', handle: c.handle,
    hex: hex([swap(29n), swap(name)])}));
  await new Promise(r => setTimeout(r, 3000));
  dump('sub28 SWAP poll ', await c.worker({kind: 'ro-rig', handle: c.handle,
    hex: hex([swap(28n), swap(0n)])}));
  await c.close();
})().catch(e => { console.error(String(e.stack || e).slice(0, 300)); process.exit(1); });
