'use strict';
// Fresh GSH(ro:dmnt) via the wave-side fs sm client + a read-only sub-28 rig
// probe. Tells us which process answers a FRESH service resolution.
const fs = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json'), 'utf8'));
const {connect} = require(path.join(latest.directory, 'switch2', 'tools', 'fs-memory.cjs'));
const swap = v => {let x = BigInt.asUintN(64, BigInt(v)); let r = 0n;
  for (let i = 0; i < 8; i++) { r = (r << 8n) | (x & 0xffn); x >>= 8n; } return r;};
const hex = arr => arr.map(v => BigInt.asUintN(64, BigInt(v)).toString(16).padStart(16, '0')).join('');
(async () => {
  const m = await connect();
  const info = await m.request({command: 'root-native-info'});
  const sm = info.services?.find(s => s.name === 'pm:shell')?.sm;
  console.log('borrowed sm:', sm);
  const open = await m.request({command: 'root-native-sm-service', handle: sm, name: 'ro:dmnt'});
  console.log('fresh ro:dmnt open:', JSON.stringify({result: open.result, moves: open.moves}));
  const h = open.moves?.[0];
  if (!h) { console.log('NO HANDLE'); process.exit(1); }
  // read-only sub-28 poll probe (safe: no side effects)
  const r = await m.request({command: 'root-native-ipc', handle: h, id: 0x524f0002,
    hex: hex([swap(28n), swap(0n)])}).catch(e => ({error: e.message}));
  const d = Buffer.from(r.data ?? '', 'hex');
  const w = [];
  for (let i = 0; i + 8 <= Math.min(d.length, 96); i += 8) w.push('0x' + d.readBigUInt64LE(i).toString(16));
  console.log('sub-28 reply:', JSON.stringify({result: r.result, error: r.error, words: w.slice(0, 8)}));
  process.exit(0);
})().catch(e => { console.error(String(e.stack || e).slice(0, 300)); process.exit(1); });
