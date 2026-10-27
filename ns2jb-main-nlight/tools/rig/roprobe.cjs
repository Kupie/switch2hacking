'use strict';
const fs = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json'), 'utf8'));
const {connect} = require(path.join(latest.directory, 'switch2', 'tools', 'fs-memory.cjs'));
(async () => {
  const m = await connect();
  const r = await m.request({command: 'root-native-ro-probe', hex: '0102030405060708'}).catch(e => ({error: e.message}));
  console.log('ro-probe:', JSON.stringify(r).slice(0, 160));
  process.exit(0);
})().catch(e => { console.error(String(e.message).slice(0, 200)); process.exit(1); });
