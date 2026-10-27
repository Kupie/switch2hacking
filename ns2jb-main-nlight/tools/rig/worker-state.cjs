'use strict';
const fs = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json'), 'utf8'));
const {connect} = require(path.join(latest.directory, 'switch2', 'tools', 'fs-memory.cjs'));
(async () => {
  const m = await connect();
  const s = await m.request({command: 'root-native-worker-state'});
  console.log('state:', JSON.stringify(s).slice(0, 200));
  const j = await m.request({command: 'root-native-worker-join'}).catch(e => ({error: e.message}));
  console.log('join:', JSON.stringify(j).slice(0, 300));
  process.exit(0);
})().catch(e => { console.error(String(e.message).slice(0, 200)); process.exit(1); });
