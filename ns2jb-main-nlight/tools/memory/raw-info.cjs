'use strict';
const fsSync = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fsSync.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json'), 'utf8'));
const {Client} = require(path.join(latest.directory, 'switch2', 'process', 'client.cjs'));
(async () => {
  const client = await new Client().open();
  const fsHandle = await client.fsProcess();
  console.log('fsHandle:', fsHandle);
  const r = await client.request(0x524f0010, fsHandle, [0n, 0x7c93896000n, 0n, 0n]);
  const d = Buffer.from(r.data, 'hex');
  const w = [];
  for (let i = 0; i + 8 <= d.length; i += 8) w.push('0x' + d.readBigUInt64LE(i).toString(16));
  console.log('raw 0x524f0010 reply words:', w.slice(0, 12).join(' '));
  await client.close();
  process.exit(0);
})().catch(e => { console.error(String(e.stack || e).slice(0, 300)); process.exit(1); });
