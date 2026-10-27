'use strict';
const fsSync = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fsSync.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json'), 'utf8'));
const {Client} = require(path.join(latest.directory, 'switch2', 'process', 'client.cjs'));
(async () => {
  const client = await new Client().open();
  const fsHandle = await client.fsProcess();
  const qualFile = fsSync.readdirSync(path.join(latest.directory, 'switch2', 'process'))
    .find(f => f.includes('qualification'));
  const qual = JSON.parse(fsSync.readFileSync(path.join(latest.directory, 'switch2', 'process', qualFile)));
  const fsText = BigInt(qual.fsText.memory.address);
  const fsRod = BigInt(qual.fsRodata.memory.address);
  for (const [label, addr, len, trusted] of [
    ['fsText page', fsText, 0x1000n, 0n],
    ['fsText page TRUSTED', fsText, 0x1000n, 1n],
    ['gap page TRUSTED', fsRod, 0x1000n, 1n]]) {
    const r = await client.request(0x524f0016, fsHandle, [8n, addr, len, trusted]);
    console.log(label, '->', '0x' + r.result.toString(16));
  }
  await client.close();
  process.exit(0);
})().catch(e => { console.error(String(e.stack || e).slice(0, 300)); process.exit(1); });
