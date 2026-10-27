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
  const fsRod = BigInt(qual.fsRodata.memory.address);
  console.log('region:', fsRod.toString(16));
  // 0x524f0015 = SetProcessMemoryPermission; try RW (3)
  for (const perm of [3n, 5n, 7n]) {
    const f = await client.request(0x524f0015, fsHandle, [8n, fsRod, 0x11000n, perm]);
    console.log('flip to perm', perm, '->', '0x' + f.result.toString(16));
    if (f.result === 0n) {
      const r = await client.request(0x524f0016, fsHandle, [8n, fsRod, 0x1000n, 1n]);
      console.log('  bulk read after flip ->', '0x' + r.result.toString(16));
      const back = await client.request(0x524f0015, fsHandle, [8n, fsRod, 0x11000n, 1n]);
      console.log('  restore ->', '0x' + back.result.toString(16));
      if (r.result === 0n) break;
    }
  }
  await client.close();
  process.exit(0);
})().catch(e => { console.error(String(e.stack || e).slice(0, 300)); process.exit(1); });
