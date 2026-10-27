'use strict';
const fsSync = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fsSync.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json'), 'utf8'));
const {Client} = require(path.join(latest.directory, 'switch2', 'process', 'client.cjs'));
(async () => {
  const client = await new Client().open();
  const fsHandle = await client.fsProcess();
  for (const addr of [0x599223e000n, 0x5992290000n, 0x5992295000n, 0x5992296000n, 0x599229d000n, 0x59922a6000n, 0x59922a7000n]) {
    const r = await client.info(fsHandle, addr, 0n);
    const m = r.memory || {};
    console.log('probe', addr.toString(16), '->', JSON.stringify({
      result: r.result, pid: r.pid, programId: r.programId,
      base: m.address ? Number(m.address).toString(16) : null,
      size: m.size ? Number(m.size).toString(16) : null,
      type: m.type, attributes: m.attributes}));
  }
  await client.close();
  process.exit(0);
})().catch(e => { console.error(String(e.stack || e).slice(0, 300)); process.exit(1); });
