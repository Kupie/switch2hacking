'use strict';
const fsSync = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fsSync.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json')));
const RUN = latest.directory;
const {Client, check} = require(path.join(RUN, 'switch2', 'process', 'client.cjs'));
(async () => {
  const c = await new Client().open();
  // rig sub 20: the executor's exact sm sequence, GSH for a 4-char name in arg.
  const name = 'pm:s';
  let arg = 0n;
  for (let i = 0; i < name.length; i++) arg |= BigInt(name.charCodeAt(i)) << BigInt(8 * i);
  const hex = [21n - 1n /* placeholder */, arg].map(() => '').join(''); // unused
  const input = [20n, arg].map(v => BigInt.asUintN(64, v).toString(16).padStart(16, '0')).join('');
  const reply = await c.worker({kind: 'ro-rig', handle: c.handle, hex: input});
  const d = Buffer.from(reply.data ?? '', 'hex');
  const w = [];
  for (let i = 0; i + 8 <= d.length; i += 8) w.push(d.readBigUInt64LE(i));
  console.log(JSON.stringify({
    tag: w[0]?.toString(16), sub: w[1]?.toString(), arg: w[2]?.toString(16),
    connectResult: w[3]?.toString(16), init: w[4]?.toString(16),
    gsh: w[5]?.toString(16), sessionWord: w[6]?.toString(16),
    closeResult: w[7]?.toString(16), raw: d.subarray(0, 80).toString('hex')}));
  await c.close();
})().catch(e => { console.error(String(e.message).slice(0, 200)); process.exitCode = 1; });
