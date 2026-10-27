const fs = require('node:fs/promises');
const path = require('node:path');
async function main() {
  const latest = JSON.parse(await fs.readFile(path.join(__dirname, '..', '..', 'latest-session.json')));
  const runDir = path.join(latest.directory, 'switch2');
  const {connect} = require(path.join(runDir, 'tools', 'fs-memory.cjs'));
  const m = await connect();
  const r = await m.request({command: 'root-native-peek', offset: 0x158400, bytes: 0x200});
  const data = Buffer.from(r.bytes, 'hex');
  console.log('len', data.length);
  console.log(data.subarray(0, 0x100).toString('hex').replace(/(.{32})/g, '$1\n'));
}
main().catch(e => {console.error(e.stack); process.exitCode = 1;});
