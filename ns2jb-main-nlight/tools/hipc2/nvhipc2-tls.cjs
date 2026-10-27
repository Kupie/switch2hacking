const fs = require('node:fs/promises');
const path = require('node:path');
async function main() {
  const latest = JSON.parse(await fs.readFile(path.join(__dirname, '..', '..', 'latest-session.json')));
  const runDir = path.join(latest.directory, 'switch2');
  const {connect} = require(path.join(runDir, 'tools', 'fs-memory.cjs'));
  const m = await connect();
  const info = await m.request({command: 'root-native-info'});
  const sm = info.services?.find(s => s.name === 'pm:shell')?.sm;
  const svc = await m.request({command: 'root-native-sm-service', handle: sm, name: 'nvdrv:t'});
  const handle = svc.moves[0];
  console.log('nvdrv:t handle', handle);
  // cmd 1 = Initialize-ish with 0x2000 arg
  const payload = Buffer.alloc(8); payload.writeUInt32LE(0x2000, 0);
  const r = await m.request({command: 'root-native-hipc2', handle, id: 1, hex: payload.toString('hex')});
  console.log(JSON.stringify(r, null, 1).slice(0, 1400));
}
main().catch(e => {console.error(e.stack); process.exitCode = 1;});
