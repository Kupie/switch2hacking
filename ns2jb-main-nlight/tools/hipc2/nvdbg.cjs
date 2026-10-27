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
  console.log('svc', JSON.stringify(svc));
  const handle = svc.moves[0];
  const payload = Buffer.alloc(8); payload.writeUInt32LE(0x12345678, 0); payload.writeUInt32LE(0xdeadbeef, 4);
  const r = await m.request({command: 'root-native-raw-ipc', handle, id: 3, hex: payload.toString('hex')});
  console.log('raw-ipc full:', JSON.stringify(r, null, 1));
}
main().catch(e => {console.error(e.stack); process.exitCode = 1;});
