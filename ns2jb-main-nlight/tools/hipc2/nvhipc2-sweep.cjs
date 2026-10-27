const fs = require('node:fs/promises');
const path = require('node:path');
const hex = b => b.toString('hex');
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
  for (let cmd = 0; cmd <= 16; cmd++) {
    const msg = Buffer.alloc(64);
    msg.writeUInt32LE(6, 0); msg.writeUInt32LE(8, 4);
    msg.write('SFCI', 8); msg.writeUInt32LE(1, 12);
    msg.writeUInt32LE(cmd, 16); msg.writeUInt32LE(1, 20);
    msg.writeUInt32LE(0x2000, 24); // plausible arg
    const r = await m.request({command: 'root-native-raw-ipc', handle, id: cmd, bare: true, hex: hex(msg)});
    console.log(`cmd ${cmd}: transport 0x${(r.transport>>>0).toString(16)} raw=${(r.raw||'').slice(0,64)}`);
  }
}
main().catch(e => {console.error(e.stack); process.exitCode = 1;});
