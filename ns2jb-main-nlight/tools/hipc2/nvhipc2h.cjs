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
  for (const hi of [8, 0x28, 0x50, 0x30]) {
    for (const size of [0x28, 0x40, 0x50, 0x60, 0x80, 0x100]) {
      const msg = Buffer.alloc(0x40);
      msg.writeUInt32LE(6, 0); msg.writeUInt32LE(hi, 4);
      msg.write('SFCI', 0x10); msg.writeUInt32LE(1, 0x14);
      msg.writeUInt32LE(1, 0x18); msg.writeUInt32LE(0, 0x1c);
      msg.writeUInt32LE(0x2000, 0x20);
      const r = await m.request({command: 'root-native-raw-ipc', handle, id: 1, bare: true, sendSize: size, hex: hex(msg)});
      const t = (r.transport>>>0).toString(16);
      console.log(`hi=${hi} size=0x${size.toString(16)}: 0x${t}${t!=='ca01'&&t!=='f601' ? ' raw=' + (r.raw||'').slice(0,96) : ''}`);
    }
  }
}
main().catch(e => {console.error(e.stack); process.exitCode = 1;});
