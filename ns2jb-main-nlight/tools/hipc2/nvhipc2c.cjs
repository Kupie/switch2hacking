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
  const msg = Buffer.alloc(64);
  msg.writeUInt32LE(6, 0); msg.writeUInt32LE(handle, 4);
  msg.write('SFCI', 8); msg.writeUInt32LE(1, 12);
  msg.writeUInt32LE(1, 16); msg.writeUInt32LE(1, 20);
  msg.writeUInt32LE(0x2000, 24);
  const r1 = await m.request({command: 'root-native-raw-ipc', handle, id: 1, bare: true, hex: hex(msg)});
  console.log('send1 transport 0x' + (r1.transport>>>0).toString(16), 'raw', (r1.raw||'').slice(0,80));
  await new Promise(r => setTimeout(r, 800));
  // retry same command: session may now be primed
  const r2 = await m.request({command: 'root-native-raw-ipc', handle, id: 1, bare: true, hex: hex(msg)});
  console.log('send2 transport 0x' + (r2.transport>>>0).toString(16), 'raw', (r2.raw||'').slice(0,80));
  // try a query-ish command (nvdrv 'GetStatus' style), varied token
  const msg2 = Buffer.from(msg); msg2.writeUInt32LE(2, 16); msg2.writeUInt32LE(2, 20);
  const r3 = await m.request({command: 'root-native-raw-ipc', handle, id: 2, bare: true, hex: hex(msg2)});
  console.log('send3 transport 0x' + (r3.transport>>>0).toString(16), 'raw', (r3.raw||'').slice(0,80));
}
main().catch(e => {console.error(e.stack); process.exitCode = 1;});
