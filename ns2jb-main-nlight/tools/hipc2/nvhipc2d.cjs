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
  // open pm:dmnt and try HIPC2 framing on it (we know it answers cmif cmd 0)
  const svc = await m.request({command: 'root-native-sm-service', handle: sm, name: 'pm:dmnt'});
  const handle = svc.moves[0];
  console.log('pm:dmnt handle', handle);
  const msg = Buffer.alloc(64);
  msg.writeUInt32LE(6, 0); msg.writeUInt32LE(handle, 4);
  msg.write('SFCI', 8); msg.writeUInt32LE(1, 12);
  msg.writeUInt32LE(0, 16); msg.writeUInt32LE(1, 20);
  const r = await m.request({command: 'root-native-raw-ipc', handle, id: 0, bare: true, hex: hex(msg)});
  console.log('hipc2->pm:dmnt cmd0: transport 0x' + (r.transport>>>0).toString(16), 'raw', (r.raw||'').slice(0,96));
  // same via standard cmif (s.ipc) as baseline for comparison
  const r2 = await m.request({command: 'root-native-ipc', handle: handle, id: 0, hex: ''});
  console.log('cmif->pm:dmnt cmd0:', JSON.stringify({result: r2.result, moves: r2.moves, hex: (r2.hex||'').slice(0,32)}));
}
main().catch(e => {console.error(e.stack); process.exitCode = 1;});
