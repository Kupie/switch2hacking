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
  // cmif framing with hipc type 6 instead of 4
  const cmif = Buffer.alloc(64);
  cmif.writeUInt32LE(6, 0);              // hipc type 6, no buffers
  cmif.writeUInt32LE(Math.ceil((16 + 8) / 4), 4); // raw words (SFCI+8)
  cmif.write('SFCI', 16);
  cmif.writeUInt32LE(1, 24);             // cmif command 1
  cmif.writeUInt32LE(0x12345678, 28);
  const r = await m.request({command: 'root-native-raw-ipc', handle, id: 1, bare: true, hex: hex(cmif)});
  console.log(`type6+cmif cmd1: transport 0x${(r.transport>>>0).toString(16)} result=${r.result>>>0} raw=${(r.raw||'').slice(0,64)}`);
  // and plain type 4 cmif for comparison (what s.ipc does)
  const cmif4 = Buffer.from(cmif); cmif4.writeUInt32LE(4, 0);
  const r2 = await m.request({command: 'root-native-raw-ipc', handle, id: 1, bare: true, hex: hex(cmif4)});
  console.log(`type4+cmif cmd1: transport 0x${(r2.transport>>>0).toString(16)} result=${r2.result>>>0} raw=${(r2.raw||'').slice(0,64)}`);
}
main().catch(e => {console.error(e.stack); process.exitCode = 1;});
