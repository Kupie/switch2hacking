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
  for (const [w0, w1, label] of [
    [4, 1, 'type4 cmd1'], [4, 3, 'type4 cmd3'], [4, 5, 'type4 cmd5'],
    [0x40000, 0, 'type4 tag1'], [2, 1, 'type2 cmd1'], [5, 1, 'type5 cmd1'], [6, 1, 'type6 cmd1']
  ]) {
    const bytes = Buffer.alloc(64);
    bytes.writeUInt32LE(w0, 0); bytes.writeUInt32LE(w1, 4);
    bytes.writeUInt32LE(0, 8); bytes.writeUInt32LE(0, 12);
    const r = await m.request({command: 'root-native-raw-ipc', handle, id: w1, bare: true, hex: hex(bytes)});
    console.log(`${label}: transport 0x${(r.transport>>>0).toString(16)} result=${r.result>>>0} raw=${(r.raw||'').slice(0,48)}`);
  }
}
main().catch(e => {console.error(e.stack); process.exitCode = 1;});
