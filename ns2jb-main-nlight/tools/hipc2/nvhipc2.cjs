// HIPC2 framing test: [type=6][handle][SFCI][token=1][cmd][seq][args]
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
  for (const seq of [0, 1]) {
    const msg = Buffer.alloc(64);
    msg.writeUInt32LE(6, 0);          // type 6
    msg.writeUInt32LE(handle, 4);     // handle?
    msg.write('SFCI', 8);
    msg.writeUInt32LE(1, 12);          // token = 1
    msg.writeUInt32LE(1, 16);          // cmd 1 (Initialize)
    msg.writeUInt32LE(seq, 20);        // sequence
    msg.writeUInt32LE(0x1000, 24);      // arg: transfer memory size?
    const r = await m.request({command: 'root-native-raw-ipc', handle, id: 1, bare: true, hex: hex(msg)});
    console.log(`seq=${seq}: transport 0x${(r.transport>>>0).toString(16)} result=${r.result>>>0} raw=${(r.raw||'').slice(0,72)}`);
  }
}
main().catch(e => {console.error(e.stack); process.exitCode = 1;});
