// nvdrv TIPC framing probe (bare mode): find the word0 layout that passes hipc.
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
  // framing candidates for cmd 1 (Initialize-ish), payload word zeros.
  const candidates = [];
  for (let t = 0; t <= 7; t++) candidates.push({label: `cmd1|t${t}`, w0: (1 << 4) | t});
  candidates.push({label: 'sm-style cmd1', w0: 0x11});
  candidates.push({label: 'cmd3|t1', w0: (3 << 4) | 1});
  candidates.push({label: 'w0=1', w0: 1});
  candidates.push({label: 'w0=3', w0: 3});
  candidates.push({label: 'w0=4', w0: 4});
  for (const c of candidates) {
    const bytes = Buffer.alloc(64);
    bytes.writeUInt32LE(c.w0, 0);
    bytes.writeUInt32LE(0, 4); bytes.writeUInt32LE(0, 8);
    const r = await m.request({command: 'root-native-raw-ipc', handle, id: 1, bare: true, hex: hex(bytes)});
    console.log(`${c.label}: transport 0x${(r.transport>>>0).toString(16)} result=${r.result >>> 0} raw=${(r.raw||'').slice(0,48)}`);
  }
}
main().catch(e => {console.error(e.stack); process.exitCode = 1;});
