const fs = require('node:fs/promises');
const path = require('node:path');
const hex = b => b.toString('hex');
async function main() {
  const latest = JSON.parse(await fs.readFile(path.join(__dirname, '..', '..', 'latest-session.json')));
  const runDir = path.join(latest.directory, 'switch2');
  const {connect} = require(path.join(runDir, 'tools', 'fs-memory.cjs'));
  const m = await connect();
  const info = await m.request({command: 'root-native-info'});
  console.log('nativeRo keys:', Object.keys(info));
  const sm = info.services?.find(s => s.name === 'pm:shell')?.sm;
  // add the svc 0x36 wrapper as a raw call via the bare call path: we need a
  // generic native-call. Check what the ro layer exposes:
  const r = await m.request({command: 'root-native-hipc2', handle: sm, id: 0}).catch(e => ({err: String(e.message)}));
  console.log('hipc2 attempt (expected gadget fail):', JSON.stringify(r).slice(0, 200));
}
main().catch(e => {console.error(e.stack); process.exitCode = 1;});
