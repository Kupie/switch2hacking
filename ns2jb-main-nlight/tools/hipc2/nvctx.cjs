const fs = require('node:fs/promises');
const path = require('node:path');
async function main() {
  const latest = JSON.parse(await fs.readFile(path.join(__dirname, '..', '..', 'latest-session.json')));
  const runDir = path.join(latest.directory, 'switch2');
  const {connect} = require(path.join(runDir, 'tools', 'fs-memory.cjs'));
  const m = await connect();
  // search the SDK wrapper block for svc 0x36 + ret and a few other plain wrappers
  const r = await m.request({command: 'root-native-peek', offset: 0x158000, bytes: 0x1000});
  const data = Buffer.from(r.bytes, 'hex');
  const patterns = {
    'svc36+ret': 'c10600d4c0035fd6',
    'svc35+ret': 'a10600d4c0035fd6',
    'svc34+ret': '810600d4c0035fd6',
    'mrs-x0-tls+ret': '68d03bd5c0035fd6',
    'mrs-x0-tls+retab': '68d03bd5c0035ff6',
  };
  for (const [name, hexstr] of Object.entries(patterns)) {
    const buf = Buffer.from(hexstr, 'hex');
    let at = data.indexOf(buf);
    while (at >= 0) {
      console.log(`${name} @ sdk+0x${(0x158000 + at).toString(16)}`);
      at = data.indexOf(buf, at + 4);
    }
  }
  console.log('search done');
}
main().catch(e => {console.error(e.stack); process.exitCode = 1;});
