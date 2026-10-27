const fs = require('node:fs/promises');
const path = require('node:path');
async function main() {
  const latest = JSON.parse(await fs.readFile(path.join(__dirname, '..', '..', 'latest-session.json')));
  const runDir = path.join(latest.directory, 'switch2');
  const {connect} = require(path.join(runDir, 'tools', 'fs-memory.cjs'));
  const m = await connect();
  // dump the svc wrapper block: send offset 1410140 = 0x157FCC; block approx 0x157800-0x158500
  const r = await m.request({command: 'root-native-peek', offset: 0x157800, bytes: 0x1000});
  const data = Buffer.from(r.bytes, 'hex');
  // enumerate svc instructions + show 4-instruction windows around each wrapper
  for (let i = 0; i < data.length - 4; i += 4) {
    const w = data.readUInt32LE(i);
    if ((w & 0xFFE00000) === 0xD4000000) {
      const svc = (w >> 5) & 0xFFFF;
      const prev = i >= 4 ? data.readUInt32LE(i - 4) : 0;
      const next = i + 4 < data.length ? data.readUInt32LE(i + 4) : 0;
      console.log(`@0x${(0x157800 + i).toString(16)} svc 0x${svc.toString(16)}  prev=0x${prev.toString(16)} next=0x${next.toString(16)}`);
    }
  }
}
main().catch(e => {console.error(e.stack); process.exitCode = 1;});
