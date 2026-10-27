const fs = require('node:fs/promises');
const path = require('node:path');
async function main() {
  const latest = JSON.parse(await fs.readFile(path.join(__dirname, '..', '..', 'latest-session.json')));
  const runDir = path.join(latest.directory, 'switch2');
  const {connect} = require(path.join(runDir, 'tools', 'fs-memory.cjs'));
  const m = await connect();
  const magic = Buffer.from('48505845', 'hex');  // "EXPH" LE
  const SDK_BYTES = 0x5e1000;
  for (let off = 0x400000; off < SDK_BYTES; off += 0x20000) {
    const r = await m.request({command: 'root-native-peek', offset: off, bytes: 0x20000});
    const data = Buffer.from(r.bytes, 'hex');
    let at = data.indexOf(magic);
    while (at >= 0) {
      console.log(`EXPH magic @ sdk+0x${(off + at).toString(16)}`);
      console.log('  context:', data.subarray(at - 16, at + 64).toString('hex'));
      at = data.indexOf(magic, at + 4);
    }
  }
  console.log('scan done');
}
main().catch(e => {console.error(e.stack); process.exitCode = 1;});
