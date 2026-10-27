// Small-rig (0x524f0011) dumper for regions the bulk op rejects (attr-1/16
// vtable areas). 128 bytes per request; bounded; resumable.
'use strict';
const fsSync = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fsSync.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json')));
const {Client} = require(path.join(latest.directory, 'switch2', 'process', 'client.cjs'));

async function main() {
  // Reuse an owned rig session if the sm-get budget is burnt; open fresh otherwise.
  let client;
  try { client = await new Client().open(); }
  catch (error) {
    const {connect} = require(path.join(latest.directory, 'switch2', 'tools', 'fs-memory.cjs'));
    const memory = await connect();
    const state = await memory.request({command: 'root-native-info'});
    const owned = (state.services || []).filter(x => x.name === 'ro:dmnt').pop();
    if (!owned) throw error;
    const execution = JSON.parse(fsSync.readFileSync(
      path.join(latest.directory, 'switch2', 'ro', 'current-execution.json')));
    client = new Client();
    client.memory = memory; client.pid = execution.pid; client.handle = owned.handle;
    client.record = {session: execution.session, calls: []};
    client.file = path.join(latest.directory, 'switch2', 'process', 'smalldump-' + Date.now() + '.json');
    console.log('reusing owned ro:dmnt', owned.handle);
  }
  const fsHandle = await client.fsProcess();
  const fsInfo = await client.info(fsHandle);
  const fsPid = BigInt(fsInfo.pid);
  const regions = JSON.parse(fsSync.readFileSync(
    path.join(latest.directory, 'fs-dump', 'regions.json')));
  // skipped-but-valuable: small attr!=0 regions (vtables, globals)
  const targets = regions.filter(r => [3,4].includes(r.type) && r.attributes !== 0 && r.size <= 0x20000);
  console.log(targets.length, 'small attr regions');
  const outDir = path.join(latest.directory, 'fs-dump');
  const maxReads = Number((process.argv.find(a => a.startsWith('--max-reads=')) || '').slice(13)) || 600;
  let reads = 0;
  for (const r of targets) {
    const name = `r-${r.base.toString(16)}-${r.size.toString(16)}.bin`;
    const out = path.join(outDir, name);
    if (fsSync.existsSync(out) && fsSync.statSync(out).size === r.size) { console.log('done already:', name); continue; }
    if (reads >= maxReads) { console.log('budget reached'); return; }
    const fd = fsSync.openSync(out, 'w');
    try {
      for (let off = 0; off < r.size; off += 0x80) {
        if (reads >= maxReads) { console.log('budget mid-region at', name); return; }
        const reply = await client.read(fsHandle, fsPid, r.base + off, 0x80);
        if (reply.result) throw Error('small read failed 0x' + reply.result.toString(16));
        const bytes = Buffer.from(reply.hex || '', 'hex');
        fsSync.writeSync(fd, bytes);
        reads++;
      }
    } finally { fsSync.closeSync(fd); }
    console.log('dumped', name, `(${r.size} bytes, ${reads} reads total)`);
  }
  console.log('all done,', reads, 'reads');
}
main().catch(e => {console.error(e.stack || e); process.exitCode = 1;});
