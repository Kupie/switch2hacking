#!/usr/bin/env node
// Targeted dump of the fs vtable gap 0x5992296000-0x59922a7000 (the region
// between the two captured rodata/data slices — it holds the fsp-pr/fsp-srv
// session-class vtables at 0x59922997d8/0x599229d020/0x599229d0c0/0x599229d0e0
// needed for the fsp-pr RegisterProgram decode).
// Method = the proven fs-dump inner loop: rig 0x524f0016 bulk read into the
// owned buffer, fetched via the retained read in 64 KiB chunks.
// Usage: sudo -n ip netns exec switchlab runuser -u <user> -- node dump-fs-gap.cjs
'use strict';
const fsSync = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fsSync.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json')));
const {Client} = require(path.join(latest.directory, 'switch2', 'process', 'client.cjs'));
const {connect} = require(path.join(latest.directory, 'switch2', 'tools', 'fs-memory.cjs'));

// The vtable region = the separate fsRodata slice (the era dump's "gap"):
// resolve its per-boot ASLR base/size from the qualification record.
const qualFile = fsSync.readdirSync(path.join(latest.directory, 'switch2', 'process'))
  .find(f => f.includes('qualification'));
const qual = JSON.parse(fsSync.readFileSync(path.join(latest.directory, 'switch2', 'process', qualFile)));
const GAP_BASE = BigInt(qual.fsRodata.memory.address);
const GAP_SIZE = BigInt(qual.fsRodata.memory.size);

async function main() {
  let client;
  try { client = await new Client().open(); }
  catch (error) {
    const memory = await connect();
    const state = await memory.request({command: 'root-native-info'});
    const owned = (state.services || []).filter(x => x.name === 'ro:dmnt').pop();
    if (!owned) throw error;
    const execution = JSON.parse(fsSync.readFileSync(
      path.join(latest.directory, 'switch2', 'ro', 'current-execution.json')));
    client = new Client();
    client.memory = memory;
    client.pid = execution.pid;
    client.handle = owned.handle;
    client.record = {session: execution.session, calls: []};
    client.file = path.join(latest.directory, 'switch2', 'process',
      execution.session + '-fsgap-' + Date.now() + '.json');
    console.log('fell back to owned ro:dmnt', owned.handle);
  }
  const memory = client.memory;
  const fsHandle = await client.fsProcess();
  const fsInfo = await client.info(fsHandle);
  if (fsInfo.result || !fsInfo.pid) throw Error('fs process probe failed');
  const fsPid = BigInt(fsInfo.pid);
  console.log('fs pid', fsPid);

  const info = await memory.request({command: 'root-native-info'});
  const fetchAt = Number(info.ownedBase) + 0x1800000;
  if (!(Number(info.ownedBytes) > 0x1810000) || fetchAt + 0x10000 > Number(info.ownedBase) + Number(info.ownedBytes))
    throw Error('owned region too small for the fetch buffer');

  const outDir = path.join(__dirname, 'dumps', 'fw23-live-fs');
  fsSync.mkdirSync(outDir, {recursive: true});
  const out = path.join(outDir, `r-${GAP_BASE.toString(16)}-${GAP_SIZE.toString(16)}.bin`);
  const fd = fsSync.openSync(out, 'w');
  try {
    for (let off = 0n; off < GAP_SIZE; off += 0x10000n) {
      const len = GAP_SIZE - off > 0x10000n ? 0x10000n : GAP_SIZE - off;
      const t0 = Date.now();
      const reply = await client.request(0x524f0016, fsHandle, [fsPid, GAP_BASE + off, len, 0n]); // word3=0: the fs-dump proven shape (word3=1 trusted-mode refused 0xd401)
      if (reply.result) throw Error('rig bulk read failed at +0x' + off.toString(16) + ': 0x' + reply.result.toString(16));
      // fetch the chunk from the owned buffer via the dispatch's fast
      // owned-fetch channel (the qpJIeS lesson: never the retained read)
      const fetched = await memory.request({command: 'root-native-owned-fetch',
        address: fetchAt, length: Number(len)});
      const bytes = Buffer.from(fetched.hex, 'hex');
      if (bytes.length !== Number(len)) throw Error('fetch short: got ' + bytes.length + ' want ' + len);
      fsSync.writeSync(fd, bytes);
      console.log('chunk +0x' + off.toString(16) + ' (' + len + 'B, rig ' + (Date.now() - t0) + 'ms)');
    }
  } finally { fsSync.closeSync(fd); }
  console.log('saved', out, fsSync.statSync(out).size, 'bytes');
}
main().catch(e => { console.error(String(e.stack || e).slice(0, 400)); process.exitCode = 1; });
