// Owned fs-heap region dumper — the live fs object graph (the corrupted
// session's objects, the mount-path state) via the FAST readOwned dispatch
// channel (root-native-owned-fetch). Plain reads of our own memory: no rig,
// no flip, no writes. Slice-bounded + resumable like fs-dump.
'use strict';
const fsSync = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fsSync.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json')));
const {connect} = require(path.join(latest.directory, 'switch2', 'tools', 'fs-memory.cjs'));

async function main() {
  const memory = await connect();
  const info = await memory.request({command: 'root-native-info'});
  const base = Number(info.ownedBase), bytes = Number(info.ownedBytes);
  if (!(base > 0 && bytes > 0x10000)) throw Error('no owned region in state');
  console.log('owned region 0x' + base.toString(16) + ' + 0x' + bytes.toString(16));
  const outDir = path.join(latest.directory, 'owned-dump');
  fsSync.mkdirSync(outDir, {recursive: true});
  const out = path.join(outDir, 'owned-' + base.toString(16) + '.bin');
  const maxChunks = Number((process.argv.find(a => a.startsWith('--max-chunks=')) || '').slice(13)) || 96;
  let done = 0;
  if (fsSync.existsSync(out)) {
    done = Math.min(fsSync.statSync(out).size, bytes);
    done -= done % 0x10000;
  }
  const fd = fsSync.openSync(out, done ? 'a' : 'w');
  let chunks = 0, total = done;
  const t0 = Date.now();
  try {
    for (let off = done; off < bytes && chunks < maxChunks; off += 0x10000) {
      const len = Math.min(0x10000, bytes - off);
      const reply = await memory.request({command: 'root-native-owned-fetch',
        address: base + off, length: len});
      const buf = Buffer.from(reply.hex, 'hex');
      if (buf.length !== len) throw Error('fetch returned ' + buf.length + ' of ' + len);
      fsSync.writeSync(fd, buf);
      total += len; chunks++;
      if (chunks % 16 === 0)
        console.log(`  +0x${off.toString(16)}: ${total} bytes (${Date.now() - t0}ms elapsed)`);
    }
  } finally { fsSync.closeSync(fd); }
  console.log(`banked ${total}/${bytes} (${total === bytes ? 'COMPLETE' : 'partial — rerun to resume'})`);
  console.log(`rate: ${chunks} chunks in ${Date.now() - t0}ms`);
}

main().catch(e => {console.error(e.stack || e); process.exitCode = 1;});
