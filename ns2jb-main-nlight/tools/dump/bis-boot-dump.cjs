// BIS boot-partition dumper — the kernel-hunting track's prerequisite.
//
// BIS 0 and 10 are the boot partitions (package2/KTN live there — the
// fw23 kernel + warmboot + secure-monitor blobs we have NO dump of).
// Everything here is read-only + proven machinery (root-probe-bis opens
// the storage, root-read-bis reads 16 KiB chunks with sha256 verification).
//
// Usage (netns-wrapped, live READY session):
//   sudo -n ip netns exec switchlab runuser -u nlight -- node bis-boot-dump.cjs [id] [maxBytes]
//   (default: both id 0 and id 10, up to 16 MiB each)
'use strict';
const fsSync = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fsSync.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json')));
const {connect} = require(path.join(latest.directory, 'switch2', 'tools', 'fs-memory.cjs'));

const outDir = path.join(latest.directory, 'bis-boot');
const CHUNK = 0x4000;

async function main() {
  const ids = process.argv[2] ? [Number(process.argv[2])] : [0, 10];
  const maxBytes = Number(process.argv[3] || 16 * 1024 * 1024);
  fsSync.mkdirSync(outDir, {recursive: true});
  const memory = await connect();
  const req = c => memory.request(c);
  const info = await req({command: 'root-native-info'});
  console.log('session', info.session);

  for (const id of ids) {
    console.log(`--- BIS ${id} ---`);
    const probe = await req({command: 'root-probe-bis', id});
    console.log('probe:', JSON.stringify(probe).slice(0, 200));
    if (probe.result) { console.log(`  BIS ${id} not openable (0x${probe.result.toString(16)})`); continue; }
    const size = BigInt(probe.size || '0');
    const take = size > BigInt(maxBytes) ? BigInt(maxBytes) : size;
    console.log(`  size ${size} bytes; dumping ${take}`);
    const out = path.join(outDir, `bis-${id}.bin`);
    const fd = fsSync.openSync(out, 'w');
    let hash = 0n;
    for (let off = 0; off < take; off += CHUNK) {
      const len = Number(BigInt(CHUNK) < take - BigInt(off) ? BigInt(CHUNK) : take - BigInt(off));
      const r = await req({command: 'root-read-bis', id, offset: off, length: len});
      fsSync.writeSync(fd, fsSync.readFileSync(r.outputFile));
      hash ^= BigInt('0x' + r.sha256.slice(0, 8));
      if ((off / CHUNK) % 64 === 0) console.log(`  0x${off.toString(16)} / 0x${take.toString(16)} (last sha ${r.sha256.slice(0, 12)})`);
    }
    fsSync.closeSync(fd);
    console.log(`  dumped to ${out} (${take} bytes)`);
  }
  console.log('done');
}

main().catch(e => {console.error(e.stack || e); process.exitCode = 1;});
