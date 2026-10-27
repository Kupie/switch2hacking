// Read-only BIS GPT/FAT16 structure analysis. Uses only root-read-bis (raw
// reads from BIS storage 20). Parses the GPT to locate SYSTEM/USER FAT16
// partitions, then reads their boot sectors and root directories. No writes.
const fs = require('node:fs/promises');
const path = require('node:path');
const {connect} = require(path.resolve(__dirname, 'runs/switch2-rxMCyH/switch2/tools/fs-memory.cjs'));

const LBA = 512;
const utf16 = b => { let s = ''; for (let i = 0; i < b.length && b[i]; i += 2) s += String.fromCharCode(b[i]); return s; };

async function main() {
  const memory = await connect();
  const reportFile = memory.reportFile;
  const label = path.basename(reportFile).replace('.json', '');
  const file = path.join(path.dirname(reportFile), label + '-bis-structure.json');
  const proof = {session: memory.info.session, report: reportFile, started: new Date().toISOString(), reads: [], partitions: [], fats: {}};
  const readBis = async (id, offset, length) => {
    const parts = [];
    for (let at = offset; at < offset + length; at += 0x4000) {
      const take = Math.min(0x4000, offset + length - at);
      const r = await memory.request({command: 'root-read-bis', id, offset: at, length: take});
      parts.push(await fs.readFile(r.outputFile));
    }
    return Buffer.concat(parts);
  };

  // --- GPT parse from raw user NAND (BIS 20) ---
  const head = await readBis(20, 0, 2 * LBA);
  if (head.toString('ascii', LBA, LBA + 8) !== 'EFI PART') throw Error('No GPT header at LBA1');
  const entryLba = head.readBigUInt64LE(LBA + 72), entryCount = head.readUInt32LE(LBA + 80),
    entrySize = head.readUInt32LE(LBA + 84);
  console.log('GPT: entryLba', entryLba.toString(), 'count', entryCount, 'size', entrySize);
  const entries = await readBis(20, Number(entryLba) * LBA, entryCount * entrySize);
  for (let i = 0; i < entryCount; i++) {
    const e = entries.subarray(i * entrySize, (i + 1) * entrySize);
    if (e.every(v => !v)) continue;
    const first = Number(e.readBigUInt64LE(32)), last = Number(e.readBigUInt64LE(40));
    const name = utf16(e.subarray(56, 128));
    proof.partitions.push({index: i, name, firstLba: first, lastLba: last,
      byteOffset: first * LBA, bytes: (last - first + 1) * LBA,
      guid: e.subarray(0, 16).toString('hex')});
    console.log('GPT', i, name, 'LBA', first, '..', last, 'at', (first * LBA / 1024 / 1024 / 1024).toFixed(2), 'GiB', (last - first + 1) * LBA / 1024 / 1024, 'MiB');
  }

  // --- FAT16 boot sector of each FAT partition ---
  for (const p of proof.partitions.filter(p => ['SYSTEM', 'USER', 'SAFE'].includes(p.name))) {
    const boot = await readBis(20, p.byteOffset, 0x400);
    const fat = {
      partition: p.name, offset: p.byteOffset,
      bytesPerSector: boot.readUInt16LE(0x0b), sectorsPerCluster: boot[0x0d],
      reservedSectors: boot.readUInt16LE(0x0e), fatCount: boot[0x10],
      rootEntries: boot.readUInt16LE(0x11), totalSectors16: boot.readUInt16LE(0x13),
      sectorsPerFat: boot.readUInt16LE(0x16), totalSectors32: boot.readUInt32LE(0x20),
      fatSize: (boot.readUInt16LE(0x16) * boot[0x10] * 512) / 1024, fsUtf16Label: utf16(boot.subarray(0x2b, 0x46)),
      signature: boot.toString('ascii', 0x36, 0x3a)
    };
    const rootStart = p.byteOffset + (fat.reservedSectors + fat.sectorsPerFat * fat.fatCount) * fat.bytesPerSector;
    fat.rootDirOffset = rootStart;
    proof.fats[p.name] = fat;
    console.log('FAT16', p.name, JSON.stringify({label: fat.fsUtf16Label, sectorsPerCluster: fat.sectorsPerCluster,
      rootEntries: fat.rootEntries, totalSectors: fat.totalSectors32, rootDirOffset: rootStart, sig: fat.signature}));
    // Root directory (first 0x40 entries = 2 sectors)
    const root = await readBis(20, rootStart, 0x1000);
    const names = [];
    for (let i = 0; i < 0x1000; i += 32) {
      const e = root.subarray(i, i + 32);
      if (e[0] === 0) break;
      if (e[0] === 0xe5 || e[0x0b] === 0x0f) continue;
      const name = e.subarray(0, 8).toString('ascii').trim() + '.' + e.subarray(8, 11).toString('ascii').trim();
      names.push({name, attr: '0x' + e[0x0b].toString(16), cluster: e.readUInt16LE(0x1a), size: e.readUInt32LE(0x1c)});
    }
    fat.rootEntries0 = names;
    console.log('  root:', names.map(n => n.name).join(', '));
  }

  proof.finished = new Date().toISOString();
  await fs.writeFile(file, JSON.stringify(proof, null, 2) + '\n', {mode: 0o600});
  console.log('written', file);
}

main().catch(error => { console.error(error.stack); process.exitCode = 1; });
