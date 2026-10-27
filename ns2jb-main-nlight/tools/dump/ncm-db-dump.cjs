#!/usr/bin/env node
// NCM content-DB save dumper: reads the SYSTEM-partition FAT16 from raw BIS 20,
// walks GPT -> SYSTEM partition -> FAT -> /save/<id> cluster chain, reads the
// save image raw (16 KiB root-read-bis chunks, all in-window fs-session ops),
// then scans it for known NCA content IDs (MKW dump track) and 04xx/01xx
// ProgramId-shaped u64s. No console writes anywhere.
const fs = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json')));
const {connect} = require(path.join(latest.directory, 'switch2', 'tools', 'fs-memory.cjs'));

const LBA = 512;
const utf16 = b => {let s = ''; for (let i = 0; i + 1 < b.length && (b[i] || b[i + 1]); i += 2)
  s += String.fromCharCode(b[i] | (b[i + 1] << 8)); return s;};

async function main() {
  const targetSave = process.argv[2] || '8000000000000121';
  const needles = {
    '0400000000000036': Buffer.from('97db2b3d38b1be5e', 'hex'),  // creport npdm sha? no - nca ids below
  };
  const ncaIds = {
    'MKW-progNCA': Buffer.from('98e946d3312d454c58042be105072877', 'hex'),
    'MKW-dataNCA': Buffer.from('bc97cbf31eab065923e05c01a6de49ed', 'hex'),
    'FB-cnmtNCA': Buffer.from('88c6ecd89d26f154d459c449d7dd7dd9', 'hex'),
  };
  const m = await connect();
  const probe = await m.request({command: 'root-probe-bis', id: 20});
  if (!probe.opened) throw Error('BIS 20 raw storage open failed: 0x' + (probe.result ?? 0).toString(16));
  console.log('BIS 20 storage size:', probe.size);
  const readBis = async (id, offset, length) => {
    const parts = [];
    for (let at = offset; at < offset + length; at += 0x4000) {
      const take = Math.min(0x4000, offset + length - at);
      const r = await m.request({command: 'root-read-bis', id, offset: at, length: take});
      parts.push(await fs.promises.readFile(r.outputFile));
    }
    return Buffer.concat(parts);
  };

  // GPT
  const head = await readBis(20, 0, 2 * LBA);
  if (head.toString('ascii', LBA, LBA + 8) !== 'EFI PART') throw Error('no GPT at LBA1');
  const entryLba = Number(head.readBigUInt64LE(LBA + 72)), entryCount = head.readUInt32LE(LBA + 80),
    entrySize = head.readUInt32LE(LBA + 84);
  const entries = await readBis(20, entryLba * LBA, entryCount * entrySize);
  let system = null;
  for (let i = 0; i < entryCount; i++) {
    const e = entries.subarray(i * entrySize, (i + 1) * entrySize);
    if (e.every(v => !v)) continue;
    const name = utf16(e.subarray(56, 128));
    if (name === 'SYSTEM') system = {first: Number(e.readBigUInt64LE(32)), last: Number(e.readBigUInt64LE(40))};
  }
  if (!system) throw Error('no SYSTEM partition in GPT');
  const sysBase = system.first * LBA;
  console.log('SYSTEM partition at 0x%x, %d MiB', sysBase, (system.last - system.first + 1) * LBA / 1048576);

  // FAT16 boot sector
  const boot = await readBis(20, sysBase, 0x200);
  const bps = boot.readUInt16LE(0x0b), spc = boot[0x0d], reserved = boot.readUInt16LE(0x0e),
    fatCount = boot[0x10], rootEntries = boot.readUInt16LE(0x11), sectorsPerFat = boot.readUInt16LE(0x16),
    total32 = boot.readUInt32LE(0x20);
  const clusterBytes = bps * spc;
  const fatOffset = sysBase + reserved * bps;
  const rootDirOffset = sysBase + (reserved + fatCount * sectorsPerFat) * bps;
  const dataOffset = rootDirOffset + rootEntries * 32;
  console.log('FAT16: bps %d spc %d reserved %d fats %d rootEntries %d spf %d total %d', bps, spc, reserved,
    fatCount, rootEntries, sectorsPerFat, total32);
  console.log('  data region at 0x%x, cluster %d bytes', dataOffset, clusterBytes);

  // FAT16 entry reader (first FAT)
  const fatSectors = Math.min(sectorsPerFat, 64); // 64 sectors = 32768 entries, enough for a chain
  const fat = await readBis(20, fatOffset, fatSectors * bps);
  const nextCluster = n => {const at = 2 * n; if (at + 2 > fat.length) return -1;
    const v = fat.readUInt16LE(at); return v >= 0xFFF8 ? 0 : v;};
  const clusterOffset = n => dataOffset + (n - 2) * clusterBytes;

  // LFN-aware directory parser
  const parseDir = buf => {
    const out = [];
    for (let i = 0; i + 32 <= buf.length; i += 32) {
      const e = buf.subarray(i, i + 32);
      if (e[0] === 0) break;
      if (e[0x0b] & 0x08) continue;         // deleted entry
      if (e[0x0b] === 0x0F) continue;       // LFN handled by accumulating below
      const short8 = e.subarray(0, 8).toString('ascii').trim();
      const short3 = e.subarray(8, 11).toString('ascii').trim();
      out.push({attr: e[0x0b], cluster: e.readUInt16LE(0x1a), size: e.readUInt32LE(0x1c),
        short8, short3, at: i, lfn: ''});
    }
    return out;
  };
  // LFN pass
  const attachLfn = buf => {
    const entries = parseDir(buf);
    let lfnAcc = null;
    for (let i = 0; i + 32 <= buf.length; i += 32) {
      const e = buf.subarray(i, i + 32);
      if (e[0] === 0) break;
      if (e[0x0b] === 0x0F) {
        const seq = e[0], part = utf16(e.subarray(1, 0x20)) + utf16(e.subarray(0x20, 0x20 + 4)) +
          utf16(e.subarray(0x20 + 6, 0x20 + 6 + 12));
        lfnAcc = (seq & 0x40 ? '' : (lfnAcc || '')) + part;
      } else if (e[0x0b] !== 0x0F && (e[0x0b] & 0x08) === 0) {
        const found = entries.find(x => x.at === i);
        if (found && lfnAcc) {found.lfn = lfnAcc.replace(/\0.*$/, ''); lfnAcc = null;}
      }
    }
    return entries;
  };

  // Read a full directory given its first cluster
  const readDir = async first => {
    const parts = [];
    for (let c = first, guard = 0; c && c > 1 && guard++ < 256; c = nextCluster(c))
      parts.push(await readBis(20, clusterOffset(c), clusterBytes));
    return Buffer.concat(parts);
  };

  // Root directory (fixed region, not chained)
  const root = await readBis(20, rootDirOffset, rootEntries * 32);
  const rootEntriesList = attachLfn(root);
  console.log('root:', rootEntriesList.map(e => (e.lfn || e.short8 + '.' + e.short3) +
    (e.attr & 0x10 ? '/' : '')).join(' '));
  const saveDir = rootEntriesList.find(e => e.attr & 0x10 && e.short8.toUpperCase().startsWith('SAVE'));
  if (!saveDir) throw Error('no SAVE directory in SYSTEM root');
  console.log('SAVE dir cluster', saveDir.cluster);

  // /save directory
  const saveDirBuf = await readDir(saveDir.cluster);
  const saveEntries = attachLfn(saveDirBuf);
  const wanted = saveEntries.find(e => e.lfn === targetSave || e.short8 === targetSave.slice(0, 8));
  if (!wanted) throw Error('save ' + targetSave + ' not found; entries: ' +
    saveEntries.slice(0, 40).map(e => e.lfn || e.short8).join(','));
  console.log('save', targetSave, 'cluster', wanted.cluster, 'size', wanted.size);

  // Cluster chain -> contiguous runs
  const runs = [];
  let c = wanted.cluster, guard = 0;
  while (c && c > 1 && guard++ < 100000) {
    const off = clusterOffset(c);
    const last = runs[runs.length - 1];
    if (last && last.off + last.len === off) last.len += clusterBytes; else runs.push({off, len: clusterBytes});
    c = nextCluster(c);
    if (runs.reduce((a, r) => a + r.len, 0) >= wanted.size) break;
  }
  const totalRun = runs.reduce((a, r) => a + r.len, 0);
  console.log('file extent: %d runs, %d bytes', runs.length, totalRun);

  // Read the image
  const image = Buffer.concat(await Promise.all(runs.map(async r => {
    const parts = [];
    for (let at = r.off; at < r.off + r.len; at += 0x4000) {
      const take = Math.min(0x4000, r.off + r.len - at);
      const rr = await m.request({command: 'root-read-bis', id: 20, offset: at, length: take});
      parts.push(await fs.promises.readFile(rr.outputFile));
    }
    return Buffer.concat(parts);
  })));
  const out = '/tmp/ncm-save-' + targetSave + '.bin';
  fs.writeFileSync(out, image.subarray(0, Math.min(image.length, wanted.size)));
  console.log('dumped', out, Math.min(image.length, wanted.size), 'bytes');

  // Scan
  for (const [label, needle] of Object.entries(ncaIds)) {
    const hits = [];
    let at = image.indexOf(needle);
    while (at >= 0 && hits.length < 8) {hits.push(at); at = image.indexOf(needle, at + 1);}
    const hitsRev = [];
    at = image.indexOf(Buffer.from([...needle].reverse()));
    console.log(label, 'hits:', hits.map(h => '0x' + h.toString(16)).join(',') || 'none');
    for (const h of hits) {
      const ctx = image.subarray(Math.max(0, h - 32), Math.min(image.length, h + 64));
      console.log('  ctx@0x%x:' + ctx.toString('hex'), h);
    }
  }
  const titles = new Map();
  for (let i = 0; i + 8 <= image.length; i += 4) {
    const b0 = image[i], b1 = image[i + 1], b7 = image[i + 7];
    if ((b0 === 0x04 || b0 === 0x01) && b1 === 0x00 && b7 === 0x00 && (image[i + 2] | image[i + 3])) {
      const hex = image.subarray(i, i + 8).toString('hex');
      titles.set(hex, (titles.get(hex) || 0) + 1);
    }
  }
  const rows = [...titles.entries()].sort((a, b) => b[1] - a[1]).slice(0, 40);
  console.log('title-like u64s:', rows.length);
  for (const [hex, count] of rows) console.log(' ', hex, 'x' + count);
  process.exit(0);
}
main().catch(e => {console.error('ERR', e.message); process.exit(1);});