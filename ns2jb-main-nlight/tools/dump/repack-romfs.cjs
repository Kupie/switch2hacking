#!/usr/bin/env node
// Repack an extracted RomFS file tree into (a) a valid binary RomFS image and
// (b) the game-dump packaging format (romfs/ tree + manifest.json with
// offsets + romfs-file-list.json), so a dump can be mounted or diffed either way.
//
// Image layout (classic builder order; section order is builder-dependent,
// extents are what matter — see FINDINGS "RomFS specifics"):
//   header 0x50 | dirhash | dirtable | filehash | filetable | data
// Entry layouts (live-verified against real Switch 2 RomFS):
//   dir:  parent u32@0, sibling u32@4, child u32@8, firstFile u32@12,
//         hash u32@16, nameLen u32@20, name[] (entries 4-byte aligned)
//   file: parent u32@0, sibling u32@4, offset u64@8, size u64@16,
//         hash u32@24, nameLen u32@28, name[] (entries 4-byte aligned)
// Name hash (documented RomFS builder hash): h = c + h*123 over the name bytes.
// Sibling chains order entries within a parent; hash chains link colliding
// buckets (slot = first entry offset, chain via the hash field, 0 = tail).
//
// Usage: node tools/dump/repack-romfs.cjs <tree-dir> <out-dir> [--no-image]
'use strict';
const fsSync = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

const NONE = 0xffffffff;
const align = (n, a) => Math.ceil(n / a) * a;
const nameHash = name => {
  let h = 0;
  for (const c of Buffer.from(name, 'utf8')) h = (c + h * 123) >>> 0;
  return h >>> 0;
};
const pow2min4 = n => {let v = 4; while (v < n) v *= 2; return v;};

function buildModel(root) {
  const dirs = [{name: '', parent: 0, children: [], files: []}];
  const files = [];
  const queue = [''];
  const index = new Map([['', 0]]);
  while (queue.length) {
    const prefix = queue.shift();
    for (const item of fsSync.readdirSync(path.join(root, prefix),
      {withFileTypes: true}).sort((a, b) => a.name.localeCompare(b.name))) {
      const rel = prefix ? prefix + '/' + item.name : item.name;
      if (item.isDirectory()) {
        index.set(rel, dirs.length);
        dirs.push({name: item.name, parent: index.get(prefix), children: [], files: []});
        dirs[index.get(prefix)].children.push(dirs.length - 1);
        queue.push(rel);
      } else {
        files.push({name: item.name, dir: index.get(prefix),
          size: fsSync.statSync(path.join(root, rel)).size, rel});
        dirs[index.get(prefix)].files.push(files.length - 1);
      }
    }
  }
  return {dirs, files};
}

function layout(model) {
  let at = 0;
  for (const dir of model.dirs) {dir.at = at; at += align(24 + Buffer.byteLength(dir.name), 4);}
  const dirTableSize = at;
  at = 0;
  for (const file of model.files) {file.at = at; at += align(32 + Buffer.byteLength(file.name), 4);}
  const fileTableSize = at;
  let data = 0;
  for (const file of model.files) {file.offset = data; data += align(file.size, 0x10);}
  return {dirTableSize, fileTableSize, dataSize: data};
}

function buildTables(model, sizes) {
  const dirBuckets = pow2min4(model.dirs.length * 4) / 4;   // u32 slots
  const fileBuckets = pow2min4(model.files.length * 4) / 4;
  const dirHash = Buffer.alloc(dirBuckets * 4), fileHash = Buffer.alloc(fileBuckets * 4);
  const dirTable = Buffer.alloc(sizes.dirTableSize), fileTable = Buffer.alloc(sizes.fileTableSize);
  const dirFirst = new Array(dirBuckets).fill(0), fileFirst = new Array(fileBuckets).fill(0);

  for (const [i, dir] of model.dirs.entries()) {
    const name = Buffer.from(dir.name, 'utf8');
    const b = dirTable.subarray(dir.at, dir.at + align(24 + name.length, 4));
    b.writeUInt32LE(i === 0 ? 0 : model.dirs[dir.parent].at, 0);
    b.writeUInt32LE(NONE, 4);
    b.writeUInt32LE(dir.children.length ? model.dirs[dir.children[0]].at : NONE, 8);
    b.writeUInt32LE(dir.files.length ? model.files[dir.files[0]].at : NONE, 12);
    b.writeUInt32LE(0, 16);
    b.writeUInt32LE(name.length, 20);
    name.copy(b, 24);
  }
  for (const file of model.files) {
    const name = Buffer.from(file.name, 'utf8');
    const b = fileTable.subarray(file.at, file.at + align(32 + name.length, 4));
    b.writeUInt32LE(model.dirs[file.dir].at, 0);
    b.writeUInt32LE(NONE, 4);
    b.writeBigUInt64LE(BigInt(file.offset), 8);
    b.writeBigUInt64LE(BigInt(file.size), 16);
    b.writeUInt32LE(0, 24);
    b.writeUInt32LE(name.length, 28);
    name.copy(b, 32);
  }

  // sibling chains within each parent (table order, last = NONE already set)
  for (const dir of model.dirs) {
    for (let i = 0; i + 1 < dir.children.length; i++)
      dirTable.writeUInt32LE(model.dirs[dir.children[i + 1]].at, model.dirs[dir.children[i]].at + 4);
    for (let i = 0; i + 1 < dir.files.length; i++)
      fileTable.writeUInt32LE(model.files[dir.files[i + 1]].at, model.files[dir.files[i]].at + 4);
  }

  // hash chains: slot = first entry in the bucket, chain via the hash field
  const chainIn = (table, first, bucket, at, chainOffset) => {
    if (first[bucket] === 0) {first[bucket] = at; return;}
    let walk = first[bucket];
    for (;;) {
      const next = table.readUInt32LE(walk + chainOffset);
      if (next === 0) {table.writeUInt32LE(at, walk + chainOffset); return;}
      walk = next;
    }
  };
  for (const [i, dir] of model.dirs.entries()) {
    if (i === 0) continue;   // the root has no name and no hash slot
    chainIn(dirTable, dirFirst, nameHash(dir.name) % dirBuckets, dir.at, 16);
  }
  for (const file of model.files) chainIn(fileTable, fileFirst, nameHash(file.name) % fileBuckets, file.at, 24);
  for (let i = 0; i < dirBuckets; i++) dirHash.writeUInt32LE(dirFirst[i], i * 4);
  for (let i = 0; i < fileBuckets; i++) fileHash.writeUInt32LE(fileFirst[i], i * 4);
  return {dirHash, fileHash, dirTable, fileTable};
}

async function main() {
  const argv = process.argv.slice(2);
  const treeDir = path.resolve(argv[0]), outDir = path.resolve(argv[1]);
  const noImage = argv.includes('--no-image');
  if (!argv[0] || !argv[1]) throw Error('Usage: node repack-romfs.cjs <tree-dir> <out-dir> [--no-image]');

  const model = buildModel(treeDir);
  const sizes = layout(model);
  const tables = buildTables(model, sizes);

  const dirHashOff = 0x50, dirOff = dirHashOff + tables.dirHash.length,
    fileHashOff = dirOff + sizes.dirTableSize, fileOff = fileHashOff + tables.fileHash.length,
    dataOff = fileOff + sizes.fileTableSize;

  const dirPath = i => {
    if (i === 0) return '';
    const parts = [];
    for (let at = i; at !== 0; at = model.dirs[at].parent) parts.unshift(model.dirs[at].name);
    return '/' + parts.join('/');
  };
  const files = model.files.map(f => ({path: dirPath(f.dir) + '/' + f.name, size: f.size,
    offset: f.offset, sha256: crypto.createHash('sha256')
      .update(fsSync.readFileSync(path.join(treeDir, f.rel))).digest('hex')}));
  const tree = [];
  for (const [i] of model.dirs.entries()) {if (i) tree.push({path: dirPath(i), type: 'directory'});}
  tree.push({path: '/', type: 'directory'});
  for (const f of files) tree.push({path: f.path, type: 'file', size: f.size, offset: f.offset});

  await fsp.mkdir(path.join(outDir, 'romfs'), {recursive: true});
  await fsp.cp(treeDir, path.join(outDir, 'romfs'), {recursive: true});
  await fsp.writeFile(path.join(outDir, 'manifest.json'), JSON.stringify({
    section: 'romfs', started: new Date().toISOString(), files, partial: {}}, null, 2));
  const header = [0x50, dirHashOff, tables.dirHash.length, dirOff, sizes.dirTableSize,
    fileHashOff, tables.fileHash.length, fileOff, sizes.fileTableSize, dataOff];
  await fsp.writeFile(path.join(outDir, 'romfs-file-list.json'), JSON.stringify({
    size: dataOff + sizes.dataSize, header: header.map(String), tree}, null, 2));

  if (!noImage) {
    const image = Buffer.alloc(dataOff + sizes.dataSize);
    header.forEach((v, i) => image.writeBigUInt64LE(BigInt(v), i * 8));
    tables.dirHash.copy(image, dirHashOff);
    tables.dirTable.copy(image, dirOff);
    tables.fileHash.copy(image, fileHashOff);
    tables.fileTable.copy(image, fileOff);
    for (const f of model.files) fsSync.readFileSync(path.join(treeDir, f.rel)).copy(image, dataOff + f.offset);
    await fsp.writeFile(path.join(outDir, 'romfs.img'), image);
    console.log('image:', image.length, 'bytes | dirs', model.dirs.length,
      '| files', model.files.length, '| data at', dataOff);
  }
  console.log('packaged:', outDir, '|', files.length, 'files');
}
main().catch(e => {console.error(e.stack || e.message); process.exitCode = 1;});
