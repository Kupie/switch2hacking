#!/usr/bin/env node
// Offline finisher for a COMPLETED composed romfs image: recompute the delta
// vs the base manifest (path-normalized), write manifests, and materialize
// the LayeredFS overlay tree (loose files for the delta entries only) by
// copying from the image. Pure disk work — no console needed.
const path = require('node:path');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const crypto = require('node:crypto');
const check = (ok, m) => {if (!ok) throw Error(m);};

const ROOT = '/home/nlight/dev/switch/roms/' + (process.argv[2] || '0400c3f00006e000');
// output dir: the composed-image dir this repo's update-romfs.cjs writes
const fs2 = require('node:fs');
const TITLE = process.argv[2] || '0400c3f00006e000';
const composedDir = fs2.existsSync(path.join(ROOT, 'update-romfs-composed', 'romfs.img'))
  ? path.join(ROOT, 'update-romfs-composed')
  : fs2.existsSync(path.join(ROOT, 'update-v' + (JSON.parse(fs2.readFileSync(path.join(ROOT, 'game.json'))).discovery?.updates?.[0]?.version ?? 917504), 'romfs.img'))
    ? path.join(ROOT, 'update-v' + (JSON.parse(fs2.readFileSync(path.join(ROOT, 'game.json'))).discovery?.updates?.[0]?.version ?? 917504))
    : path.join(ROOT, 'update-v917504');
const OUT = composedDir;
const IMAGE = path.join(OUT, 'romfs.img');

(async () => {
  // ---- parse the image header + tables (composed: data FIRST at h[9]) ----
  const fd = await fsp.open(IMAGE, 'r');
  try {
    const head = Buffer.alloc(0x50);
    check((await fd.read(head, 0, 0x50, 0)).bytesRead === 0x50, 'short header read');
    const h = Array.from({length: 10}, (_, i) => head.readBigUInt64LE(i * 8));
    check(h[0] === 0x50n, 'bad header');
    const dataOffset = Number(h[9]);
    console.log('image:', (Number(h[7]) + Number(h[8]) - Number(h[9])) / 2 ** 30, 'GiB | data at', dataOffset);
    const readBig = async (at, length) => {
      const parts = [];
      for (let o = 0; o < length; o += 0x400000) {
        const buf = Buffer.alloc(Math.min(0x400000, length - o));
        check((await fd.read(buf, 0, buf.length, at + o)).bytesRead === buf.length, 'short table read');
        parts.push(buf);
      }
      return Buffer.concat(parts);
    };
    const dirBytes = await readBig(Number(h[3]), Number(h[4]));
    const fileBytes = await readBig(Number(h[7]), Number(h[8]));
    // ---- walk to files ----
    const NONE = 0xffffffff;
    const files = [];
    const walkDir = (offset, prefix) => {
      let file = dirBytes.readUInt32LE(offset + 12);
      while (file !== NONE) {
        const e = fileBytes.subarray(file, file + 32);
        const len = e.readUInt32LE(28);
        const name = fileBytes.subarray(file + 32, file + 32 + len).toString('utf8');
        files.push({path: prefix + name, offset: Number(e.readBigUInt64LE(8)),
          size: Number(e.readBigUInt64LE(16))});
        file = e.readUInt32LE(4);
      }
      let child = dirBytes.readUInt32LE(offset + 8);
      while (child !== NONE) {
        const e = dirBytes.subarray(child, child + 24);
        const len = e.readUInt32LE(20);
        const name = dirBytes.subarray(child + 24, child + 24 + len).toString('utf8');
        walkDir(child, prefix + name + '/');
        child = e.readUInt32LE(4);
      }
    };
    walkDir(0, '/');
    console.log('tree:', files.length, 'files');
    // ---- delta vs base (leading-slash normalized) ----
    const baseManifest = JSON.parse(await fsp.readFile(path.join(ROOT, 'base', 'manifest.json')));
    const baseMap = new Map(baseManifest.files.map(f => [f.path.startsWith('/') ? f.path : '/' + f.path, f]));
    const delta = {section: 'romfs-delta', base: 'base/manifest.json',
      generated: new Date().toISOString(), added: [], changed: [], unchanged: 0};
    const norm = p => p.startsWith('/') ? p : '/' + p;
    for (const f of files) {
      const key = norm(f.path);
      const b = baseMap.get(key);
      if (!b) {delta.added.push({path: key, size: f.size, offset: f.offset}); continue;}
      // same size + same bytes -> unchanged (hash from the image)
      let same = b.size === f.size;
      if (same) {
        const buf = Buffer.alloc(Math.min(f.size, 0x100000));
        const hash = crypto.createHash('sha256');
        for (let at = 0; at < f.size; at += 0x100000) {
          const take = Math.min(0x100000, f.size - at);
          check((await fd.read(buf, 0, take, dataOffset + f.offset + at)).bytesRead === take,
            'short delta hash read: ' + key);
          hash.update(buf.subarray(0, take));
        }
        same = hash.digest('hex') === b.sha256;
      }
      if (same) delta.unchanged++;
      else delta.changed.push({path: key, size: f.size, offset: f.offset,
        base: {size: b.size, sha256: b.sha256}});
    }
    await fsp.writeFile(path.join(OUT, 'manifest-delta.json'), JSON.stringify(delta, null, 2));
    console.log('DELTA | added:', delta.added.length, '| changed:', delta.changed.length,
      '| unchanged:', delta.unchanged);
    // ---- overlay tree: copy added + changed from the image ----
    const overlayRoot = path.join(OUT, 'romfs-overlay');
    await fsp.rm(overlayRoot, {recursive: true, force: true});
    let n = 0;
    for (const f of [...delta.added, ...delta.changed]) {
      const target = path.join(overlayRoot, 'romfs', f.path);
      await fsp.mkdir(path.dirname(target), {recursive: true});
      const out = await fsp.open(target, 'w');
      try {
        const buf = Buffer.alloc(Math.min(f.size, 0x40000));
        for (let at = 0; at < f.size; at += 0x40000) {
          const take = Math.min(0x40000, f.size - at);
          check((await fd.read(buf, 0, take, dataOffset + f.offset + at)).bytesRead === take,
            'short overlay read: ' + f.path);
          await out.write(buf.subarray(0, take), 0, take, at);   // positional write (buffer, bufOff, len, position)
        }
      } finally {await out.close();}
      if (++n % 10000 === 0) console.log('  overlay', n, 'files');
    }
    console.log('OVERLAY TREE:', n, 'files ->', overlayRoot);
  } finally {await fd.close();}
})().catch(e => {console.error('FAILED:', e.stack || e.message); process.exitCode = 1;});