#!/usr/bin/env node
// SYSTEM ARCHIVE BATCH via fs cmd 10 (OpenFileSystemWithId) fsType 6 — the
// 2026-10-28 decode: cmd 206's dispatcher mask-gates type-6 into the host
// flow (@Host only); cmd 10's WithId form reaches the DATA path directly.
// Fresh-boot proven (x7Edbi/GeodhE era): no promote, no license, no uptime.
'use strict';
const path = require('node:path');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const crypto = require('node:crypto');
const latest = JSON.parse(fs.readFileSync(process.env.HOME + '/dev/ns2jb/latest-session.json'));
const engine = path.join(latest.directory, 'switch2');
const {Session, u32, u64, check} = require(path.join(engine, 'app', 'session.cjs'));
const domain = require(path.join(engine, 'app', 'domain.cjs'));
const filesystem = require(path.join(engine, 'app', 'filesystem.cjs'));
const {paths} = require(path.join(engine, 'memory', 'paths.cjs'));
const check2 = (ok, m) => {if (!ok) throw Error(m);};
const success = (r, l) => {if (r.result) throw Error(l + ': 0x' + (Number(r.result) >>> 0).toString(16)); return r;};
const OUTROOT = process.env.OUTROOT || path.join(require('node:os').homedir(), 'dev/switch/dumps/fw23-archives');
const argv = process.argv.slice(2);
const only = argv.find(x => /^0?x?[0-9a-fA-F]{16}$/.test(x))?.replace(/^0x/, '').toLowerCase() || null;
const invFile = argv.find(x => x.endsWith('.json')) || '/tmp/sysarch-inventory.json';
(async () => {
  const inv = JSON.parse(fs.readFileSync(invFile));
  const targets = only ? inv.filter(a => a.title === only) : inv;
  check2(targets.length, 'no archives selected');
  console.log('archives:', targets.length, '->', OUTROOT);
  const proof = JSON.parse(await fsp.readFile(path.join(engine, 'ro', 'root', 'current-root.json')));
  const s = new Session('sysarch10-' + Date.now(), 0x2100000);
  s.record = async () => {};
  await s.initialize();
  s.bulkDownloads = true;
  const handles = [];
  const track = h => {handles.push(h); return h;};
  try {
    const root = track(domain.oneHandle(success(await domain.send(s, 'clone root', proof.rootHandle,
      domain.wire.control(2)), 'clone root')));
    const pathApi = paths(s, domain);
    let ok = 0, skipped = 0, failed = 0;
    for (const [i, arch] of targets.entries()) {
      const label = arch.title + ' v' + arch.version;
      const outDir = path.join(OUTROOT, arch.title);
      const manifestPath = path.join(outDir, 'manifest.json');
      try {
        const existing = JSON.parse(await fsp.readFile(manifestPath));
        if (existing.completed && existing.files?.length) {
          console.log('==', label, '== already banked', existing.files.length, 'files (skip)');
          skipped++; continue;
        }
      } catch {}
      const pb = Buffer.alloc(0x301);
      pb.write('@SystemContent://registered/' + arch.contentId + '.nca');
      const input = Buffer.alloc(16);
      input[0] = arch.attributes;
      input.writeUInt32LE(6, 4);                      // fsType 6 = DATA (the decode)
      input.writeBigUInt64LE(BigInt('0x' + arch.title), 8);
      const reply = await pathApi.raw(root, 10, pb, input);
      if (reply.result) {
        console.log('==', label, '== REFUSED canonical 0x' + (Number(reply.result) & 0x3fffff).toString(16));
        failed++; continue;
      }
      const fsobj = track(domain.oneHandle(reply));
      try {
        // cmd 10 returns an IFileSystem: walk it recursively (cmd 9 dirs),
        // open each file (cmd 8), size + read + sha256.
        const list = async (dir, prefix) => {
          const entries = await filesystem.listDirectory(s, fsobj, dir, 4096);
          const out = [];
          for (const e of entries) {
            if (e.type === 3) out.push(...await list(prefix + e.name + '/', prefix + e.name + '/'));
            else out.push({path: prefix + e.name});
          }
          return out;
        };
        // listDirectory returns relative names per dir; build the walk manually:
        const walk = async dir => {
          const entries = await filesystem.listDirectory(s, fsobj, dir, 4096);
          if (dir === '/') console.log('   root entries:', entries.length, ':', entries.slice(0, 12).map(e => e.name + ':' + e.type).join(' | '));
          const files = [];
          for (const e of entries) {
            const full = (dir === '/' ? '' : dir) + '/' + e.name;
            if (e.type === 1) files.push({path: full});
            else if (e.type === 0) files.push(...await walk(full));
            else console.log('   (skip type', e.type, 'entry', full + ')');
          }
          return files;
        };
        console.log('==', label, '== OPEN (IFileSystem)');
        const files = await walk('/');
        console.log('   tree:', files.length, 'files');
        const manifest = {title: arch.title, version: arch.version, contentId: arch.contentId,
          attributes: arch.attributes, via: 'fs cmd 10 fsType 6 (OpenFileSystemWithId, DATA class, IFileSystem walk)',
          started: new Date().toISOString(), files: []};
        for (const [j, f] of files.entries()) {
          const file = track(domain.oneHandle(success(
            await filesystem.pathMethod(s, fsobj, 8, f.path, u32(1)), 'open ' + f.path)));
          try {
            const size = Number(await filesystem.fileSize(s, file));
            const target = path.join(outDir, 'archive', f.path);
            await fsp.mkdir(path.dirname(target), {recursive: true});
            const hash = crypto.createHash('sha256');
            const out = await fsp.open(target, 'w');
            try {
              for (let at = 0; at < size; at += 0x100000) {
                const take = Math.min(0x100000, size - at);
                const chunk = await filesystem.readFile(s, file, at, take, s.base + 0x6000);
                hash.update(chunk);
                await out.write(chunk, 0, take, at);
              }
            } finally {await out.close();}
            manifest.files.push({path: f.path, size, sha256: hash.digest('hex')});
          } finally {await s.close(file).catch(() => {});}
          if ((j + 1) % 200 === 0) console.log('   ', j + 1, '/', files.length, 'files');
        }
        manifest.completed = new Date().toISOString();
        await fsp.mkdir(outDir, {recursive: true});
        await fsp.writeFile(manifestPath, JSON.stringify(manifest, null, 2));
        ok++;
        console.log('==', label, '== DONE', files.length, 'files');
      } finally {await s.close(fsobj).catch(() => {});}
      if (i + 1 < targets.length) await new Promise(r => setTimeout(r, Number(process.env.SYSARCH_COOLDOWN_MS ?? 3000)));
    }
    console.log('BATCH DONE:', ok, 'ok /', failed, 'refused /', skipped, 'skipped');
  } finally {
    for (const h of [...handles].reverse()) await s.close(h).catch(() => {});
    await s.cleanup().catch(() => {});
  }
})().catch(e => {console.error('FAILED:', e.stack || e.message); process.exitCode = 1;});
