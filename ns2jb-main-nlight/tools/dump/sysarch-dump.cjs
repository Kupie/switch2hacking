#!/usr/bin/env node
// System data archives (8xx titles, storage 3) dumper — the tzdata route
// generalized: NCM content-path resolution -> fsp-srv cmd 10 fsType 6 mount
// (the takeover-host root's own content resolution) -> walk + dump + manifest.
// Per-archive sha256 manifests, resume-safe (skips files already banked).
//
//   sudo -n ip netns exec switchlab runuser -u nlight -- \
//     node tools/dump/sysarch-dump.cjs [--probe] [--only <title-id>]
const path = require('node:path');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const crypto = require('node:crypto');
const latest = JSON.parse(fs.readFileSync(path.join(require('node:os').homedir(),
  'dev/ns2jb/latest-session.json')));
const SESSION = path.basename(latest.directory);
const engine = path.join(latest.directory, 'switch2');
const fsMemory = require(path.join(engine, 'tools', 'fs-memory.cjs'));
const check = (ok, m) => {if (!ok) throw Error(m);};
const OUTROOT = path.join(require('node:os').homedir(), 'dev/switch/dumps/fw23-archives');

(async () => {
  const argv = process.argv.slice(2);
  const probe = argv.includes('--probe');
  const only = argv.includes('--only') ? argv[argv.indexOf('--only') + 1] : null;
  const memory = await fsMemory.connect();
  const inventory = JSON.parse(await fsp.readFile('/tmp/sysarch-inventory.json'));
  const targets = only ? inventory.filter(a => a.title === only.replace(/^0x/, '')) : inventory;
  check(targets.length, 'no archives selected');
  console.log('archives:', targets.length, probe ? '(probe)' : '->', OUTROOT);
  await fsp.mkdir(OUTROOT, {recursive: true});

  for (const arch of targets) {
    const outDir = path.join(OUTROOT, arch.title);
    const manifestFile = path.join(outDir, 'manifest.json');
    const manifest = fs.existsSync(manifestFile) ? JSON.parse(await fsp.readFile(manifestFile)) :
      {title: arch.title, version: arch.version, contentId: arch.contentId,
        attributes: arch.attributes, started: new Date().toISOString(), files: []};
    const done = new Map(manifest.files.map(f => [f.path, f]));
    const memoryApi = {
      read: memory.read.bind(memory),
      write: memory.write.bind(memory),
    };
    // ---- resolve the archive NCA path via NCM (GetPath on the content storage) ----
    // storage 3 content storage: OpenContentStorage(3) -> GetPath(cmd 8, contentId)
    // NOTE: system content storage path resolution rides the same session.
    const info = await memory.request({command: 'root-native-info'});
    // (The controller's fs-root-control has root-content-path via ns:am2 cmd 21,
    //  but system-data titles are not "applications" — the NCM GetPath shape
    //  we use on storage 4 is the same. Use root-native-ipc on the ncm handle.)
    // Simpler + proven: fsp-srv cmd 10 with the @SystemContent:// path DIRECTLY —
    // the registered path is deterministic: @SystemContent://registered/<nca>.nca
    const contentPath = '@SystemContent://registered/' + arch.contentId + '.nca';
    console.log('==', arch.title, 'v' + arch.version, '==');
    console.log('  path:', contentPath, 'attr', arch.attributes);
    if (probe) continue;
    // ---- mount (fsType 6) ----
    const mounted = await memory.request({command: 'root-mount-content',
      tid: arch.title, fsType: 6, attr: arch.attributes, path: contentPath, prove: false});
    if (mounted.result) {
      console.log('  mount refused: 0x' + (Number(mounted.result) >>> 0).toString(16));
      manifest.mountError = (Number(mounted.result) >>> 0).toString(16);
      await fsp.mkdir(outDir, {recursive: true});
      await fsp.writeFile(manifestFile, JSON.stringify(manifest, null, 2));
      continue;
    }
    console.log('  mounted, handle:', mounted.handle);
    // ---- walk + dump ----
    const listDir = async dir => {
      const reply = await memory.request({command: 'root-list-romfs', handle: mounted.handle, path: dir});
      if (reply.result) throw Error('list ' + dir + ': 0x' + (Number(reply.result) >>> 0).toString(16));
      return reply.entries;
    };
    const walk = async (dir, prefix, out) => {
      for (const e of await listDir(dir)) {
        const p = prefix + e.name;
        if (e.type === 1) {await walk(dir + (dir.endsWith('/') ? '' : '/') + e.name, p + '/', out); continue;}
        out.push({...e, path: p, dir: dir.endsWith('/') ? dir : dir + '/'});
      }
      return out;
    };
    const entries = await walk('/', '/', []);
    console.log('  tree:', entries.length, 'files');
    let n = 0, bytes = 0;
    for (const e of entries) {
      if (done.has(e.path) && done.get(e.path).size === e.size) continue;
      const out = path.join(outDir, 'archive', e.path);
      await fsp.mkdir(path.dirname(out), {recursive: true});
      const r = await memory.request({command: 'root-read-romfs-file',
        handle: mounted.handle, path: e.dir + e.name});
      if (r.result) {console.log('    read refused', e.path); continue;}
      const data = Buffer.from(r.hex, 'hex');
      check(data.length === e.size, 'short read ' + e.path);
      await fsp.writeFile(out, data);
      const sha = crypto.createHash('sha256').update(data).digest('hex');
      manifest.files.push({path: e.path, size: e.size, sha256: sha});
      bytes += e.size; n++;
    }
    manifest.completed = new Date().toISOString();
    await fsp.writeFile(manifestFile, JSON.stringify(manifest, null, 2));
    console.log('  dumped:', n, 'new files,', (bytes / 1024).toFixed(0) + ' KiB | manifest total:', manifest.files.length);
    // unmount: close the handle
    await memory.request({command: 'root-native-close-handle', handle: mounted.handle}).catch(() => {});
  }
  console.log('ARCHIVES DONE');
})().catch(e => {console.error('FAILED:', e.stack || e.message); process.exitCode = 1;});