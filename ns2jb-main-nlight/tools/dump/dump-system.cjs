// Dump system state for offline analysis (no game saves, no savegames).
// Usage: node dump-system.cjs [outdir]
//   1. raw BIS partitions (boot0/boot1/calibration/SD-seed)
//   2. SYSTEM (31) + USER (30) FAT filesystems: recursive enumeration + file dumps
// Requires a live session (latest-session.json); netns-wrapped like the probes.
const path = require('node:path');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const crypto = require('node:crypto');
const latest = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json'), 'utf8'));
const dir = path.resolve(latest.directory, 'switch2');
const {connect} = require(dir + '/tools/fs-memory.cjs');

const OUT = path.resolve(process.argv[2] || path.join(require('node:os').homedir(), 'dev/switch/dumps', latest.directory.replace(/.*\//, '')));
const SKIP_OVER = 40 * 1048576;   // skip files > 40 MB by default
const USER_SKIP = [/^\/Album\//, /^\/save\//, /^\/Contents\/registered\//];

async function main() {
  await fsp.mkdir(OUT, {recursive: true});
  const manifest = {session: latest.directory, started: new Date().toISOString(), files: []};
  const memory = await connect();
  const readBis = async (id, offset, length, file) => {
    await memory.request({command: 'root-probe-bis', id});
    const parts = [];
    for (let at = 0; at < length; at += 0x4000) {
      const take = Math.min(0x4000, length - at);
      const r = await memory.request({command: 'root-read-bis', id, offset: offset + at, length: take});
      parts.push(await fsp.readFile(r.outputFile));
    }
    const bytes = Buffer.concat(parts);
    await fsp.writeFile(file, bytes);
    return crypto.createHash('sha256').update(bytes).digest('hex');
  };

  // 1. raw BIS partitions
  console.log('== raw BIS partitions ==');
  for (const [id, size, name] of [[0, 32 * 1048576, 'bis0-bootA.bin'], [10, 32 * 1048576, 'bis10-bootB.bin'],
      [27, 3932160, 'bis27-calibration.bin'], [35, 262144, 'bis35-sdseed.bin']]) {
    const file = path.join(OUT, name);
    if (fs.existsSync(file) && fs.statSync(file).size === size) {
      const sha256 = crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
      console.log('BIS', id, 'already dumped ->', name);
      manifest.files.push({source: 'bis-raw', id, path: name, size, sha256, reused: true});
      continue;
    }
    console.log('dumping BIS', id, '->', name);
    const sha256 = await readBis(id, 0, size, file);
    manifest.files.push({source: 'bis-raw', id, path: name, size, sha256});
  }

  // 2. FAT filesystems (file-level, decrypted by fs)
  const listing = async (id, dirPath) => {
    await memory.request({command: 'root-probe-bis', id});
    const r = await memory.request({command: 'root-probe-bis-filesystem', id});
    if (!r.opened) throw Error('BIS ' + id + ' filesystem did not open');
    return memory.request({command: 'root-list-bis', id, path: dirPath});
  };
  const readFile = async (id, filePath, size, file) => {
    const parts = [];
    for (let at = 0; at < size; at += 0x40000) {
      const take = Math.min(0x40000, size - at);
      const r = await memory.request({command: 'root-read-bis-file', id, path: filePath,
        length: take, offset: at}).catch(e => ({error: e.message}));
      if (r.error) return {error: r.error};
      parts.push(Buffer.from(r.bytes, 'hex'));
    }
    const bytes = Buffer.concat(parts);
    await fsp.writeFile(file, bytes);
    return crypto.createHash('sha256').update(bytes).digest('hex');
  };
  const walk = async (id, dirPath, outDir, label) => {
    await fsp.mkdir(outDir, {recursive: true});
    const listing = await memory.request({command: 'root-list-bis', id, path: dirPath});
    for (const entry of listing.entries) {
      const full = (dirPath === '/' ? '' : dirPath) + '/' + entry.name;
      if (entry.type === 0) { await walk(id, full, path.join(outDir, entry.name), label); continue; }
      const size = Number(entry.size);
      const rel = full.replace(/^\//, '');
      if (id === 30 && USER_SKIP.some(re => re.test(full + '/'))) {
        manifest.files.push({source: label, path: full, size, skipped: 'user-skip'});
        continue;
      }
      if (size > SKIP_OVER) { manifest.files.push({source: label, path: full, size, skipped: 'over-limit'}); continue; }
      const file = path.join(outDir, entry.name);
      const sha256 = await readFile(id, full, size, file);
      if (typeof sha256 !== 'string') { manifest.files.push({source: label, path: full, size, error: sha256.error}); continue; }
      manifest.files.push({source: label, path: full, size, sha256});
      console.log('  ' + label + ':' + full, size, 'bytes ✓');
    }
  };

  console.log('== opening BIS filesystems ==');
  await listing(31, '/');
  await listing(30, '/');

  console.log('== SYSTEM (31) ==');
  await walk(31, '/', path.join(OUT, 'system'), 'system');
  console.log('== USER (30, filtered) ==');
  await walk(30, '/', path.join(OUT, 'user'), 'user');

  manifest.finished = new Date().toISOString();
  await fsp.writeFile(path.join(OUT, 'dump-manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  console.log('dump complete:', OUT, '| files:', manifest.files.length);
}

main().catch(e => { console.error('FAILED:', e.message); process.exit(1); });
