// Read-only exploration of the SmileBASIC save filesystem. Clones the mounted
// save (borrowed session, no console-side writes), lists directories to find
// the NS2 program text, and dumps it for offline diffing.
const fs = require('node:fs/promises');
const fsSync = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fsSync.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json'), 'utf8'));
const runDir = path.resolve(latest.directory, 'switch2');
const session = require(runDir + '/memory/session.cjs');
const mounted = require(runDir + '/app/mounted-save.cjs');
const filesys = require(runDir + '/app/filesystem.cjs');

async function main() {
  const {s, live} = await session.connect('save-explore', 0x40000);
  s.bulkDownloads = false;
  const outDir = path.join(__dirname, 'runs/switch2-rxMCyH/switch2/save-explore');
  await fs.mkdir(outDir, {recursive: true, mode: 0o700});
  const saveFs = await mounted.cloneMountedFilesystem(s, 'save');
  console.log('save filesystem handle:', saveFs);
  const root = await filesys.listDirectory(s, saveFs, '/');
  console.log('root entries:', JSON.stringify(root));
  const found = [];
  async function walk(dirPath, depth) {
    if (depth > 4) return;
    let entries;
    try {entries = await filesys.listDirectory(s, saveFs, dirPath);}
    catch (error) {console.log('skip', dirPath, error.message); return;}
    for (const entry of entries) {
      const full = (dirPath === '/' ? '' : dirPath) + '/' + entry.name;
      if (entry.type === 0) { // directory
        console.log('dir ', full);
        await walk(full, depth + 1);
      } else {
        found.push({path: full, size: entry.size});
        if (/NS2|BAK|GO|BOOT|\.TXT|\.BAS|PG/i.test(entry.name) || full.length < 64)
          console.log('file', full, entry.size, 'bytes');
      }
    }
  }
  await walk('/', 0);
  console.log('total files:', found.length);
  await fs.writeFile(path.join(outDir, 'save-listing.json'),
    JSON.stringify({session: live.session, root, files: found}, null, 2) + '\n', {mode: 0o600});
  for (const target of found.filter(f => /NS2/i.test(f.path))) {
    const handle = (await filesys.openFile(s, saveFs, target.path)).handle;
    if (!handle) {console.log('open failed', target.path); continue;}
    const size = await filesys.fileSize(s, handle);
    const bytes = await filesys.readFile(s, handle, 0, Math.min(Number(size), 0x40000));
    await s.close(handle);
    const out = path.join(outDir, target.path.replace(/\//g, '_').replace(/^_/, '') + '.bin');
    await fs.writeFile(out, bytes, {mode: 0o600});
    const ascii = !bytes.subarray(0, 64).includes(0);
    console.log('dumped', target.path, size, 'bytes ascii:', ascii,
      'head:', JSON.stringify(bytes.subarray(0, 80).toString('latin1')));
  }
}

main().catch(error => { console.error(error.stack); process.exitCode = 1; });
