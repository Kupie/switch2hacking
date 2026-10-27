// Post-reboot persistence validation (task-1). Run after the console dance:
// reads every manifest marker back from USER:/temp and compares hashes.
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const projectDir = __dirname;
const latest = JSON.parse(fs.readFileSync(path.join(projectDir, 'latest-session.json'), 'utf8'));
const dir = path.resolve(latest.directory, 'switch2');
const {connect} = require(dir + '/tools/fs-memory.cjs');

async function main() {
  const manifestPath = process.env.NS2_PERSIST_MANIFEST ||
    require('node:fs').existsSync(path.join(dir, 'bis-persistence-manifest.json'))
      ? path.join(dir, 'bis-persistence-manifest.json')
      : path.join(projectDir, 'runs', 'switch2-1z3IsI', 'switch2', 'bis-persistence-manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const memory = await connect();
  await memory.request({command: 'root-probe-bis-filesystem', id: 30});
  const results = [];
  for (const entry of manifest.files) {
    try {
      const read = await memory.request({command: 'root-read-bis-file', id: 30,
        path: entry.path, length: Math.min(entry.size, 0x40000)});
      const matches = read.sha256 === entry.sha256;
      results.push({path: entry.path, size: entry.size, survived: matches,
        expected: entry.sha256.slice(0, 16), actual: read.sha256.slice(0, 16)});
      // multi-chunk files only verify the first 256KiB via root-read-bis-file;
      // the manifest hash covers the full file, so also verify size via listing
    } catch (error) {
      results.push({path: entry.path, survived: false, error: error.message});
    }
  }
  const listing = await memory.request({command: 'root-list-bis', id: 30, path: '/temp'});
  const present = {};
  for (const entry of listing.entries) present[entry.name] = entry;
  for (const entry of manifest.files) {
    const name = entry.path.replace('/temp/', '');
    const listed = present[name] || present[name.replace('.bin', '')];
    const sizeOk = listed && String(listed.size) === String(entry.size);
    results.push({path: entry.path + ' (listing)', sizeOk,
      listedSize: listed ? listed.size : 'absent'});
  }
  const allSurvived = results.filter(r => !r.path.includes('(listing)')).every(r => r.survived);
  const verdict = {session: manifest.session, validatedAt: new Date().toISOString(),
    allSurvived, results};
  const out = path.join(dir, 'bis-persistence-validation.json');
  fs.writeFileSync(out, JSON.stringify(verdict, null, 2) + '\n');
  console.log(JSON.stringify(verdict, null, 1));
  console.log('VERDICT:', allSurvived ? 'ALL MARKERS SURVIVED THE REBOOT' : 'SOME MARKERS DID NOT SURVIVE', '| saved', out);
}

main().catch(error => { console.error('FAILED:', error.message); process.exit(1); });
