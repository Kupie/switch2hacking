// Reclaim scratch from interrupted launches using their saved ownership records.
const fs = require('node:fs/promises');
const path = require('node:path');
const check = (ok, message) => {if (!ok) throw Error(message);};

async function previousScratch() {
  const current = path.resolve(__dirname, '..'), workspace = path.dirname(current), found = [];
  for (const entry of await fs.readdir(workspace, {withFileTypes: true})) {
    if (!entry.isDirectory() || !/^switch2-[A-Za-z0-9]{6}$/.test(entry.name)) continue;
    const directory = path.join(workspace, entry.name);
    if (directory === current) continue;
    let acquisition;
    try {acquisition = JSON.parse(await fs.readFile(path.join(directory, 'switch2/current-acquisition.json')));}
    catch (error) {if (error.code === 'ENOENT') continue; throw error;}
    const reportPath = path.resolve(acquisition.report);
    const allowedReportRoots = [
      path.join(directory, 'switch2/memory'),
      path.resolve(__dirname, '../../../../ns2jb-extent-diagnostic/runs'),
    ];
    check(/^reserved-gap-[0-9]+\.json$/.test(path.basename(reportPath)) &&
      allowedReportRoots.some(root => reportPath.startsWith(root + path.sep)),
      'Previous acquisition path differs');
    const report = JSON.parse(await fs.readFile(acquisition.report));
    check(report.session === entry.name, 'Previous scratch belongs to a different launch');
    if (report.cleanedUp || !report.retained?.created?.length) continue;
    check(/^\/NS2_GAP_[0-9]{13}$/.test(report.scratch) && report.retained.created.every(item =>
      ['save', 'tmp'].includes(item.name) && item.path === report.scratch), 'Previous scratch ownership is incomplete');
    found.push({source: acquisition.report, scratch: report.scratch, mounts: report.retained.created.map(item => item.name)});
  }
  return found;
}

// Sweep ownership-less scratch left by interrupted launches (crashes/wedges
// never run retire()). The recorded pass above only sees OUR run tree; any
// other pipeline (or a wedge that lost its records) leaks 16 MiB per boot in
// the app save data until every acquisition fails on 'Insufficient save
// space'. Guard: only directories named like scratch and older than 15
// minutes are removed (a concurrent live acquisition owns a fresh one).
async function sweepOrphans(s, domain, previous, proof, save) {
  const filesystem = require('./app/filesystem.cjs');
  const mounted = require('./app/mounted-save.cjs');
  const {paths} = require('./memory/paths.cjs');
  const {normal} = paths(s, domain);
  // 2026-10-26: the guard 15 min -> 60 s. Its purpose = protecting a
  // CONCURRENT live acquisition's fresh scratch, but session.sh enforces a
  // single host and every attempt here = a full console reboot — no live
  // scratch can exist at sweep time. The 15-min guard made rapid retries
  // leak 16 MiB each until the save filled ('Insufficient save space').
  const ageGuardMs = Number(process.env.NS2_SCRATCH_AGE_MS ?? 60 * 1000), now = Date.now(), swept = [];
  for (const name of ['save', 'tmp']) {
    const handle = await mounted.cloneMountedFilesystem(s, name);
    try {
      const entries = await filesystem.listDirectory(s, handle, '/');
      for (const entry of entries) {
        // File-type NS2_GAP entries (upstream 9b73729): same name class,
        // same age guard, deleted via cmd 1 instead of the recursive cmd 4.
        // Directory contents are contents-verified as before; a leaked FILE
        // entry can only be scratch residue by construction, so it is removed
        // without a contents check (files cannot be listed like dirs).
        const isDir = entry.type === 0, isFile = entry.type === 1;
        const match = (isDir || isFile) && entry.name.match(/^(?:NS2_GAP|S0)_([0-9]{13})$/);
        if (!match) continue;
        const created = Number(match[1]);
        const path = '/' + entry.name;
        if (!Number.isSafeInteger(created) || now - created < ageGuardMs) {
          swept.push({mount: name, path, skipped: 'age guard'}); continue;
        }
        if (previous.some(item => item.scratch === path)) continue; // handled above
        if (isDir) {
          const contents = await filesystem.listDirectory(s, handle, path);
          const known = new Set(['canary', 'selected', 'commit_data']);
          if (!contents.length || !contents.every(item => known.has(item.name))) {
            swept.push({mount: name, path, skipped: 'unexpected contents: ' +
              contents.map(item => item.name).join(',')}); continue;
          }
        }
        const typed = await normal(handle, 7, path);
        if (typed.result) {swept.push({mount: name, path, skipped: 'type 0x' + typed.result.toString(16)}); continue;}
        // cmd 4 = DeleteDirectoryRecursively (dirs), cmd 1 = DeleteFile (files).
        const command = isDir ? 4 : 1;
        proof.pending = {mount: name, path}; await save();
        const removed = await normal(handle, command, path);
        check(!removed.result, 'Orphan scratch removal failed: 0x' + (removed.result ?? 0).toString(16));
        check(!(await s.ipc('Commit orphan scratch removal ' + path, handle, 10)).result,
          'Orphan scratch cleanup commit failed');
        check((await normal(handle, 7, path)).canonicalResult === 0x202, 'Orphan scratch still exists');
        swept.push({mount: name, path, removed: true, created: new Date(created).toISOString()});
        proof.pending = undefined; await save();
      }
    } finally {await s.close(handle);}
  }
  return swept;
}

async function main() {
  const previous = await previousScratch();
  const proof = {started: new Date().toISOString(), previous, removed: [], swept: [], cleanedUp: false};
  if (!previous.length && !process.env.NS2_NO_ORPHAN_SWEEP) {
    // No recorded scratch: still sweep orphans (other pipelines / lost records)
    // before the acquisition space check can fail the launch.
    const {Session, live} = require('./app/session.cjs');
    const domain = require('./app/domain.cjs');
    const s = new Session('sweep-orphans');
    proof.sweepSession = live.session;
    const file = path.join(__dirname, 'scratch-cleanup.json');
    const save = () => fs.writeFile(file, JSON.stringify(proof, null, 2) + '\n', {mode: 0o600});
    try {
      await s.initialize();
      proof.swept = await sweepOrphans(s, domain, previous, proof, save);
      await s.cleanup();
    } catch (error) {proof.sweepError = error.stack;}
    proof.cleanedUp = !s.base && !s.handles.size;
    proof.completed = new Date().toISOString(); await save();
    return proof;
  }
  if (!previous.length) return {...proof, cleanedUp: true};
  const {Session, live} = require('./app/session.cjs');
  const mounted = require('./app/mounted-save.cjs');
  const filesystem = require('./app/filesystem.cjs');
  const domain = require('./app/domain.cjs');
  const {paths} = require('./memory/paths.cjs');
  const s = new Session('cleanup-prior-launches');
  proof.session = live.session;
  const file = path.join(__dirname, 'scratch-cleanup.json');
  const save = () => fs.writeFile(file, JSON.stringify(proof, null, 2) + '\n', {mode: 0o600});
  try {
    await s.initialize();
    const {normal} = paths(s, domain);
    for (const name of ['save', 'tmp']) {
      const handle = await mounted.cloneMountedFilesystem(s, name);
      for (const record of previous.filter(item => item.mounts.includes(name))) {
        const entry = await normal(handle, 7, record.scratch);
        if (entry.canonicalResult === 0x202) continue;
        check(!entry.result && entry.data.readUInt32LE() === 0, 'Previous scratch is not a directory');
        const contents = await filesystem.listDirectory(s, handle, record.scratch);
        if (name === 'save') {
          check(contents.length === 3 && contents.every(item => ['canary', 'selected', 'commit_data'].includes(item.name)),
            'Previous scratch contents changed; inspect ' + record.source);
          const data = contents.find(item => item.name === 'commit_data');
          check(data.type === 1 && data.size === String(0x1000000), 'Previous commit file changed');
        } else check(contents.length === 1 && contents[0].type === 0 && /^S0_[0-9]{13}$/.test(contents[0].name),
          'Previous temporary directory changed');
        proof.pending = {name, path: record.scratch}; await save();
        check(!(await normal(handle, 4, record.scratch)).result, 'Previous scratch removal failed');
        check(!(await s.ipc('Commit previous scratch removal', handle, 10)).result, 'Scratch cleanup commit failed');
        check((await normal(handle, 7, record.scratch)).canonicalResult === 0x202, 'Previous scratch still exists');
        proof.removed.push(proof.pending); delete proof.pending; await save();
      }
      await s.close(handle);
    }
    // Recorded scratch handled; sweep orphans on the same mounts before the
    // acquisition space check (other pipelines / unrecorded wedges).
    proof.swept = await sweepOrphans(s, domain, previous, proof, save);
  } catch (error) {proof.error = error.stack; throw error;}
  finally {
    await s.cleanup(); proof.cleanedUp = !s.base && !s.handles.size;
    proof.completed = new Date().toISOString(); await save();
  }
  return proof;
}

module.exports = {main};
