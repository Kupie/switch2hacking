#!/usr/bin/env node
// Firmware dump driver (ported from upstream kurumuz/ns2jb dump-firmware.cjs,
// adapted to the retained-session architecture): NCM system-program
// enumeration + read-only CodeFS capture of main.npdm + main for every
// installed system program. Extended with an NCM Application-metaType sweep
// (real game title IDs) — the MKW dump-track oracle.
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const check = (ok, message) => {if (!ok) throw Error(message);};
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

async function main() {
  const latest = JSON.parse(await fs.readFile(path.join(__dirname, '..', '..', 'latest-session.json')));
  const runDir = path.join(latest.directory, 'switch2');
  const {connect} = require(path.join(runDir, 'tools', 'fs-memory.cjs'));
  const m = await connect();
  const session = m.info.session;
  console.log('session:', session);

  const info = await m.request({command: 'root-native-info'});
  const sm = info.services?.find(s => s.name === 'pm:shell')?.sm;
  check(sm, 'no borrowed SM client (pm:shell sm) in service state');
  const loaderRoot = JSON.parse(await fs.readFile(path.join(runDir, 'ro',
    session + '-loader-root-copy.json')));
  const rootHandle = loaderRoot.copy.handle;
  check(info.domainCopies?.some(item => item.handle === rootHandle), 'loader root copy missing');

  // --- NCM lookup + system-program inventory ---
  const lookup = await m.request({command: 'root-native-sm-service', handle: sm, name: 'ncm'});
  check(!lookup.transport && !lookup.result && lookup.moves?.length === 1, 'ncm lookup failed');
  const ncm = lookup.moves[0];
  console.log('ncm handle:', ncm);

  const system = await m.request({command: 'root-native-ncm-list-system', handle: ncm});
  console.log('system programs:', system.total, '(written', system.written + ', complete:', system.complete + ')');
  for (const key of system.keys) console.log(' ', key.id, 'v' + key.version);

  // --- Application metaType sweep (real game title IDs) ---
  const apps = {keys: []};
  try {
    const appList = await m.request({command: 'root-native-ncm-list-system', handle: ncm, metaType: 0x80});
    Object.assign(apps, appList);
    console.log('application metas:', appList.total, '(written', appList.written + ')');
    for (const key of appList.keys) console.log(' APP', key.id, 'v' + key.version);
  } catch (e) {console.log('application sweep failed:', e.message.slice(0, 90));}

  await m.request({command: 'root-native-close-handle', handle: ncm});

  // --- CodeFS capture of every system program ---
  const journal = {session, started: new Date().toISOString(), entries: []};
  const journalFile = path.join(runDir, 'ro', session + '-firmware-dump.json');
  const save = () => fs.writeFile(journalFile, JSON.stringify(journal, null, 2) + '\n', {mode: 0o600});
  await save();
  let captured = 0, unavailable = 0;
  for (const key of system.keys) {
    const title = key.id;
    const entry = {title, version: key.version};
    try {
      const code = await m.request({command: 'root-native-code-open', handle: rootHandle,
        title, fresh: true, storage: 3, attributes: 1});
      if (code.result) {
        entry.status = 'codefs-unavailable';
        entry.result = code.result;
        unavailable++;
      } else {
        entry.status = 'captured';
        entry.files = [];
        for (const name of ['main.npdm', 'main']) {
          const cap = await m.request({command: 'root-native-file-capture', handle: code.handle, name});
          entry.files.push({name, size: cap.size, sha256: cap.sha256, file: cap.file});
        }
        captured++;
        if (code.handle !== info.codeFileSystems?.[0]?.handle)
          await m.request({command: 'root-native-code-close', handle: code.handle});
      }
    } catch (e) {entry.status = 'error'; entry.error = e.message.slice(0, 120);}
    journal.entries.push(entry);
    await save();
    console.log(entry.status.padEnd(18), title, entry.files ? entry.files.map(f => f.name + ':' + f.size).join(' ') : (entry.result ? '0x' + entry.result.toString(16) : ''));
  }
  journal.completed = new Date().toISOString();
  journal.complete = true;
  journal.counts = {listed: system.keys.length, captured, unavailable};
  await save();
  console.log('journal:', journalFile);
  console.log('counts:', JSON.stringify(journal.counts));
  process.exit(0);
}
main().catch(e => {console.error('ERR', e.message); process.exit(1);});