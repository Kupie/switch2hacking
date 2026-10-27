'use strict';
// Targeted CodeFS capture for the titles the fw-dump run missed (the EEXIST/
// mid-capture errors). Same flow as fw-dump.cjs: loader root -> code-open ->
// file-capture. Usage: node capture-titles.cjs <title> [title...]
const fs = require('node:fs/promises');
const path = require('node:path');
const latest = JSON.parse(require('node:fs').readFileSync(path.join(__dirname, '..', '..', 'latest-session.json'), 'utf8'));
const runDir = path.join(latest.directory, 'switch2');
(async () => {
  const {connect} = require(path.join(runDir, 'tools', 'fs-memory.cjs'));
  const m = await connect();
  const session = m.info.session;
  console.log('session:', session);
  const loaderRoot = JSON.parse(await require('node:fs').readFileSync(
    path.join(runDir, 'ro', session + '-loader-root-copy.json')));
  const rootHandle = loaderRoot.copy.handle;
  for (const title of process.argv.slice(2)) {
    const id = title.startsWith('0x') ? title : '0x' + title;
    try {
      const storage = Number(process.env.NS2_CODE_STORAGE || 3);
      const code = await m.request({command: 'root-native-code-open', handle: rootHandle,
        title: id, fresh: true, storage, attributes: 1});
      if (code.result) { console.log(id, 'codefs-unavailable 0x' + code.result.toString(16)); continue; }
      const files = [];
      for (const name of ['main.npdm', 'main']) {
        const cap = await m.request({command: 'root-native-file-capture', handle: code.handle, name});
        files.push({name, size: cap.size, sha256: cap.sha256, file: cap.file});
        console.log(id, name, cap.size);
      }
      await m.request({command: 'root-native-code-close', handle: code.handle}).catch(() => {});
      console.log(id, 'CAPTURED', JSON.stringify(files.map(f => f.file)));
    } catch (e) { console.log(id, 'ERROR:', String(e.message).slice(0, 100)); }
  }
  process.exit(0);
})().catch(e => { console.error('ERR', e.message); process.exit(1); });
