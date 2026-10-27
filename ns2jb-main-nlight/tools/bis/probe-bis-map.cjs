// Read-only BIS partition map probe. Opens the dedicated root (fsp-srv clone),
// walks BIS ids 0..255 reporting which storages open, their sizes, and whether
// the USER(30)/SYSTEM(31) partition filesystems open. No writes anywhere.
const fs = require('node:fs/promises');
const path = require('node:path');
const runDir = require('node:path').resolve(__dirname, 'runs/switch2-rxMCyH/switch2');
const {connect} = require(runDir + '/tools/fs-memory.cjs');

async function main() {
  const memory = await connect();
  const reportFile = memory.reportFile;
  const file = path.join(path.dirname(reportFile), path.basename(reportFile).replace('.json', '') + '-bis-map.json');
  const proof = {session: memory.info.session, report: reportFile, started: new Date().toISOString(), storages: [], filesystems: []};

  const info = await memory.request({command: 'root-info'});
  proof.rootBefore = info;
  if (!info.initialized) {
    const opened = await memory.request({command: 'root-open'});
    proof.rootOpened = opened;
  }

  for (let id = 0; id <= 255; id++) {
    const probe = await memory.request({command: 'root-probe-bis', id});
    if (probe.opened) {
      proof.storages.push({id, size: probe.size});
      console.log('BIS', id, 'OPEN size', probe.size);
    }
  }

  for (const id of [30, 31]) {
    const probe = await memory.request({command: 'root-probe-bis-filesystem', id});
    proof.filesystems.push({id, result: probe.result, opened: probe.opened,
      entryResult: probe.entryResult, entryType: probe.entryType});
    console.log('BIS filesystem', id, JSON.stringify({result: probe.result, entryResult: probe.entryResult, entryType: probe.entryType}));
  }

  proof.finished = new Date().toISOString();
  await fs.writeFile(file, JSON.stringify(proof, null, 2) + '\n', {mode: 0o600});
  console.log(JSON.stringify({file, storages: proof.storages.length, filesystems: proof.filesystems}));
}

main().catch(error => { console.error(error.stack); process.exitCode = 1; });
