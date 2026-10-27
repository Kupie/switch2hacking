const fs = require('node:fs/promises');
const path = require('node:path');
const read = file => fs.readFile(file, 'utf8').then(JSON.parse);
async function main(command) {
  if (!['status', 'probe', 'stop'].includes(command)) throw Error('Usage: session.sh status|probe|stop');
  const {directory} = await read(path.join(__dirname, 'latest-session.json'));
  if (path.dirname(directory) !== path.join(__dirname, 'runs') || !/^switch2-[A-Za-z0-9]{6}$/.test(path.basename(directory)))
    throw Error('Invalid session directory');
  const root = path.join(directory, 'switch2'), file = path.join(root, 'session.json');
  let state;
  try {state = await read(file);}
  catch (error) {
    if (error.code !== 'ENOENT') throw error;
    let result; try {result = await read(path.join(directory, 'result.json'));} catch {}
    throw Error(result?.error || 'Session is not ready yet. Check the host terminal.');
  }
  if (command === 'status') {
    if (state.phase === 'active') {
      const status = await require(path.join(directory, 'shared/rpc.cjs')).request({command: 'status'});
      if (!status.ready) throw Error('Saved session is stale: console disconnected');
      const acquisition = await read(path.join(root, 'current-acquisition.json'));
      const info = await require(path.join(root, 'tools/endpoint.cjs')).request(acquisition.socketPath, {command: 'info'});
      if (!info.ready) throw Error('Retained memory endpoint is not ready');
    }
    console.log(JSON.stringify({directory, ...state}, null, 2)); return;
  }
  if (state.phase !== 'active') throw Error('Session is ' + state.phase);
  const lock = path.join(root, 'session-operation.lock');
  const owned = await fs.open(lock, 'wx', 0o600).catch(error => {
    if (error.code === 'EEXIST') throw Error('Another session operation is active; do not replay it');
    throw error;
  });
  await owned.close();
  try {
    state = await read(file);
    if (state.phase !== 'active') throw Error('Session is no longer active');
    if (command === 'stop') {
      await fs.writeFile(path.join(root, 'session-stop'), '', {flag: 'wx', mode: 0o600});
      console.log('Cleanup requested. Wait for the host to confirm restoration and cleanup.');
    } else {
      try {await fs.access(path.join(root, 'session-stop')); throw Error('Cleanup has already been requested');}
      catch (error) {if (error.code !== 'ENOENT') throw error;}
      const proof = await require(path.join(root, 'process/fs-execute.cjs')).main();
      if (!proof.verified || !proof.restored) throw Error('Repeated FS execution proof failed');
      console.log(JSON.stringify(proof, null, 2));
    }
  } finally {await fs.unlink(lock);}
}
if (require.main === module) main(process.argv[2]).catch(error => {console.error(error.message); process.exitCode = 1;});
module.exports = {main};
