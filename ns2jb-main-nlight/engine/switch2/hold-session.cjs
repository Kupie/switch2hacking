const fs = require('node:fs/promises');
const path = require('node:path');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

async function hold({directory, session, execution, health, interval = 5000}) {
  const file = path.join(directory, 'session.json');
  const stop = path.join(directory, 'session-stop');
  const lock = path.join(directory, 'session-operation.lock');
  const state = {session, phase: 'active', execution, started: new Date().toISOString()};
  const save = async () => {
    await fs.writeFile(file + '.tmp', JSON.stringify(state, null, 2) + '\n', {mode: 0o600});
    await fs.rename(file + '.tmp', file);
  };
  try {
    await health();
    await save();
    console.log('SESSION READY: verified access retained. Use session.sh status, probe, or stop.');
    for (;;) {
      try {
        await fs.access(stop);
        // Stop and probe share this lock, so retirement cannot overlap a proof.
        const owned = await fs.open(lock, 'wx', 0o600);
        await owned.close();
        state.phase = 'retiring'; await save();
        return;
      } catch (error) {if (!['ENOENT', 'EEXIST'].includes(error.code)) throw error;}
      await delay(interval);
      await health();
      state.lastHealthy = new Date().toISOString(); await save();
    }
  } catch (error) {
    state.phase = 'failed'; state.error = error.message; await save(); throw error;
  }
}
module.exports = {hold};
