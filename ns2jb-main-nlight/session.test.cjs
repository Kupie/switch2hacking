const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const {savedPairing} = require('./pairing.cjs');
const {hold} = require('./engine/switch2/hold-session.cjs');
async function fixture(t) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ns2-session-test-'));
  t.after(() => fs.rm(dir, {recursive: true, force: true})); return dir;
}
test('saved pairing survives subsequent starts and rejects damaged config', async t => {
  const file = path.join(await fixture(t), 'pairing.json');
  const first = await savedPairing(file);
  assert.deepEqual(await savedPairing(file), first);
  assert.equal((await fs.stat(file)).mode & 0o777, 0o600);
  await fs.writeFile(file, '{"version":1,"token":[1]}');
  await assert.rejects(savedPairing(file), /Invalid saved pairing/);
});
test('stop waits for an operation lock before retirement', async t => {
  const directory = await fixture(t), lock = path.join(directory, 'session-operation.lock');
  await fs.writeFile(lock, ''); await fs.writeFile(path.join(directory, 'session-stop'), '');
  let polls = 0;
  await hold({directory, session: 'test', execution: {}, interval: 1, health: async () => {
    if (++polls === 3) await fs.unlink(lock);
  }});
  assert.equal(polls, 3);
  assert.equal(JSON.parse(await fs.readFile(path.join(directory, 'session.json'))).phase, 'retiring');
  await fs.access(lock);
});
test('connection failure marks the retained session failed', async t => {
  const directory = await fixture(t); let polls = 0;
  await assert.rejects(hold({directory, session: 'test', execution: {}, interval: 1,
    health: async () => {if (++polls === 2) throw Error('Disconnected');}}), /Disconnected/);
  assert.equal(JSON.parse(await fs.readFile(path.join(directory, 'session.json'))).phase, 'failed');
});
