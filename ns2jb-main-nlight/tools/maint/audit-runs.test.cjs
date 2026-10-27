const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const {audit} = require('./audit-runs.cjs');

test('readiness survives later failure; resume and duplicate input do not inflate attempts', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'run-audit-'));
  t.after(() => fs.rm(root, {recursive: true, force: true}));
  const dir = path.join(root, 'switch2-ABC123');
  await fs.mkdir(dir);
  await fs.writeFile(path.join(dir, 'run.log'), '1/4 Checking\n4/4 Verifying\nSESSION READY: retained\nError: disconnected\n');
  await fs.writeFile(path.join(dir, 'result.json'), JSON.stringify({verified: false, error: 'stopped'}));
  await fs.writeFile(path.join(dir, 'run-resume.log'), 'SESSION READY: resumed\n');
  const {summary} = await audit([root, root]);
  assert.equal(summary.loggedRuns, 1);
  assert.equal(summary.readyObserved, 1);
  assert.equal(summary.readyButFinalUnverified, 1);
  assert.equal(summary.withResumeLogs, 1);
});

test('partial evidence stays unknown and malformed JSON is reported', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'run-audit-'));
  t.after(() => fs.rm(root, {recursive: true, force: true}));
  for (const name of ['ABC123', 'DEF456']) await fs.mkdir(path.join(root, 'switch2-' + name));
  await fs.writeFile(path.join(root, 'switch2-ABC123', 'run.log'), '2/4 Acquiring\n');
  await fs.writeFile(path.join(root, 'switch2-ABC123', 'result.json'), '{');
  const {summary, records} = await audit([root]);
  assert.equal(summary.unknown, 2);
  assert.equal(summary.loggedRuns, 1);
  assert.equal(summary.readyObserved, 0);
  assert.ok(records[0].warnings.includes('Malformed JSON: result.json'));
  assert.equal((await audit([])).summary.readyPercentOfLoggedRuns, null);
});
