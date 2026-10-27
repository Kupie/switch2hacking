// Rebuild the memory controller from the existing report and serve again.
// The console-side state (retained memory, candidate cache slot, owned root)
// persisted across the host restart; this child only rebuilds PC-side pieces.
// Ownership note: the new session does NOT own the recorded retained handles;
// the report's retained inventory is preserved untouched and only the newly
// opened candidate handle is tracked under memoryControl.resumedCandidate.
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const {connect: connectSession, u64} = require('./session.cjs');
const domain = require('../app/domain.cjs');
const {RunControl, reportWriter} = require('./run-control.cjs');
const controller = require('./fs-memory-control.cjs');

const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

async function main() {
  const current = JSON.parse(await fs.readFile(path.join(__dirname, '..', 'current-acquisition.json'), 'utf8'));
  const file = current.report;
  if (!file || !path.isAbsolute(file)) throw Error('current-acquisition.json has no report path');
  const label = path.basename(file).replace(/\.json$/, '');
  const directory = path.dirname(file);
  const report = JSON.parse(await fs.readFile(file, 'utf8'));
  const check = (ok, message) => { if (!ok) throw Error(message); };
  check(report.session === current.session, 'The acquisition report belongs to another session');
  check(report.retainedMemory?.ready && report.retainedMemory.promoted, 'The retained endpoint is not ready; resume needs a previously retained session');
  check(report.ownedRoot?.clones?.length, 'The owned dedicated root handle is missing from the report');

  // The signed plan: prefer the retained snapshot's bootstrap plan; fall back
  // to the last memoryControl plan when it is still a signed header.
  const recordedPlan = report.retainedMemory?.bootstrapPlan || report.memoryControl?.plan;
  check(recordedPlan?.encoding === 'signed-one-shot' && typeof recordedPlan.header === 'string',
    'No signed cache plan is recorded; resume cannot rebuild the memory window');
  const initialPlan = {...recordedPlan, bytes: Buffer.from(recordedPlan.header, 'hex')};
  check(initialPlan.bytes.length === initialPlan.header.length / 2, 'The recorded plan header is not valid hex');

  let s = null, candidateHandle = null, opened = false;
  const generation = label + '-resume-' + Date.now();
  // The save getter preserves the original retained inventory exactly; resume
  // session state is recorded under memoryControl instead.
  const save = reportWriter(file, () => ({...report, metrics: s ? s.metrics : report.metrics}));
  const runControl = new RunControl({id: label + '-resume', save});

  try {
    const connection = await fs.readFile(path.resolve(directory, '../connection.json'), 'utf8')
      .then(JSON.parse);
    const live = {session: report.session, sdk: Number(connection.addresses?.sdk)};
    ({s} = await connectSession(label + '-resume', 0x2400000));
    s.bulkUploads = true;
    s.uploadThreshold = 256;
    const bulk = require(path.join(directory, '../app/bulk-transfer.cjs'));
    check(await s.ready(), 'The native bridge is not ready');

    const b = s.base, output = b + 0xa00000, input = b + 0xb0000;
    const put = async (address, bytes) => {
      const aligned = Buffer.alloc(Math.ceil(bytes.length / 4) * 4);
      bytes.copy(aligned);
      await s.write(address, aligned);
      return bytes.length;
    };
    async function readStorage(handle, size, offset = 0, poison = report.cacheAlias?.outputPoison ?? 0xa5) {
      await s.call('memset', output, poison, size);
      const reply = await s.ipc('Read candidate content', handle, 0,
        Buffer.concat([u64(offset), u64(size)]), {receive: [{address: output, size, mode: 1}]});
      if (reply.result) return {result: reply.canonicalResult, bytes: null};
      const bytes = size >= 0x8000 ? await bulk.read(s, output, size) : await s.readOwned(output, size);
      return {result: reply.canonicalResult, bytes};
    }

    // Reopen the candidate storage over the still-armed canary cache slot.
    const root = report.retained?.root ?? report.ownedRoot.clones[0];
    candidateHandle = domain.oneHandle(await s.ipc('Reuse the canary slot with own content', root, 200));
    opened = true;
    const prime = await readStorage(candidateHandle, 16);
    check(!prime.result, 'Candidate cache slot did not reopen: 0x' + (prime.result ?? 0).toString(16));
    check(prime.bytes.toString('hex') === report.cacheAlias.expectedAliasHex,
      'The reopened candidate content differs from the recorded alias control');
    const controlBytes = await fs.readFile(report.cacheAlias.controlFile);
    const controlCheck = await readStorage(candidateHandle, Math.min(controlBytes.length, 0x8000));
    check(!controlCheck.result && controlBytes.subarray(0, controlCheck.bytes.length).equals(controlCheck.bytes),
      'The candidate control content differs from the recorded range control');
    console.log(JSON.stringify({stage: 'candidate-reopened', handle: candidateHandle,
      prime: prime.bytes.toString('hex'), verified: true}));

    report.memoryControl = {...report.memoryControl, resumedGeneration: generation,
      resumedCandidate: {handle: candidateHandle, sessionBase: s.base, sessionBytes: s.bytes}};
    await runControl.start();
    const context = {s, live: {session: report.session}, report, file, label, save,
      storageSize: Number(report.storageSize), readStorage, candidateHandle, input, put,
      runControl, initialPlan, previousOperations: report.memoryControl.operations || [],
      copyField: null, resumePhase: 'resumed', resumeGeneration: generation};
    await controller.serve(context);
  } finally {
    // Close only what this child opened; the retained inventory stays untouched.
    try {
      if (opened && candidateHandle && s) {
        const invalidate = await s.ipc('Invalidate the widened clean cache', candidateHandle, 5,
          Buffer.concat([u64(2), u64(0), u64(Number(report.storageSize))]));
        const content = invalidate.result ? null : await (async () => {
          const r = await s.ipc('Read candidate content', candidateHandle, 0,
            Buffer.concat([u64(0), u64(16)]), {receive: [{address: s.base + 0xa00000, size: 16, mode: 1}]});
          return r.result ? null : await s.readOwned(s.base + 0xa00000, 16);
        })();
        const expected = report.cacheAlias?.expectedAliasHex;
        if (!invalidate.result && content && (!expected || content.toString('hex') === expected))
          await s.close(candidateHandle);
        // Otherwise leave the handle open: an unexpected content state is
        // evidence, and closing it cannot be verified.
      }
    } catch (error) { console.error(JSON.stringify({stage: 'resume-finally', error: error.message})); }
    try {await runControl.close();} catch {}
    try {await s?.cleanup?.();} catch {}
  }
}

module.exports = {main};
if (require.main === module) main().catch(error => {
  console.error(JSON.stringify({error: error.message, stack: error.stack.split('\n').slice(0, 4).join(' | ')}));
  process.exitCode = 1;
});
