#!/usr/bin/env node
// Deploy the RO monitor payload to a live session without a console reboot.
// Sequence (mirrors the acquisition launch path, safe ordering):
//   1. cycle the donor (cleanup -> reset -> prepare with the new payload),
//   2. run the gated PM/Loader launch dance (abort-safe, restores on failure),
//   3. start the accepted image, then terminate the previous monitor,
//   4. verify + hand off, update the execution record, probe the exec rig.
// The launch dance is the only reboot-relevant step: if the Loader gate ever
// misbehaves, stop here and reboot the console. Everything before it is a
// transient, file-level write to the application's own temporary volume.
//
// Usage: node deploy-monitor.cjs [--terminate-first]
//   --terminate-first: free the program slot before launching (fallback for
//   pm rejecting a second concurrent instance of the same program id).
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const {run} = require('../../engine/shared/stages.cjs');
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

async function main() {
  const terminateFirst = process.argv.includes('--terminate-first');
  const second = process.argv.includes('--second');
  const policyMatch = process.argv.find(a => a.startsWith('--policy='));
  const policyTitle = policyMatch ? policyMatch.slice('--policy='.length).replace(/^0x/i, '') : '';
  const latest = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json')));
  const runDir = path.join(latest.directory, 'switch2');
  const {connect, encodeU64} = require(path.join(runDir, 'tools', 'fs-memory.cjs'));
  const memory = await connect();
  // Use the run-dir toolchain: its connect() resolves this session's
  // acquisition record, and the launch child writes its proofs beside it.
  const engineRo = path.join(runDir, 'ro');
  const runtime = require(path.join(engineRo, 'runtime.cjs'));
  const executionFile = path.join(runDir, 'ro', 'current-execution.json');
  const previous = JSON.parse(fs.readFileSync(executionFile));
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, 'engine/switch2/ro/payload/manifest.json')));
  // The monitor's policy pin: the 0037 policies entry (npdmFile override)
  // when present - the same source donor-prepare verifies against. The
  // top-level manifest.policySha256 can be stale when a policies entry
  // carries its own npdmFile (the smc-oracle policy era).
  const monitorPolicy = manifest.policies?.['0400000000000037'];
  const monitorPolicyPin = monitorPolicy?.npdm ?? manifest.policySha256;
  const policyEntry = second && policyTitle ? manifest.policies?.[policyTitle] : null;
  const policyObject = policyEntry && typeof policyEntry === 'object' ? policyEntry : null;
  const stagedPayload = second
    ? (policyObject?.payloadFile === 'main' ? 'engine/switch2/ro/payload/main' : 'engine/switch2/ro/payload/executor')
    : 'engine/switch2/ro/payload/main';
  const builtHash = hash(fs.readFileSync(path.join(__dirname, stagedPayload)));
  const expectedPayloadSha = second ? policyObject?.payload : manifest.payloadSha256;
  if (second && !policyObject)
    throw Error('--second requires a pinned policies[' + (policyTitle || 'title') + '] object in the payload manifest');
  if (builtHash !== expectedPayloadSha)
    throw Error('payload build is stale or the run-dir payload is out of sync; run node engine/build-payload.cjs and copy it');
  if (!second) {
    const runHash = hash(fs.readFileSync(path.join(engineRo, 'payload/main')));
    if (runHash !== manifest.payloadSha256)
      throw Error('the run-dir monitor payload is out of sync; run node engine/build-payload.cjs and copy it');
  }
  console.log(JSON.stringify({stage: 'preconditions', session: memory.info.session,
    liveMonitor: {pid: previous.pid, payloadSha256: previous.payloadSha256},
    newMonitor: {payloadSha256: expectedPayloadSha, bytes: second ? policyObject.payloadBytes : manifest.payloadBytes},
    second, policyTitle, terminateFirst}));

  const info = await memory.request({command: 'root-native-info'});
  if (info.worker && !info.worker.joined) throw Error('a native worker is still active');
  // Idempotence guard (BABkjG lesson, 2026-10-24 console fatal 2162-0002):
  // the pipeline stages the CURRENT engine payload at every boot, so a
  // redeploy with an unchanged manifest is always redundant - and its
  // second same-program spawn while the first monitor still holds the
  // service registrations is a console-fatal dice roll that already killed
  // one boot AFTER the dance itself completed. Never roll it again.
  if (!second && !terminateFirst && previous.payloadSha256 === manifest.payloadSha256)
    throw Error('the live monitor already runs the built payload ' + manifest.payloadSha256.slice(0, 12) +
      '; nothing to deploy (use --second --policy=0400000000000036 for the debug executor)');
  const donorBefore = info.donor ? {ready: info.donor.ready, cleanedUp: !!info.donor.cleanedUp} : null;
  console.log(JSON.stringify({stage: 'donor', before: donorBefore}));

  // Idempotent donor cycle: keep a verified donor so re-runs do not churn
  // the domain objects again (each cycle invalidates the bind captures).
  const expected = second ? {main: policyObject.payload, 'main.npdm': policyObject.npdm}
    : {main: manifest.payloadSha256, 'main.npdm': monitorPolicyPin};
  const donorCurrent = info.donor?.ready && info.donor.files?.length === 2 &&
    info.donor.files.every(f => f.verified && expected[f.name] === f.sha256);
  let donor;
  if (donorCurrent) {
    donor = info.donor;
    console.log(JSON.stringify({stage: 'donor-reused', files: donor.files.map(f => ({name: f.name, sha256: f.sha256}))}));
  } else {
    if (info.donor && !info.donor.cleanedUp) {
      const cleanup = await memory.request({command: 'root-native-donor-cleanup'});
      if (!cleanup.cleanedUp) throw Error('donor cleanup did not finish');
      console.log(JSON.stringify({stage: 'donor-cleaned', removed: cleanup.files}));
    }
    if (info.donor) await memory.request({command: 'root-native-donor-reset'});
    // A previous deploy can leave verified payload files in the temporary
    // volume (reused entries are outside donor-cleanup's scope). Purge them
    // only on exact hash match with what we know we placed there.
    const purge = await memory.request({command: 'root-native-donor-purge', names: [
      {name: 'main', sha256: previous.payloadSha256},
      {name: 'main.npdm', sha256: monitorPolicyPin}]});
    console.log(JSON.stringify({stage: 'donor-purged', purged: purge.purged}));
    donor = await memory.request({command: 'root-native-donor-prepare',
      ...(second ? {title: '0x' + policyTitle} : {})});
    if (!donor.ready || !donor.files.every(f => f.verified)) throw Error('donor prepare did not verify');
    const main = donor.files.find(f => f.name === 'main');
    if (main.sha256 !== expectedPayloadSha) throw Error('donor holds a different payload than the build');
    console.log(JSON.stringify({stage: 'donor-prepared', files: donor.files.map(f => ({name: f.name, sha256: f.sha256}))}));
  }

  // Re-derive the loader session and filesystem-type captures from current
  // state; the launch swap verifies against these, and a donor cycle moves
  // the domain objects. (Pipeline runs this right after donor-prepare.)
  const binding = await run(engineRo, 'bind-sessions', [], 120000);
  console.log(JSON.stringify({stage: 'bound', parsed: binding !== null}));

  const ipc = (handle, id, pid) => memory.request({command: 'root-native-ipc', handle, id,
    hex: encodeU64(BigInt(pid)).toString('hex')});
  const shell = info.services.find(s => s.name === 'pm:shell')?.handle;
  const monitor = info.services.find(s => s.name === 'pm:dmnt')?.handle;
  if (!shell || !monitor) throw Error('the owned PM sessions are missing');

  if (terminateFirst) {
    console.log(JSON.stringify({stage: 'terminate-first', pid: previous.pid}));
    const terminated = await ipc(shell, 1, previous.pid);
    // 0x20f = already gone (a crashed previous monitor): the slot is free.
    if (terminated.result && terminated.result !== 0x20f)
      throw Error('terminating the previous monitor failed: 0x' + terminated.result.toString(16));
    console.log(JSON.stringify({stage: 'previous-terminated', pid: previous.pid, result: terminated.result}));
  }

  // The gated PM/Loader dance. Child process; restores the gate on any
  // failure and cleans up an accepted-but-unwanted process on its own.
  const launch = await run(engineRo, 'launch', [], 300000);
  console.log(JSON.stringify({stage: 'launch', ...launch}));
  if (!launch.imageAccepted || !launch.restored || !launch.pid)
    throw Error('launch did not accept an image; state restored, session unchanged');

  const identity = {};
  for (const [name, pid] of [['replacement', launch.pid], ['previous', previous.pid]]) {
    identity[name] = await ipc(monitor, 7, pid);
    console.log(JSON.stringify({stage: 'identify', name, pid, result: identity[name].result,
      program: identity[name].hex}));
  }
  const started = await ipc(monitor, 1, launch.pid);
  if (started.result) throw Error('the accepted image did not start: 0x' + started.result.toString(16));
  console.log(JSON.stringify({stage: 'started', pid: launch.pid}));
  if (!terminateFirst && !second) {
    const terminated = await ipc(shell, 1, previous.pid);
    // 0x20f = already gone (a crashed previous monitor): nothing to stop.
    if (terminated.result && terminated.result !== 0x20f)
      throw Error('the previous monitor did not terminate: 0x' + terminated.result.toString(16));
    console.log(JSON.stringify({stage: 'previous-terminated', pid: previous.pid, result: terminated.result}));
  }

  if (second) {
    // The executor is a pure IPC client: it serves no RO proof. Its record
    // goes to a separate file so the monitor's stays authoritative, and
    // liveness is checked through the relay instead (debug-relay.cjs).
    const record = {verified: true, session: memory.info.session, report: memory.reportFile,
      pid: launch.pid, programId: policyTitle, payloadSha256: policyObject.payload,
      launch: launch.file, deployed: new Date().toISOString(), role: 'debug-executor',
      monitor: {pid: previous.pid, payloadSha256: previous.payloadSha256}};
    const recordFile = path.join(runDir, 'ro', 'current-executor.json');
    await fs.promises.writeFile(recordFile, JSON.stringify(record, null, 2) + '\n', {mode: 0o600});
    console.log(JSON.stringify({stage: 'executor-record', recordFile, pid: record.pid}));
    console.log('EXECUTOR DEPLOYED: check node debug-relay.cjs status (the executor connects to ro:dmnt on its own)');
    return;
  }

  const proof = await runtime.probe(launch.pid);
  const handoff = await runtime.handoff();
  const execution = {verified: true, session: memory.info.session, report: memory.reportFile,
    pid: proof.pid, programId: '0400000000000037', payloadSha256: manifest.payloadSha256,
    proof: proof.file, launch: launch.file, identity: handoff.file, handoff: handoff.file,
    deployed: new Date().toISOString(), previous: {pid: previous.pid, payloadSha256: previous.payloadSha256}};
  await fs.promises.writeFile(executionFile, JSON.stringify(execution, null, 2) + '\n', {mode: 0o600});
  console.log(JSON.stringify({stage: 'execution-record', executionFile, pid: execution.pid}));
  console.log('DEPLOY COMPLETE: verify with node rig-harness.cjs info');
}

main().catch(e => {console.error(e.stack ?? e.message); process.exitCode = 1;});
