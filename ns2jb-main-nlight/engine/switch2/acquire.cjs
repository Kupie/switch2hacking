const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');
const {spawn} = require('node:child_process');
const {a} = require('../shared/rpc.cjs');
const {request} = require('./tools/endpoint.cjs');
const {verifyProof} = require('./memory/verify-proof.cjs');
const {save, read} = require('./ro/runtime.cjs');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

// The acquisition owns native allocations until retire() completes. The heap
// shaping is boot-layout dependent and flaky, so a failed roll is retried on
// the same boot (a fresh probe re-runs the bounded leak with structurally
// different heap state; corpus evidence only rules out re-rolling one wave).
// Ported from the upstream ns2jb release (crueter, eden-emu): 3 attempts.
async function start() {
  const MAX_ATTEMPTS = 3;
  let lastError;
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    const logFile = path.join(__dirname, 'acquisition.log');
    try {await fs.promises.unlink(logFile);} catch (e) {if (e.code !== 'ENOENT') throw e;}
    const log = fs.createWriteStream(logFile, {flags: 'wx', mode: 0o600});
    await new Promise((resolve, reject) => {log.once('open', resolve); log.once('error', reject);});
    const child = spawn(process.execPath, [path.join(__dirname, 'memory/probe-reserved-gap.cjs')],
      {cwd: __dirname, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true});
    child.stdout.pipe(log, {end: false}); child.stderr.pipe(log, {end: false});
    let reportFile, exited, spawnError;
    child.once('error', error => {spawnError = error;});
    const done = new Promise(resolve => child.once('close', (code, signal) => {
      exited = {code, signal}; log.end(); resolve(exited);
    }));
    const lines = readline.createInterface({input: child.stdout});
    lines.on('line', line => {
      let row;
      try {row = JSON.parse(line);} catch {return;}
      if (row.stage === 'connected') reportFile = row.file;
    });
    const abandon = async () => {
      if (!exited) child.kill('SIGKILL');
      await done;
    };
    try {
      const deadline = Date.now() + 25 * 60 * 1000;
      let report, recorded = false;
      for (;;) {
        if (reportFile) {
          report = await read(reportFile);
          if (!recorded) {
            // Keep the scratch owner discoverable even if acquisition later fails.
            await save(path.join(__dirname, 'current-acquisition.json'), {session: a.session, report: reportFile});
            recorded = true;
          }
        }
        if (report?.memoryControl?.ready) break;
        if (exited || spawnError || Date.now() >= deadline) {
          // Surface everything the child left behind so silent deaths are
          // diagnosable: exit code, signal, and the tail of its output.
          const detail = [];
          if (spawnError) detail.push('spawn: ' + spawnError.message);
          if (exited) detail.push('exit ' + JSON.stringify(exited));
          try {
            const tail = fs.readFileSync(logFile).toString().split('\n').filter(Boolean).slice(-5);
            for (const line of tail) detail.push('tail: ' + line.slice(0, 160));
          } catch {}
          throw Error('FS acquisition did not complete (attempt ' + (attempt + 1) + '). Inspect ' + logFile +
            '; restart the console before another launch.' +
            (detail.length ? '\n  ' + detail.join('\n  ') : ''));
        }
        await delay(500);
      }
      if (report.session !== a.session || report.error || report.cleanupError)
        throw Error('FS acquisition has an error or belongs to another session');
      const proof = await verifyProof(reportFile, a.session);
      const supervisorReport = path.join(__dirname, 'acquisition-supervisor.json');
      await save(supervisorReport, {stage: 'memory-ready', attempts: [{report: reportFile}]});
      const current = {session: a.session, report: reportFile, supervisorReport,
        socketPath: report.memoryControl.socketPath, proof, finished: new Date().toISOString()};
      await save(path.join(__dirname, 'current-acquisition.json'), current);
      return {
        ...current, abandon,
        async retire() {
          const latest = await read(reportFile);
          const retained = latest.retainedMemory;
          if (!latest.memoryControl?.ready || latest.placementUncertain || retained?.pending ||
              latest.memoryControl.pending || latest.retained.threads.length ||
              retained?.promoted && (!retained.ready || !retained.canonical || !retained.zeroCountVerified))
            throw Error('The retained endpoint cannot be retired from its current state');
          const state = latest.nativeRo;
          if (state?.worker && !state.worker.joined) throw Error('A native worker is still pending');
          const result = await request(current.socketPath, {command: 'retire'});
          if (!result.retired && !result.retiring) throw Error('The retained endpoint did not retire');
          const retireDeadline = Date.now() + 60000;
          while (!exited && Date.now() < retireDeadline) await delay(100);
          if (!exited) throw Error('FS cleanup timed out; inspect ' + reportFile);
          const final = await read(reportFile);
          if (exited.code !== 0 || !final.cleanedUp || final.cleanupError)
            throw Error('FS resources did not clean up completely; inspect ' + reportFile);
          return {cleanedUp: true, report: reportFile};
        },
      };
    } catch (error) {
      await abandon();
      lastError = error;
      console.log('acquisition attempt ' + (attempt + 1) + '/' + MAX_ATTEMPTS + ' failed: ' + error.message.split('\n')[0]);
      // Corpus replay (docs/acquisition-state-mining.md): same-boot retries
      // after a placement-class failure are 0/41 — the missed overwrite
      // itself wedges fs (36/41 with fs-wedge death signatures on the next
      // attempt). Stop the launch instead of spawning attempts against a
      // dead console; the operator reboots. All other failure classes
      // (transport/setup/extent-qualification) keep their retries.
      let placementFailed = false;
      if (reportFile) {
        try {
          const report = JSON.parse(await fs.promises.readFile(reportFile, 'utf8'));
          placementFailed = !report.markerSelected &&
            (report.cases || []).some(item => item.profile === 'positive');
        } catch { /* unreadable/partial report: keep the default retry */ }
      }
      if (placementFailed) {
        const fatal = Error('Console reboot required: the overwrite missed the qualified canary ' +
          '(attempt ' + (attempt + 1) + '/' + MAX_ATTEMPTS + '). Same-boot retries are proven futile ' +
          'for this failure class. Inspect ' + reportFile);
        fatal.rebootRequired = true;
        throw fatal;
      }
    }
    if (attempt < MAX_ATTEMPTS - 1) await delay(1000);
  }
  throw lastError;
}

module.exports = {start};
