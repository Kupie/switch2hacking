const fs = require('node:fs/promises');
const path = require('node:path');
const {spawn} = require('node:child_process');
const {a} = require('../shared/rpc.cjs');
const {run} = require('../shared/stages.cjs');
const {connect} = require('./tools/fs-memory.cjs');
const runtime = require('./ro/runtime.cjs');
const {read, save, local, hash} = runtime;
const check = (ok, message) => {if (!ok) throw Error(message);};

// Re-attach to a retained session after a host restart: rebuild the memory
// controller from the existing report and hold verified access. Nothing here
// tears down console-side state; stopping only ends the PC-side processes.
async function resumeMain() {
  const file = path.join(__dirname, 'pipeline-resume.json');
  const record = {session: a.session, resumed: new Date().toISOString(), stages: []};
  await fs.writeFile(file, JSON.stringify(record) + '\n', {flag: 'w', mode: 0o600});
  async function stage(name, action) {
    console.log(name);
    const row = {name, started: new Date().toISOString(), status: 'running'};
    record.stages.push(row); await save(file, record);
    try {
      row.result = await action(); row.status = 'complete';
      return row.result;
    } catch (error) {row.status = 'failed'; row.error = error.stack; throw error;}
    finally {row.finished = new Date().toISOString(); await save(file, record);}
  }
  let controllerChild = null, childExited = null, childExitWaiters = [];
  const childClosed = new Promise(resolve => childExitWaiters.push(resolve));
  const stopController = async () => {
    const child = controllerChild; controllerChild = null;
    if (!child || childExited) {
      if (child) await childClosed;
      return;
    }
    child.kill('SIGTERM');
    const escalated = setTimeout(() => child.kill('SIGKILL'), 5000).unref();
    await childClosed;
    clearTimeout(escalated);
  };
  try {
    console.log('R/1 Rebuilding the memory controller');
    await stage('Resume controller', async () => {
      controllerChild = spawn(process.execPath, [path.join(__dirname, 'memory/controller-resume.cjs')],
        {cwd: __dirname, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
          env: {...process.env, NS2_KEEP_SESSION: '1'}});
      controllerChild.stdout.pipe(process.stdout, {end: false});
      controllerChild.stderr.pipe(process.stderr, {end: false});
      controllerChild.once('error', error => {childExited = {error: error.message};
        childExitWaiters.forEach(resolve => resolve(childExited)); childExitWaiters = [];});
      controllerChild.once('close', (code, signal) => {childExited = {code, signal};
        childExitWaiters.forEach(resolve => resolve(childExited)); childExitWaiters = [];});
      const current = await read(path.join(__dirname, 'current-acquisition.json'));
      const reportFile = current.report;
      const initial = await read(reportFile);
      const generation = initial.memoryControl?.resumedGeneration;
      if (!generation) throw Error('The resume controller did not record its generation token');
      const deadline = Date.now() + 5 * 60 * 1000;
      for (;;) {
        if (childExited) throw Error('The resume controller exited: ' + JSON.stringify(childExited));
        const report = await read(reportFile);
        if (report.memoryControl?.ready && report.memoryControl.phase === 'resumed' &&
            report.memoryControl.generation === generation)
          return {socketPath: report.memoryControl.socketPath, plan: report.memoryControl.plan};
        if (Date.now() > deadline) throw Error('The resume controller did not become ready in time');
        await new Promise(resolve => setTimeout(resolve, 500));
      }
    });
    console.log('R/2 Retaining verified access');
    await require('./hold-session.cjs').hold({directory: __dirname, session: a.session,
      execution: {resumed: true, verified: true},
      health: async () => {
        if (childExited) throw Error('The resume controller exited: ' + JSON.stringify(childExited));
        const status = await require('../shared/rpc.cjs').request({command: 'status'});
        check(status.ready, 'Console connection is no longer available; restart required');
      }});
    await stopController();
    const result = {resumed: true, started: record.resumed, completed: new Date().toISOString()};
    record.verified = true; record.result = result;
    await save(path.join(__dirname, 'session.json'), {session: a.session, phase: 'closed', result});
  } catch (error) {
    record.error = error.stack;
    controllerChild?.kill('SIGKILL'); controllerChild = null;
    await save(path.join(__dirname, 'session.json'), {session: a.session, phase: 'failed', error: error.message});
    throw error;
  } finally {
    record.finished = new Date().toISOString(); await save(file, record);
  }
}

async function main() {
  const file = path.join(__dirname, 'pipeline.json');
  const record = {session: a.session, started: new Date().toISOString(), stages: []};
  await fs.writeFile(file, JSON.stringify(record) + '\n', {flag: 'wx', mode: 0o600});
  async function stage(name, action) {
    console.log(name);
    const row = {name, started: new Date().toISOString(), status: 'running'};
    record.stages.push(row); await save(file, record);
    try {
      row.result = await action(); row.status = 'complete';
      return row.result;
    } catch (error) {row.status = 'failed'; row.error = error.stack; throw error;}
    finally {row.finished = new Date().toISOString(); await save(file, record);}
  }
  const script = (folder, name, args = [], timeout) =>
    stage(folder + '/' + name, () => run(path.join(__dirname, folder), name, args, timeout));
  let acquisition;
  try {
    console.log('1/4 Checking the console');
    await script('app', 'map');
    await script('app', 'inspect-mounts');
    await stage('Remove recorded scratch from prior launches', () => require('./cleanup-scratch.cjs').main());
    const app = await script('app', 'qualify');
    check(app.verified && app.cleanedUp, 'Application worker qualification failed');
    console.log('2/4 Acquiring FS memory');
    await stage('FS read, write and restoration', async () => {
      acquisition = await require('./acquire.cjs').start();
      return {report: acquisition.report, proof: acquisition.proof};
    });
    console.log('3/4 Starting the native helper');
    const captured = await read(acquisition.report);
    // Let the freshly acquired state settle before the metadata walk
    // (ported from upstream ns2jb: improves find-metadata reliability).
    await new Promise(resolve => setTimeout(resolve, 2000));
    if (!captured.retainedMemory?.captures?.some(c => c.length === 0x4d8000))
      await stage('retained/find-metadata', async () => {
        // The metadata walk can exhaust its hypothesis before the pool settles;
        // the controller stays alive across failures, so re-walk from scratch:
        // a fresh invocation resets its coverage and link history and can see
        // links that only appear as allocator state changes. Bounded retries;
        // a persistent failure still fails the stage.
        let lastError;
        for (let attempt = 0; attempt < 3; attempt++) {
          if (attempt) {
            await new Promise(resolve => setTimeout(resolve, 15000));
            console.log(`find-metadata retry ${attempt + 1}/3`);
          }
          try {
            return await run(path.join(__dirname, 'retained'), 'find-metadata', [acquisition.supervisorReport]);
          } catch (error) { lastError = error; }
        }
        throw lastError;
      });
    await script('ro', 'install-retained');
    await stage('FS layout', () => require('./ro/layout.cjs').main());
    await stage('Owned FS root', () => require('./ro/objects.cjs').main('root'));
    await stage('Owned FS notifier', () => require('./ro/objects.cjs').main('notifier'));
    const layout = await read(local(a.session, '-layout.json'));
    await script('ro', 'test-sm', [String(layout.sdk + 0x12a0)]);
    await script('ro', 'copy-loader-root', [String(layout.target.entry)]);
    await script('ro', 'prepare-workers');
    const donor = await stage('RO payload and current console policy', async () => {
      const memory = await connect(), sm = await read(local(a.session, '-sm-proof.json'));
      const monitor = await memory.request({command: 'root-native-sm-service', handle: sm.export.handle, name: 'pm:dmnt'});
      check(!monitor.result && !monitor.transport, 'PM monitor did not open');
      const loader = await read(local(a.session, '-loader-root-copy.json'));
      const code = await memory.request({command: 'root-native-code-open', handle: loader.copy.handle, title: '0x0400000000000037'});
      check(!code.result, 'Native RO CodeFS did not open');
      for (const name of ['main.npdm', 'main'])
        await memory.request({command: 'root-native-file-capture', handle: code.handle, name});
      const result = await memory.request({command: 'root-native-donor-prepare'});
      check(result.ready && result.files.every(item => item.verified), 'The payload files did not verify');
      return result;
    });
    await script('ro', 'bind-sessions');
    await script('ro', 'prepare-event');
    const gate = await script('ro', 'test-gate');
    check(gate.verified && gate.restored, 'The native request gate did not qualify');
    const launch = await script('ro', 'launch', [], 300000);
    check(launch.imageAccepted && launch.restored && launch.pid, 'PM did not accept the payload');
    const activation = await stage('Start RO payload', () => runtime.activate(launch.file));
    const proof = await stage('RO instruction challenges', () => runtime.probe(activation.pid));
    const handoff = await stage('Restore Loader session', () => runtime.handoff());
    const payload = donor.files.find(item => item.name === 'main');
    check(payload.sha256 === hash(await fs.readFile(path.join(__dirname, 'ro/payload/main'))), 'Payload changed during launch');
    await save(runtime.executionFile, {verified: true, session: a.session, report: acquisition.report,
      pid: proof.pid, programId: '0400000000000037', payloadSha256: payload.sha256,
      proof: proof.file, launch: launch.file, identity: activation.file, handoff: handoff.file});
    console.log(process.env.NS2_KEEP_SESSION === '1' ?
      '4/4 Verifying FS execution before retaining access' : '4/4 Running the FS demo and cleaning up');
    await script('process', 'bind-notifier');
    const mapping = await script('process', 'qualify');
    check(mapping.verified && mapping.cleanup?.finished, 'Native process mapping did not qualify and clean up');
    const execution = await stage('FS instruction challenges', () => require('./process/fs-execute.cjs').main());
    check(execution.verified && execution.restored, 'FS execution or restoration did not verify');
    if (process.env.NS2_KEEP_SESSION === '1') {
      await require('./hold-session.cjs').hold({directory: __dirname, session: a.session, execution,
        health: async () => {
          const status = await require('../shared/rpc.cjs').request({command: 'status'});
          check(status.ready, 'Console connection is no longer available; restart required');
        }});
    }
    const cleanup = await stage('Release FS resources', async () => {
      const memory = await connect();
      const donor = await memory.request({command: 'root-native-donor-cleanup'});
      check(donor.cleanedUp, 'Donor files did not clean up');
      return {...await acquisition.retire(), donor};
    });
    const result = {...execution, cleanup, started: record.started, completed: new Date().toISOString()};
    await save(path.join(__dirname, 'fs-execution-current.json'), result);
    record.verified = true; record.result = result;
    if (process.env.NS2_KEEP_SESSION === '1')
      await save(path.join(__dirname, 'session.json'), {session: a.session, phase: 'closed', result});
  } catch (error) {
    record.error = error.stack;
    if (process.env.NS2_KEEP_SESSION === '1')
      await save(path.join(__dirname, 'session.json'), {session: a.session, phase: 'failed', error: error.message});
    if (acquisition) {
      try {
        const latest = await read(acquisition.report);
        // Before promotion, the acquisition still owns its original restoration
        // path. Later failures may have native state that needs a console reboot.
        if (!latest.nativeRo && !latest.retainedMemory?.promoted)
          record.failureCleanup = await acquisition.retire();
        else await acquisition.abandon();
      } catch (cleanupError) {
        record.cleanupError = cleanupError.stack;
        await acquisition.abandon();
      }
    }
    throw error;
  } finally {record.finished = new Date().toISOString(); await save(file, record);}
}

module.exports = {main, resumeMain};
if (require.main === module) (process.env.NS2_RESUME === '1' ? resumeMain() : main())
  .catch(error => {console.error(error.stack); process.exitCode = 1;});
