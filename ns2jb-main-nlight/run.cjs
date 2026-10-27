#!/usr/bin/env node
const fs = require('node:fs/promises');
const {createWriteStream} = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const net = require('node:net');
const crypto = require('node:crypto');
const {spawn} = require('node:child_process');
const readline = require('node:readline');
const {listen} = require('./engine/lib/connection.cjs');
const {NativeClient} = require('./engine/lib/native.cjs');
const {qualify} = require('./engine/lib/qualify.cjs');
const {serve} = require('./engine/lib/bridge.cjs');

const port = 39380;
const save = (file, value) => fs.writeFile(file, JSON.stringify(value, null, 2) + '\n', {mode: 0o600});

function addresses(interfaces = os.networkInterfaces()) {
  return [...new Set(Object.values(interfaces).flat().filter(a =>
    a.family === 'IPv4' && !a.internal && a.netmask !== '255.255.255.255' &&
    !a.address.startsWith('169.254.')).map(a => a.address))];
}

async function chooseHost(args) {
  if (args.length > 1 || args.length === 1 && !net.isIPv4(args[0]))
    throw Error('Usage: node run.cjs [computer-IP]');
  if (args.length) return args[0];
  const choices = addresses();
  if (choices.length === 1) return choices[0];
  if (!choices.length) throw Error('Connect this computer to the console’s local network.');
  if (!process.stdin.isTTY)
    throw Error('Choose the address on the console’s network: node run.cjs IP\nAvailable: ' + choices.join(', '));
  choices.forEach((address, i) => console.log(`  ${i + 1}. ${address}`));
  const input = require('node:readline/promises').createInterface({input: process.stdin, output: process.stdout});
  try {
    const choice = await input.question('Which computer address can the Switch 2 reach? ');
    if (!/^[1-9][0-9]*$/.test(choice) || !choices[Number(choice) - 1]) throw Error('Choose one of the listed addresses.');
    return choices[Number(choice) - 1];
  } finally {input.close();}
}

function connectCommand(host, token) {
  return `V=START(${[port, ...host.split('.'), ...token].join(',')})`;
}

function hostFromConnect(command) {
  const parts = command.trim().replace(/^V=START\(/, '').replace(/\)$/, '').split(',').map(Number);
  if (parts.length !== 9 || parts.some(value => !Number.isInteger(value) || value < 0))
    throw Error('connect.txt does not contain a valid V=START command');
  const [port, ...rest] = parts;
  if (port < 1024 || port > 65535) throw Error('connect.txt dial port is out of range');
  if (rest.slice(0, 4).some(value => value > 255)) throw Error('connect.txt host byte is out of range');
  return {port, host: rest.slice(0, 4).join('.')};
}

async function sourceDigest() {
  const names = ['run.cjs', 'bootstrap.bas', 'pairing.cjs', 'session.cjs'];
  async function walk(folder) {
    for (const entry of await fs.readdir(path.join(__dirname, folder), {withFileTypes: true})) {
      const name = folder + '/' + entry.name;
      if (entry.isDirectory()) await walk(name);
      else if (entry.isFile()) names.push(name);
      else throw Error('Unexpected runtime file: ' + name);
    }
  }
  await walk('engine');
  const entries = [];
  for (const name of names.sort()) entries.push([name,
    crypto.createHash('sha256').update(await fs.readFile(path.join(__dirname, name))).digest('hex')]);
  return crypto.createHash('sha256').update(JSON.stringify(entries)).digest('hex');
}

async function runEngine(directory, keepSession = false, extraEnv = {}, logName = 'run.log') {
  const log = await fs.open(path.join(directory, logName), 'a', 0o600);
  const output = createWriteStream(null, {fd: log.fd, autoClose: false});
  try {
    const child = spawn(process.execPath, [path.join(directory, 'switch2/pipeline.cjs')],
      {cwd: directory, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
        env: {...process.env, NS2_RESUME: '0', NS2_KEEP_SESSION: keepSession ? '1' : '0', ...extraEnv}});

    child.stdout.pipe(output, {end: false});

    child.stderr.pipe(output, {end: false});
    child.stderr.pipe(process.stderr, {end: false});   // MR 8 (kurumuz!8): live error visibility

    const lines = readline.createInterface({input: child.stdout});
    lines.on('line', line => {
      if (/^[1-4]\/4 |^SESSION /.test(line)) console.log(line);
    });

    const code = await new Promise((resolve, reject) => {
      output.once('error', error => {child.kill('SIGTERM'); reject(error);});
      child.once('error', reject); child.once('close', resolve);
    });
    if (code !== 0) throw Error('The run stopped. Keep the runs folder and restart the console before trying again.');
  } finally {
    if (!output.destroyed)
      await new Promise((resolve, reject) => {output.once('error', reject); output.end(resolve);});
    await log.close();
  }
}

async function resumeMain(args = []) {
  let directory = args[0];
  if (!directory) {
    const latest = JSON.parse(await fs.readFile(path.join(__dirname, 'latest-session.json'), 'utf8'));
    directory = latest.directory;
    if (!directory) throw Error('latest-session.json has no directory; pass the run folder');
  }
  directory = path.resolve(__dirname, directory);
  const connection = JSON.parse(await fs.readFile(path.join(directory, 'connection.json'), 'utf8'));
  if (connection.addresses.target !== 'switch2') throw Error('The run folder is not a Switch 2 session');
  const {host, port: connectPort} = hostFromConnect(await fs.readFile(path.join(directory, 'connect.txt'), 'utf8'));
  const token = await require('./pairing.cjs').savedPairing(path.join(__dirname, 'pairing.json'));
  const result = {platform: 2, resumed: new Date().toISOString(), verified: false};
  let native, bridge, failure;
  try {
    const connected = await listen({host, port: connectPort, token, timeout: 30 * 60 * 1000, onWaiting() {
      console.log(`Waiting for Switch 2 at ${host}:${connectPort}.`);
      console.log('The console should reconnect on its own; V=GO() also re-dials.');
      console.log('Run folder: ' + directory);
    }});
    const recorded = connection.addresses;
    for (const name of ['scratch', 'scratchBytes', 'main', 'sdk', 'got', 'memmove', 'backing', 'controller'])
      if (Number(connected.addresses[name]) !== Number(recorded[name])) {
        connected.connection.close();
        throw Error('Console addresses changed; the console was rebooted. Use a fresh session.sh start.');
      }
    native = new NativeClient(connected.connection, connected.addresses);
    console.log('Reconnected. Verifying the app is still live...');
    result.bootstrap = await qualify(native);
    bridge = await serve(native);
    bridge.keepAwake(result.bootstrap.activity);
    await save(path.join(directory, 'connection.json'), {port: bridge.port, token: bridge.token,
      addresses: {...connected.addresses, session: path.basename(directory), target: 'switch2'}});
    await runEngine(directory, true, {NS2_RESUME: '1'}, 'run-resume.log');
    result.verified = true;
  } catch (error) {result.error = error.message; failure = error;}
  finally {
    for (const [name, close] of [['bridge', () => bridge?.close()], ['connection', () => native?.stop()]]) {
      try {await close();}
      catch (error) {(result.cleanupErrors ||= []).push({name, error: error.message}); failure ||= error;}
    }
    result.completed = new Date().toISOString();
    await save(path.join(directory, 'resume-result.json'), result);
  }
  if (failure) throw Error(failure.message + '\nDetails: ' + directory);
  console.log('Session resumed. The console-side state was retained throughout.');
  return result;
}


const DUMP_MARKER = '.ns2jb-firmware-dump.json';
async function prepareDumpDirectory(root = path.join(__dirname, 'dumps')) {
  const parent = path.dirname(root);
  const previous = await fs.lstat(root).catch(error => {
    if (error.code === 'ENOENT') return null;
    throw error;
  });
  if (previous) {
    if (!previous.isDirectory() || previous.isSymbolicLink() ||
        previous.dev !== (await fs.stat(parent)).dev)
      throw Error('Refusing to clean a symlink, mount, or non-directory at ' + root);
    const marker = await fs.readFile(path.join(root, DUMP_MARKER), 'utf8').then(JSON.parse).catch(error => {
      if (error.code === 'ENOENT') return null;
      throw error;
    });
    if (!marker || marker.kind !== 'ns2jb-system-code-dump' || marker.version !== 1) {
      if ((await fs.readdir(root)).length)
        throw Error('Refusing to clean an unrecognized nonempty dumps directory: ' + root);
    }
    await fs.rm(root, {recursive: true});
  }
  await fs.mkdir(root, {mode: 0o700});
  await fs.writeFile(path.join(root, DUMP_MARKER), JSON.stringify({
    kind: 'ns2jb-system-code-dump', version: 1, started: new Date().toISOString()
  }, null, 2) + '\n', {flag: 'wx', mode: 0o600});
  return {root, cleaned: !!previous};
}

function waitForRpcStop(connection, signals = process) {
  return new Promise(resolve => {
    const socket = connection.socket;
    let settled = false;
    const finish = reason => {
      if (settled) return;
      settled = true;
      signals.removeListener('SIGINT', interrupt);
      signals.removeListener('SIGTERM', terminate);
      socket.removeListener('close', disconnected);
      resolve(reason);
    };
    const interrupt = () => finish('SIGINT');
    const terminate = () => finish('SIGTERM');
    const disconnected = () => finish('disconnected');
    signals.once('SIGINT', interrupt);
    signals.once('SIGTERM', terminate);
    socket.once('close', disconnected);
    if (connection.error || socket.destroyed) finish('disconnected');
  });
}

async function main(args = process.argv.slice(2)) {
  const keepSession = args.includes('--session');
  const resume = args.includes('--resume');
  args = args.filter(arg => arg !== '--session' && arg !== '--resume');
  if (args.length === 1 && args[0] === '--help') {
    console.log('Usage: node run.cjs [--session] [computer-IP]\n' +
      '       node run.cjs --resume [run-folder]\n' +
      '--session retains verified access until session.sh stop. --resume re-attaches to a\n' +
      'retained session without redoing acquisition. See USAGE.txt.');
    return;
  }
  if (resume) return resumeMain(args);
  const host = await chooseHost(args);
  const token = keepSession ? await require('./pairing.cjs').savedPairing(path.join(__dirname, 'pairing.json')) : pairingCode();
  const command = connectCommand(host, token);
  if (keepSession) {
    const helper = `COMMON DEF GO()\n RETURN ${command.slice(2)}\nEND\n`;
    await fs.writeFile(path.join(__dirname, 'GO.bas'), helper, {mode: 0o600});
  }
  const workspace = path.join(__dirname, 'runs');
  await fs.mkdir(workspace, {recursive: true, mode: 0o700});
  const directory = await fs.mkdtemp(path.join(workspace, 'switch2-'));
  if (keepSession) await save(path.join(__dirname, 'latest-session.json'), {directory});
  await fs.writeFile(path.join(directory, 'connect.txt'), command + '\n', {mode: 0o600});
  const result = {platform: 2, sourceSha256: await sourceDigest(), started: new Date().toISOString(), verified: false};
  let native, bridge, failure;
  try {
    const connected = await listen({host, port, token, timeout: 30 * 60 * 1000, onWaiting() {
      console.log(`Waiting for Switch 2 at ${host}:${port}.`);
      console.log('In a freshly opened SmileBASIC, load the saved bootstrap and enter:');
      console.log('  RUN');
      console.log('This session bootstrap includes REMOVE. Do not enter REMOVE separately.');
      console.log('After the expected Out of memory message, enter:');
      console.log('  ' + command);
      if (keepSession) console.log('After saving the GO.bas helper once, use V=GO() instead.');
      console.log('Run folder: ' + directory);
    }});
    native = new NativeClient(connected.connection, connected.addresses);
    console.log('Connected. Checking the application...');
    result.bootstrap = await qualify(native);
    bridge = await serve(native);
    bridge.keepAwake(result.bootstrap.activity);
    await save(path.join(directory, 'connection.json'), {port: bridge.port, token: bridge.token,
      addresses: {...connected.addresses, session: path.basename(directory), target: 'switch2'}});
    for (const name of ['shared', 'switch2'])
      await fs.cp(path.join(__dirname, 'engine', name), path.join(directory, name), {recursive: true});
    await runEngine(directory, keepSession);
    result.fs = JSON.parse(await fs.readFile(path.join(directory, 'switch2/fs-execution-current.json')));
    if (!result.fs.verified || !result.fs.restored || !result.fs.cleanup?.cleanedUp)
      throw Error('FS execution, restoration, or cleanup did not finish.');
    result.verified = true;
    if (rpcMode) {
      result.rpc = {mode: 'held', state: 'listening', opened: new Date().toISOString()};
      await save(path.join(directory, 'result.json'), result);
      console.log('4/4 verified. SmileBASIC RPC is held while this process and the app stay open.');
      console.log('Run folder: ' + directory);
      console.log('Check it locally: node rpc.cjs ' + directory + ' status');
      console.log('Stop with Ctrl-C; do not close SmileBASIC until finished.');
      const reason = await waitForRpcStop(native.connection);
      result.rpc = {...result.rpc, state: 'closed', reason, closed: new Date().toISOString()};
      if (reason === 'disconnected') throw Error('Held RPC disconnected; do not replay an uncertain native request.');
    }
  } catch (error) {result.error = error.message; failure = error;}
  finally {
    for (const [name, close] of [['bridge', () => bridge?.close()], ['connection', () => native?.stop()]]) {
      try {await close();}
      catch (error) {(result.cleanupErrors ||= []).push({name, error: error.message}); failure ||= error;}
    }
    result.completed = new Date().toISOString();
    await save(path.join(directory, 'result.json'), result);
  }
  if (failure) throw Error(failure.message + '\nDetails: ' + directory);
  console.log('FS execution verified. Original instructions restored and scratch cleaned up.');
  console.log('Restart the console when finished.');
  return result;
}

module.exports = {main, addresses, chooseHost, connectCommand, sourceDigest, prepareDumpDirectory, waitForRpcStop};
if (require.main === module) main().catch(error => {console.error(error.message); process.exitCode = 1;});
