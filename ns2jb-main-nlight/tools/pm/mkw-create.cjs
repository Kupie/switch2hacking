#!/usr/bin/env node
// MKW create-only launch: pm:shell cmd 0 (LaunchTitle) WITHOUT StartProcess.
//
// THE ROUTE (2026-10-25 derivation, see FINDINGS "route ledger final"):
// LaunchTitle is CREATE-ONLY — deploy-monitor's own flow proves it (the
// launch dance creates the image; pm:dmnt cmd 1 = StartProcess is a separate
// call). pm registers the program with fsp-pr at CREATE (the per-boot
// content registry — the exact wall cmd 2 hits for never-launched titles).
// lUQn26 PROVED the whole class live: LaunchTitle(MKW 0x0400c3f00006e000,
// storage 04) accepted, the loader issued OpenCodeFileSystem(MKW), the boot
// SURVIVED with SmileBASIC alive (no app switch — Start never ran).
//
// So: create MKW's process (suspended, never started) -> MKW lands in fs's
// per-boot registry -> promote the session pid to MKW's pid ->
// fsp-srv cmd 2 -> MKW's data RomFS -> dump-romfs. No app switch; the RPC
// carrier (SmileBASIC) stays alive.
//
// Phases (netns-wrapped, one per invocation):
//   node mkw-create.cjs --create      pm:shell LaunchTitle(MKW, flags 16,
//                                    storage 4) via the native worker; bank
//                                    the returned pid; NEVER start it.
//   node mkw-create.cjs --status      pm:dmnt id-7 sweep (find MKW's pid +
//                                    program map; read-only)
//   node mkw-create.cjs --verify      promote session pid -> MKW pid ->
//                                    cmd 2 oracle -> RomFS listing proof
//   node mkw-create.cjs --terminate   pm:shell cmd 1 on the created pid
//                                    (revert if the registry test fails)
//
// Safety:
// - NO StartProcess ever (pm:dmnt cmd 1 on the MKW pid is forbidden here).
// - The create rides the SAME worker machinery as every monitor launch
//   (worker-prepare pm-launch -> release -> poll -> join); no gate parking,
//   no exchange — the loader loads MKW's REAL image through its own normal
//   fs sessions.
// - Every phase banks its evidence to runs/<s>/mkw-create.json first.
'use strict';
const fs = require('node:fs/promises');
const fsSync = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');
const crypto = require('node:crypto');

const MKW = '0x0400c3f00006e000';
const check = (ok, message) => { if (!ok) throw Error(message); };
const u64le = hex => Buffer.from(hex, 'hex').readBigUInt64LE(0);
const arg = name => {
  const i = process.argv.indexOf('--' + name);
  return i >= 0 ? process.argv[i + 1] : undefined;
};

async function main() {
  const latest = JSON.parse(await fs.readFile(path.join(__dirname, '..', '..', 'latest-session.json')));
  const dir = latest.directory;
  const {connect} = require(path.join(dir, 'switch2', 'tools', 'fs-memory.cjs'));
  const memory = await connect();
  const outFile = path.join(dir, 'mkw-create.json');
  let state = fsSync.existsSync(outFile) ? JSON.parse(await fs.readFile(outFile)) : {};
  const save = async () => fs.writeFile(outFile, JSON.stringify(state, null, 2) + '\n', {mode: 0o600});
  const info = await memory.request({command: 'root-info'});
  check(info.clones?.length, 'No dedicated root is retained (root-open first)');

  if (process.argv.includes('--status')) {
    // Read-only pm:dmnt id-7 sweep: pid -> {tid, programId}.
    const svc = await memory.request({command: 'root-native-info'});
    const pmDmnt = (svc.services || []).find(x => x.name === 'pm:dmnt');
    check(pmDmnt, 'pm:dmnt is not held');
    const rows = [];
    for (let pid = 1; pid <= 300; pid++) {
      const hex = Buffer.alloc(8); hex.writeBigUInt64LE(BigInt(pid));
      let reply;
      try {reply = await memory.request({command: 'root-native-ipc',
        handle: pmDmnt.handle, id: 7, hex: hex.toString('hex')});}
      catch (e) {break;}
      if (!reply || reply.result) continue;
      const data = Buffer.from(reply.hex || reply.data || '', 'hex');
      if (data.length < 16) continue;
      rows.push({pid, programId: data.readBigUInt64LE(8).toString(16).padStart(16, '0')});
    }
    const mkw = rows.filter(r => r.programId.startsWith('0400c3f00006e'));
    state.status = {at: new Date().toISOString(), processes: rows.length, mkw: mkw.map(r => r.pid)};
    await save();
    console.log(JSON.stringify({processes: rows.length, mkwPids: mkw.map(r => r.pid),
      all: rows.filter(r => !r.programId.startsWith('040000'))}, null, 1));
    return;
  }

  if (process.argv.includes('--create')) {
    const svc = await memory.request({command: 'root-native-info'});
    check(!svc.worker || svc.worker.joined, 'A native worker is still active');
    const shell = (svc.services || []).find(x => x.name === 'pm:shell');
    check(shell, 'pm:shell is not held');
    // Baseline: the session RPC must be healthy before we create anything.
    const base = await memory.request({command: 'root-native-ipc', handle: info.clones[0], id: 2, hex: ''});
    console.log('baseline cmd 2 oracle: 0x' + (base.canonicalResult ?? base.result ?? 0).toString(16));
    // The same worker shape as launch.cjs (no gate parking, no exchange):
    // LaunchTitle(flags=16, title=MKW, storage=4) on the held pm:shell.
    await memory.request({command: 'root-native-worker-prepare', kind: 'pm-launch',
      handle: shell.handle, title: MKW, flags: 0x10, storage: 4});
    await memory.request({command: 'root-native-worker-release'});
    const deadline = Date.now() + 240000;
    for (;;) {
      const w = await memory.request({command: 'root-native-worker-state'});
      if (w.finished) break;
      check(Date.now() < deadline, 'LaunchTitle did not complete in 240 s (worker preserved)');
      await new Promise(r => setTimeout(r, 50));
    }
    const joined = await memory.request({command: 'root-native-worker-join'});
    const reply = (joined.responses || [])[0] || {};
    const record = {at: new Date().toISOString(), title: MKW, flags: 0x10, storage: 4,
      result: reply.result, raw: (reply.raw || '').slice(0, 64)};
    if (!reply.result && reply.data && reply.data.length >= 16) {
      record.pid = Buffer.from(reply.data, 'hex').readBigUInt64LE(0).toString();
      record.programHex = reply.data.slice(16, 32);
    }
    state.create = record; await save();
    console.log(JSON.stringify(record, null, 1));
    check(!reply.result, 'LaunchTitle failed: 0x' + (reply.result ?? 0).toString(16));
    check(record.pid, 'LaunchTitle returned no pid in the reply');
    console.log('MKW PROCESS CREATED (suspended, NOT started). pid ' + record.pid);
    console.log('Never run pm:dmnt cmd 1 on this pid. Next: node mkw-create.cjs --verify');
    return;
  }

  if (process.argv.includes('--verify')) {
    const pid = Number(arg('pid') ?? state.create?.pid);
    check(Number.isInteger(pid) && pid > 0, 'no pid (run --create first or pass --pid N)');
    // 1. Confirm the created pid maps to MKW (read-only).
    const svc = await memory.request({command: 'root-native-info'});
    const pmDmnt = (svc.services || []).find(x => x.name === 'pm:dmnt');
    check(pmDmnt, 'pm:dmnt is not held');
    const hex = Buffer.alloc(8); hex.writeBigUInt64LE(BigInt(pid));
    const probe = await memory.request({command: 'root-native-ipc',
      handle: pmDmnt.handle, id: 7, hex: hex.toString('hex')});
    const data = Buffer.from(probe.hex || probe.data || '', 'hex');
    const programId = probe.result ? null : (data.length >= 16 ? data.readBigUInt64LE(8).toString(16).padStart(16, '0') : null);
    console.log('pm:dmnt id7(pid ' + pid + ') ->', programId ?? ('0x' + (probe.result ?? 0).toString(16)));
    check(programId === '0400c3f00006e000', 'the created pid is not MKW: ' + programId);
    // 2. Promote the session identity to the MKW pid (the proven in-band
    //    compare-verified write path; --force skips the strong-boot probe).
    console.log('promoting the session identity to pid ' + pid + ' ...');
    execFileSync('node', ['fix-session-identity.cjs', '--pid', String(pid), '--force'],
      {cwd: __dirname, stdio: 'inherit'});
    // 3. The oracle: cmd 2 as the MKW process.
    const info2 = await memory.request({command: 'root-info'});
    const r2 = await memory.request({command: 'root-native-ipc', handle: info2.clones[0], id: 2, hex: ''});
    const oracle = r2.canonicalResult ?? r2.result ?? 0;
    console.log('cmd 2 as MKW pid: 0x' + oracle.toString(16));
    state.verify = {at: new Date().toISOString(), pid, oracle: '0x' + oracle.toString(16)};
    if (oracle !== 0) {
      console.log('REGISTRY TEST FAILED (cmd 2). Revert: node mkw-create.cjs --terminate');
      await save(); return;
    }
    // 4. RomFS proof: list the opened root.
    const handle = (r2.moves || [])[0];
    check(handle, 'cmd 2 returned no filesystem handle');
    const listing = await memory.request({command: 'root-list-romfs', handle, path: '/'});
    state.verify.handle = handle;
    state.verify.entries = (listing.entries || []).slice(0, 32);
    await save();
    console.log('*** MKW DATA RomFS OPENED. Root entries:');
    for (const e of (listing.entries || []).slice(0, 32))
      console.log('   ', e.type === 0 ? 'dir ' : 'file', e.name, e.type === 1 ? '(' + e.size + ' bytes)' : '');
    console.log('Dump command:');
    console.log('  node dump-romfs.cjs --handle ' + handle +
      ' --out ' + path.join(dir, 'mkw-romfs-dump'));
    return;
  }

  if (process.argv.includes('--terminate')) {
    const pid = Number(arg('pid') ?? state.create?.pid);
    check(Number.isInteger(pid) && pid > 0, 'no pid (run --create first or pass --pid N)');
    // Revert the session identity first (full-trust helper), then terminate.
    execFileSync('node', ['fix-session-identity.cjs', '--pid', '8', '--force'],
      {cwd: __dirname, stdio: 'inherit'});
    const svc = await memory.request({command: 'root-native-info'});
    const shell = (svc.services || []).find(x => x.name === 'pm:shell');
    check(shell, 'pm:shell is not held');
    const hex = Buffer.alloc(8); hex.writeBigUInt64LE(BigInt(pid));
    const t = await memory.request({command: 'root-native-ipc',
      handle: shell.handle, id: 1, hex: hex.toString('hex')});
    state.terminate = {at: new Date().toISOString(), pid, result: t.result,
      canonical: t.canonicalResult ?? t.result};
    await save();
    console.log('TerminateProcess(' + pid + ') -> 0x' + (t.canonicalResult ?? t.result ?? 0).toString(16),
      '(0x20f = already gone)');
    return;
  }

  throw Error('modes: --create | --status | --verify [--pid N] | --terminate [--pid N]');
}

main().catch(e => {console.error(e.stack || e); process.exitCode = 1;});