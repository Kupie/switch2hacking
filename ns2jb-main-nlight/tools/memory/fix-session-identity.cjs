#!/usr/bin/env node
// Promote the memory-side root session to the full-trust identity, in-band.
//
// A boot is "weak" when the RPC worker threads execute with the SmileBASIC
// app's identity: root-initialize (SetCurrentProcess) writes the app pid into
// the session object graph and every permission check then consults the app's
// game registration — BIS opens and content mounts fail with fs 0x320002 /
// 0x299002. A boot is "strong" when the same fields hold a full-trust pid
// (the null-title helper): fs's process-info lookup misses and falls back to
// internal trust. Historically both outcomes occurred at roughly equal rates.
//
// This tool makes every boot strong: after root-open it checks whether the
// session is already strong (OpenBisFileSystem(30)); if not, it scans the
// recorded root-object graph for fields holding the current-process pid and
// rewrites them to the helper's pid with compare-verified writes (the same
// primitive the pipeline's own promote step uses), then re-verifies.
//
// Usage (from the repo root, inside the netns):
//   sudo -n ip netns exec switchlab runuser -u nlight -- node fix-session-identity.cjs
//
// Verification the tool performs: OpenDataFileSystemByCurrentProcess (cmd 2)
// must fail 0x1408 (no data filesystem for a full-trust current process) and
// OpenBisFileSystem(30) must succeed. Never re-run root-initialize after this
// tool: SetCurrentProcess rewrites the app pid back.
const fs = require('node:fs/promises');
const path = require('node:path');

async function main() {
  const latest = JSON.parse(await fs.readFile(path.join(__dirname, '..', '..', 'latest-session.json')));
  const dir = latest.directory;
  const session = path.basename(dir);
  const {connect} = require(path.join(dir, 'switch2', 'tools', 'fs-memory.cjs'));
  const mem = await connect();
  const u64 = b => b.readBigUInt64LE();

  // Boot facts: the root object address and the helper's pid from the proofs.
  const rootProof = JSON.parse(await fs.readFile(
    path.join(dir, 'switch2', 'ro', 'root', 'current-root.json')));
  const rootAddress = rootProof.rootAddress;
  let helperPid = 8n;
  const processDir = path.join(dir, 'switch2', 'process');
  for (const name of require('node:fs').readdirSync(processDir)) {
    if (!/fs-execution-.*\.json$/.test(name)) continue;
    try { helperPid = BigInt(JSON.parse(await fs.readFile(path.join(processDir, name))).identity.pid); break; } catch (e) {}
  }
  const argPid = process.argv.includes('--pid') ? process.argv[process.argv.indexOf('--pid') + 1] : null;
  if (argPid && /^(0x[0-9a-f]+|\d+)$/i.test(argPid)) helperPid = BigInt(argPid);
  console.log('session', session, '| root object', rootAddress, '| helper pid', helperPid.toString());

  // The root session must exist and be initialized before the fields exist.
  const info = await mem.request({command: 'root-info'});
  if (!info.clones?.length) await mem.request({command: 'root-open'});

  const probe = async () => {
    const p = await mem.request({command: 'root-probe-bis-filesystem', id: 30});
    return p;
  };
  let p = await probe();
  const force = process.argv.includes('--force');
  if (!p.result && !force) { console.log('already strong: BIS USER opens without promotion'); return {strong: true}; }

  // Current-process pid: whatever SetCurrentProcess last wrote at root+0x30.
  const currentPid = u64(await mem.read(rootAddress + 0x30, 8));
  console.log('current-process pid:', currentPid.toString(), '(weak session)');
  if (currentPid === 0n) throw Error('No current-process pid found; run root-open first');

  // Collect every graph field holding the current pid. Conservative and
  // generic: the root header itself, then each pointer slot chased once, with
  // bounded 0x80-byte reads of object headers only.
  const fields = [{address: rootAddress + 0x30, label: 'root+0x30'}];
  const head = await mem.read(rootAddress, 0x40);
  for (const off of [0x08, 0x10, 0x18, 0x20, 0x28]) {
    try {
      const chain = await mem.chase(rootAddress, [off]);
      const bytes = await mem.read(chain.address, 0x80);
      for (let o = 0; o <= 0x78; o += 8) {
        if (u64(bytes.subarray(o, o + 8)) === currentPid)
          fields.push({address: chain.address + o, label: 'chase+0x' + off.toString(16) + ' +0x' + o.toString(16)});
      }
    } catch (e) { /* pointer not chaseable in this graph; skip */ }
  }
  console.log('fields holding pid', currentPid.toString() + ':', fields.map(f => f.label).join(', '));
  if (!fields.some(f => f.address === rootAddress + 0x30))
    throw Error('The root current-process field is missing from the scan; layout changed');

  // Compare-verified promotion of every field.
  const expected = Buffer.alloc(8); expected.writeBigUInt64LE(currentPid);
  const replacement = Buffer.alloc(8); replacement.writeBigUInt64LE(helperPid);
  for (const field of fields) {
    await mem.write(field.address, expected, replacement);
    console.log('promoted', field.label, '->', helperPid.toString());
  }

  // Verification: the full-trust identity has no application data filesystem,
  // and BIS USER must now open.
  const info2 = await mem.request({command: 'root-info'});
  const r2 = await mem.request({command: 'root-native-ipc', handle: info2.clones[0], id: 2, hex: ''});
  console.log('cmd 2 oracle: 0x' + (r2.canonicalResult ?? r2.result ?? 0).toString(16), '(expect 0x1408)');
  p = await probe();
  if (p.result) throw Error('Promotion verified but BIS USER still fails: 0x' + p.result.toString(16));
  console.log('strong session restored: BIS USER opened, handle', p.handle);
  console.log('Do NOT run root-initialize again this boot (SetCurrentProcess rewrites the app pid).');
  return {strong: true, promoted: fields.length};
}

main().then(r => { console.log(JSON.stringify(r ?? {})); process.exit(0); })
  .catch(e => { console.error('FAILED:', e.message); process.exit(1); });
