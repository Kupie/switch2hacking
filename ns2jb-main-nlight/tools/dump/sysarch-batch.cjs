#!/usr/bin/env node
// Batch system-data-archive (8xx) dumper — ONE session for all 57 archives.
// Content paths + attributes come from the sweep inventory (/tmp/sysarch-inventory.json
// or a --inventory file). Per archive: fs 206 type 1 (program class) -> type 6
// (data class) -> optional ns-promotion retry. Walk + dump + per-archive sha256
// manifest, resume-safe. No NCM re-resolution, one attach, no armed state.
//
//   sudo -n ip netns exec switchlab runuser -u nlight -- \
//     node tools/dump/sysarch-batch.cjs [--probe] [--only <tid>]
const path = require('node:path');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const crypto = require('node:crypto');
const latest = JSON.parse(fs.readFileSync(path.join(require('node:os').homedir(),
  'dev/ns2jb/latest-session.json')));
const SESSION = path.basename(latest.directory);
const engine = path.join(latest.directory, 'switch2');
const {Session, u32, u64, check} = require(path.join(engine, 'app', 'session.cjs'));
const domain = require(path.join(engine, 'app', 'domain.cjs'));
const filesystem = require(path.join(engine, 'app', 'filesystem.cjs'));
const {paths} = require(path.join(engine, 'memory', 'paths.cjs'));
const fsMemory = require(path.join(engine, 'tools', 'fs-memory.cjs'));
const check2 = (ok, m) => {if (!ok) throw Error(m);};
const success = (r, l) => {if (r.result) throw Error(l + ': 0x' + (Number(r.result) >>> 0).toString(16)); return r;};
const pad16 = v => v.toString(16).padStart(16, '0');
const OUTROOT = path.join(require('node:os').homedir(), 'dev/switch/dumps/fw23-archives');

(async () => {
  const argv = process.argv.slice(2);
  const probe = argv.includes('--probe');
  const only = argv.includes('--only') ? argv[argv.indexOf('--only') + 1] : null;
  const invFile = argv.includes('--inventory') ? argv[argv.indexOf('--inventory') + 1] : '/tmp/sysarch-inventory.json';
  const inventory = JSON.parse(await fsp.readFile(invFile));
  const targets = only ? inventory.filter(a => a.title === only.replace(/^0x/, '')) : inventory;
  check2(targets.length, 'no archives selected');

  const memory = await fsMemory.connect();
  const info = await memory.request({command: 'root-native-info'});
  const smHandle = (info.services || []).find(x => x.sm)?.sm;
  check2(smHandle, 'no sm handle');
  const proof = JSON.parse(await fsp.readFile(path.join(engine, 'ro', 'root', 'current-root.json')));
  const s = new Session('sysarch-batch-' + Date.now(), 0x2100000);
  s.record = async () => {};
  await s.initialize();
  s.bulkDownloads = true;
  const handles = [];
  const track = h => {handles.push(h); return h;};
  let a_promoted = false;
  let nsPid = null;
  // pm:dmnt id-7 sweep (dual-offset parse) on the dump session
  const sweepProgramIdsInline = async () => {
    let pmDmnt;
    try {pmDmnt = await s.openService('pm:dmnt');}
    catch (e) {
      const infoS = await memory.request({command: 'root-native-info'});
      const smS = (infoS.services || []).find(x => x.sm)?.sm;
      check2(smS, 'no sm handle for sweep');
      const pkt = Buffer.alloc(256);
      pkt.writeUInt32LE(0x11); pkt.writeUInt32LE(2, 4); pkt.write('pm:dmnt', 8);
      await s.write(s.base, pkt);
      const transport = await s.call('send', s.base, 4096, smS);
      check2(!transport, 'pm:dmnt open');
      const reply = await s.readOwned(s.base, 256);
      let at = 8, count = 0;
      if (reply.readUInt32LE(4) >>> 31) {
        const special = reply.readUInt32LE(at); at += 4;
        count = (special >>> 5) & 15;
        if (count) {pmDmnt = reply.readUInt32LE(at); s.handles.add(pmDmnt);}
      }
    }
    check2(pmDmnt, 'pm:dmnt handle missing');
    const rows = [];
    for (let pid = 140; pid <= 220; pid++) {
      const input = Buffer.alloc(16);
      input.writeBigUInt64LE(BigInt(pid), 0);
      input.writeBigUInt64LE(BigInt(pid), 8);
      const r = await s.ipc('sweep ' + pid, pmDmnt, 7, input).catch(() => null);
      if (!r || r.result) continue;
      const data = Buffer.from(r.data, 'hex');
      const programId = data.readBigUInt64LE(0) || data.readBigUInt64LE(8) || 0n;
      if (programId) rows.push({pid, programId: programId.toString(16).padStart(16, '0')});
    }
    check2(rows.length, 'sweep found no program ids');
    return rows;
  };
  const promoteTo = async pid => {
    const {execFile} = require('node:child_process');
    await new Promise(res => execFile('node',
      [path.join(__dirname, '..', 'memory', 'fix-session-identity.cjs'), '--pid', String(pid), '--force'],
      {cwd: path.join(__dirname, '..', '..')}, () => res()));
  };
  try {
    const root = track(domain.oneHandle(success(await domain.send(s, 'clone root', proof.rootHandle,
      domain.wire.control(2)), 'clone root')));
    const pathApi = paths(s, domain);
    console.log('attached | root:', root, '| archives:', targets.length, probe ? '(PROBE)' : '-> ' + OUTROOT);
    // unconditional promote to ns (root-pid class). Oracle-verified tonight
    // but ALONE insufficient for the type-6 archive gate — FINDINGS 2026-10-26:
    // game-dump's in-catch mid-run promote ALSO refused on this boot. The one
    // remaining untested lever = the fake-program-context route
    // (RegisterOwnedTemporaryProgramContext via update-romfs.cjs) armed first.
    {
      const rows = await sweepProgramIdsInline();
      const ns = rows.find(r => r.programId.endsWith('0000001f'));
      check2(ns, 'ns pid not found in the sweep');
      nsPid = ns.pid;
      await promoteTo(nsPid);
      console.log('promoted root session to ns (pid', nsPid + ')');
      a_promoted = true;
    }
    const results = [];
    const COOLDOWN_MS = Number(process.env.SYSARCH_COOLDOWN_MS ?? 6000);
    for (const [idx, arch] of targets.entries()) {
      if (idx > 0) await new Promise(r => setTimeout(r, COOLDOWN_MS));   // fs-worker cooldown between opens
      const label = arch.title + ' v' + arch.version;
      const contentPath = '@SystemContent://registered/' + arch.contentId + '.nca';
      const open = async type => {
        const pathBuffer = Buffer.alloc(0x301);
        pathBuffer.write(contentPath);
        const input = Buffer.alloc(8);
        input[0] = arch.attributes;
        input.writeUInt32LE(type, 4);
        const reply = await pathApi.raw(root, 206, pathBuffer, input);
        return reply;
      };
      let reply = await open(1);
      let via = 'type-1';
      if (reply.result) {
        reply = await open(6);
        via = 'type-6';
      }
      const canonical = reply.result ? (Number(reply.result) & 0x3fffff) : 0;   // serial<<22 masked off
      if (reply.result && canonical === 0x320002 && a_promoted) {
        // fsaccess gate: one in-catch re-promote + retry (game-dump's Oct-25
        // shape — insufficient alone on fresh carriers, but cheap and rules
        // out promote-order before we print the hint).
        console.log('==', label, '==  fsaccess gate 0x320002 — re-promote + retry');
        await promoteTo(nsPid);
        reply = await open(6);
        via = 'type-6 (retried)';
      }
      if (reply.result) {
        const gateHint = ((Number(reply.result) & 0x3fffff) === 0x320002)
          ? ' — FAH gate: arm the fake-program-context route first (update-romfs.cjs), then re-run'
          : '';
        console.log('==', label, '==  REFUSED: 0x' + (Number(reply.result) >>> 0).toString(16) + gateHint);
        results.push({title: arch.title, version: arch.version,
          error: (Number(reply.result) >>> 0).toString(16), gate: gateHint !== ''});
        continue;   // no manifest written -> the next pass re-attempts this archive
      }
      const storage = track(domain.oneHandle(reply));
      const size = Number(await domain.storageSize(s, storage));
      console.log('==', label, '== via', via, '| size:', (size / 1024).toFixed(0), 'KiB');
      if (probe) {await s.close(storage); continue;}
      // parse + walk + dump
      const head = await filesystem.readStorage(s, storage, 0, 0x50);
      check2(head.readBigUInt64LE(0) === 0x50n, 'bad romfs header ' + label);
      const h = Array.from({length: 10}, (_, i) => head.readBigUInt64LE(i * 8));
      const dataOffset = Number(h[9]);
      const dirBytes = await filesystem.readStorage(s, storage, Number(h[3]), Number(h[4]));
      const fileBytes = await filesystem.readStorage(s, storage, Number(h[7]), Number(h[8]));
      const NONE = 0xffffffff;
      const files = [];
      const walkDir = (offset, prefix) => {
        let file = dirBytes.readUInt32LE(offset + 12);
        while (file !== NONE) {
          const e = fileBytes.subarray(file, file + 32);
          const len = e.readUInt32LE(28);
          const name = fileBytes.subarray(file + 32, file + 32 + len).toString('utf8');
          files.push({path: prefix + name, offset: Number(e.readBigUInt64LE(8)), size: Number(e.readBigUInt64LE(16))});
          file = e.readUInt32LE(4);
        }
        let child = dirBytes.readUInt32LE(offset + 8);
        while (child !== NONE) {
          const e = dirBytes.subarray(child, child + 24);
          const len = e.readUInt32LE(20);
          const name = dirBytes.subarray(child + 24, child + 24 + len).toString('utf8');
          walkDir(child, prefix + name + '/');
          child = e.readUInt32LE(4);
        }
      };
      walkDir(0, '/');
      const outDir = path.join(OUTROOT, arch.title);
      const manifestFile = path.join(outDir, 'manifest.json');
      const manifest = fs.existsSync(manifestFile) ? JSON.parse(await fsp.readFile(manifestFile)) :
        {title: arch.title, version: arch.version, contentId: arch.contentId,
          attributes: arch.attributes, started: new Date().toISOString(), files: []};
      const done = new Map(manifest.files.map(f => [f.path, f]));
      console.log('  tree:', files.length, 'files | manifest:', manifest.files.length);
      // sort by offset; coalesced streaming like the game dump (small archives: just read each)
      let n = 0, bytes = 0;
      for (const f of files.sort((a, b) => a.offset - b.offset)) {
        if (done.has(f.path) && done.get(f.path).size === f.size) continue;
        const parts = [];
        for (let at = 0; at < f.size; at += 0x100000) {   // 1 MiB chunks (archive reads)
          const take = Math.min(0x100000, f.size - at);
          parts.push(await filesystem.readStorage(s, storage, dataOffset + f.offset + at, take));
        }
        const data = Buffer.concat(parts);
        check2(data.length === f.size, 'short read ' + f.path);
        const out = path.join(outDir, 'archive', f.path);
        await fsp.mkdir(path.dirname(out), {recursive: true});
        await fsp.writeFile(out, data);
        manifest.files.push({path: f.path, size: f.size,
          sha256: crypto.createHash('sha256').update(data).digest('hex')});
        bytes += f.size; n++;
        if (n % 5000 === 0) console.log('   ', n, 'files...');
      }
      manifest.completed = new Date().toISOString();
      await fsp.mkdir(outDir, {recursive: true});
      await fsp.writeFile(manifestFile, JSON.stringify(manifest, null, 2));
      results.push({title: arch.title, files: manifest.files.length, newFiles: n, bytes});
      console.log('  dumped:', n, 'new /', manifest.files.length, 'total |', (bytes / 1024).toFixed(0), 'KiB');
      await s.close(storage);
    }
    console.log('== BATCH DONE:', results.filter(r => !r.error).length, 'ok /', results.length, '==');
    await fsp.writeFile('/tmp/sysarch-batch-results.json', JSON.stringify(results, null, 2));
  } finally {
    for (const h of [...handles].reverse()) await s.close(h).catch(() => {});
    await s.cleanup().catch(() => {});
    // restore the controller root to the helper identity (pid 8) — the
    // promotion is shared per-boot state; other routes expect the natural
    // helper class (game content opens ran under it all week).
    const {execFile} = require('node:child_process');
    await new Promise(res => execFile('node',
      [path.join(__dirname, '..', 'memory', 'fix-session-identity.cjs'), '--pid', '8', '--force'],
      {cwd: path.join(__dirname, '..', '..')}, () => res())).catch(() => {});
    console.log('identity restored to helper (pid 8)');
  }
})().catch(e => {console.error('FAILED:', e.stack || e.message); process.exitCode = 1;});