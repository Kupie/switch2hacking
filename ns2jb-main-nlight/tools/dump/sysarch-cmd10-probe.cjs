#!/usr/bin/env node
// fs cmd 10 (OpenFileSystemWithId-class) probe on system data archives — the
// route that mounts CONTROL NCAs (data-class) on fresh boots with just an
// ns promote, vs the never-working 206 archive attempts. Natural first,
// then ns-promoted, then read a known banked file (0823) end-to-end + sha.
'use strict';
const path = require('node:path');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const crypto = require('node:crypto');
const {execFile} = require('node:child_process');
const latest = JSON.parse(fs.readFileSync(process.env.HOME + '/dev/ns2jb/latest-session.json'));
const engine = path.join(latest.directory, 'switch2');
const {Session, u32, u64, check} = require(path.join(engine, 'app', 'session.cjs'));
const domain = require(path.join(engine, 'app', 'domain.cjs'));
const filesystem = require(path.join(engine, 'app', 'filesystem.cjs'));
const {paths} = require(path.join(engine, 'memory', 'paths.cjs'));
const fsMemory = require(path.join(engine, 'tools', 'fs-memory.cjs'));
const check2 = (ok, m) => {if (!ok) throw Error(m);};
const success = (r, l) => {if (r.result) throw Error(l + ': 0x' + (Number(r.result) >>> 0).toString(16)); return r;};

(async () => {
  const memory = await fsMemory.connect();
  const inv = JSON.parse(fs.readFileSync('/tmp/sysarch-inventory.json'));
  const proof = JSON.parse(await fsp.readFile(path.join(engine, 'ro', 'root', 'current-root.json')));
  const s = new Session('cmd10probe-' + Date.now(), 0x2100000);
  s.record = async () => {};
  await s.initialize();
  s.bulkDownloads = true;
  const handles = [];
  const track = h => {handles.push(h); return h;};
  const pathApi = paths(s, domain);
  const canonical = v => (Number(v) & 0x3fffff).toString(16);
  const promoteTo = async pid => {
    await new Promise(res => execFile('node',
      [path.join(__dirname, '..', 'dev', 'ns2jb', 'tools', 'memory', 'fix-session-identity.cjs'), '--pid', String(pid), '--force'],
      {cwd: process.env.HOME + '/dev/ns2jb'}, () => res()));
  };
  // pm:dmnt sweep for the ns pid
  const sweep = async () => {
    let pmDmnt;
    try {pmDmnt = await s.openService('pm:dmnt');} catch (e) {
      const infoS = await memory.request({command: 'root-native-info'});
      const smS = (infoS.services || []).find(x => x.sm)?.sm;
      const pkt = Buffer.alloc(256);
      pkt.writeUInt32LE(0x11); pkt.writeUInt32LE(2, 4); pkt.write('pm:dmnt', 8);
      await s.write(s.base, pkt);
      const transport = await s.call('send', s.base, 4096, smS);
      const reply = await s.readOwned(s.base, 256);
      let at = 8, count = 0;
      if (reply.readUInt32LE(4) >>> 31) {
        const special = reply.readUInt32LE(at); at += 4;
        count = (special >>> 5) & 15;
        if (count) {pmDmnt = reply.readUInt32LE(at); s.handles.add(pmDmnt);}
      }
    }
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
    return rows;
  };
  try {
    const root = track(domain.oneHandle(success(await domain.send(s, 'clone root', proof.rootHandle,
      domain.wire.control(2)), 'clone root')));
    const tryOpen = async (arch, label) => {
      const pathBuffer = Buffer.alloc(0x301);
      pathBuffer.write('@SystemContent://registered/' + arch.contentId + '.nca');
      const input = Buffer.alloc(16);
      input[0] = arch.attributes;
      input.writeUInt32LE(3, 4);
      input.writeBigUInt64LE(BigInt('0x' + arch.title), 8);
      const reply = await pathApi.raw(root, 10, pathBuffer, input);
      console.log(label, '->', reply.result
        ? 'REFUSED 0x' + (Number(reply.result) >>> 0).toString(16) + ' (canonical 0x' + canonical(reply.result) + ')'
        : 'OPEN handle ' + domain.oneHandle(reply));
      return reply;
    };
    const a812 = inv.find(a => a.title === '0400000000000812');
    const a823 = inv.find(a => a.title === '0400000000000823');
    // natural identity
    let r = await tryOpen(a812, '0812 cmd-10 natural');
    if (r.result) {
      // ns promote, retry
      const rows = await sweep();
      const ns = rows.find(x => x.programId.endsWith('0000001f'));
      check2(ns, 'ns pid not found');
      console.log('promoting to ns pid', ns.pid);
      await promoteTo(ns.pid);
      r = await tryOpen(a812, '0812 cmd-10 promoted');
      if (!r.result) {
        // 0823 end-to-end: read a banked file + sha
        const fsHandle = track(domain.oneHandle(r));
        const r2 = await tryOpen(a823, '0823 cmd-10 promoted');
        if (!r2.result) {
          const fs823 = track(domain.oneHandle(r2));
          const manifest = JSON.parse(await fsp.readFile(
            process.env.HOME + '/dev/switch/dumps/fw23-archives/0400000000000823/manifest.json'));
          const known = manifest.files[0];
          const file = track(domain.oneHandle(success(await pathApi.normal(fs823, 8, known.path, u32(1)), 'open file ' + known.path)));
          const size = Number(await filesystem.fileSize(s, file));
          console.log('file', known.path, '| size', size, '(manifest', known.size + ')');
          const bytes = await filesystem.readFile(s, file, 0, size);
          const sha = crypto.createHash('sha256').update(bytes).digest('hex');
          console.log('sha256:', sha.slice(0, 16), '| manifest:', known.sha256.slice(0, 16),
            '| MATCH:', sha === known.sha256);
        }
      }
    }
  } finally {
    for (const h of [...handles].reverse()) await s.close(h).catch(() => {});
    await s.cleanup().catch(() => {});
    // restore helper class (promotions persist per-boot)
    await new Promise(res => execFile('node',
      [process.env.HOME + '/dev/ns2jb/tools/memory/fix-session-identity.cjs', '--pid', '8', '--force'],
      {cwd: process.env.HOME + '/dev/ns2jb'}, () => res())).catch(() => {});
    console.log('identity restored to helper (pid 8)');
  }
})().catch(e => {console.error('FAILED:', e.stack || e.message); process.exitCode = 1;});
