// pm/boot-module dumper — the READ-ONLY debug suite (staged 0037-boot
// policy: svc 0x60 attach / 0x65 list / 0x69 query / 0x6A read; no 0x6B
// write, no 0x64 continue) driven through the RO rig subs 0x524f0017..1b.
//
// Modes (netns-wrapped, live READY session):
//   node pm-dump.cjs --list          kernel pid list (svc 0x65, read-only)
//   node pm-dump.cjs --probe <pid>   attach -> walk -> read text/rodata heads
//                                    -> service-string grep -> detach
//   node pm-dump.cjs --probe <pid> --pause-test <svc-handle-json>
//                                    probe + call a held service of the
//                                    target WHILE attached (pause oracle)
//   node pm-dump.cjs --dump <pid>    full type-3/4 dump + sha256 manifest
//                                    (--types 3,4 --max-chunks=24 --max-region=...)
//
// SAFETY (hard-won lessons, see FINDINGS):
// - NEVER dump/attach: the monitor (own pid), the helper (8), the app
//   (root callerPid) — enforced below. fs: identify FIRST via the recorded
//   fsText anchor (a walk base covering it = fs) and keep out of --dump.
// - attach may PAUSE the target on fw23 (unknown); 0x64 continue is NOT in
//   the mask, so detach (svc 0x16 on the debug handle) is the ONLY resume.
//   Always detach in finally. Never GetDebugEvent (0x63) — it stops the
//   target at the event with no resume path.
// - One rig call in flight; 64 KiB reads; only addresses from this run's
//   own 0x69 walk are read.
'use strict';
const fsSync = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const latest = JSON.parse(fsSync.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json')));
const {Client} = require(path.join(latest.directory, 'switch2', 'process', 'client.cjs'));
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const flag = (name, fallback = null) => {
  const hit = process.argv.find(a => a.startsWith('--' + name + '='));
  if (hit) return hit.slice(name.length + 3);
  const i = process.argv.indexOf('--' + name);
  if (i < 0) return fallback;
  const next = process.argv[i + 1];
  return next !== undefined && !next.startsWith('--') ? next : true;
};
const SELF = 0xffff8001;

async function openClient() {
  let client;
  try {
    client = await new Client().open();
    console.error('opened a fresh ro:dmnt rig session');
  } catch (error) {
    const {connect} = require(path.join(latest.directory, 'switch2', 'tools', 'fs-memory.cjs'));
    const memory = await connect();
    const state = await memory.request({command: 'root-native-info'});
    const owned = (state.services || []).filter(x => x.name === 'ro:dmnt').pop();
    if (!owned) throw error;
    const execution = JSON.parse(fsSync.readFileSync(
      path.join(latest.directory, 'switch2', 'ro', 'current-execution.json')));
    client = new Client();
    client.memory = memory;
    client.pid = execution.pid;
    client.handle = owned.handle;
    client.record = {session: execution.session, report: execution.report, roPid: execution.pid,
      payloadSha256: execution.payloadSha256, started: new Date().toISOString(), calls: []};
    client.file = path.join(latest.directory, 'switch2', 'process',
      execution.session + '-pmdump-' + Date.now() + '.json');
    console.error('fell back to owned ro:dmnt', owned.handle);
  }
  return client;
}

// Known per-boot process identities for the exclusion set.
function exclusions(client) {
  const set = new Map(); // pid -> reason
  set.set(Number(client.pid), 'the RO monitor (ourselves)');
  set.set(8, 'the native helper');
  try {
    const root = JSON.parse(fsSync.readFileSync(
      path.join(latest.directory, 'switch2', 'ro', 'root', 'current-root.json')));
    if (root.callerPid) set.set(Number(root.callerPid), 'the app / RPC executor (root callerPid)');
  } catch {}
  return set;
}

// The fs text anchor recorded by this boot's qualification (fs-dump.cjs
// reads the same file): a probe pid whose walk covers it IS fs.
function fsTextAnchor() {
  const dir = path.join(latest.directory, 'switch2', 'process');
  try {
    const name = fsSync.readdirSync(dir).find(f => f.includes('qualification'));
    const text = fsSync.readFileSync(path.join(dir, name), 'utf8');
    for (const line of text.split('\n')) {
      try {
        const row = JSON.parse(line);
        const anchor = row.fsText?.memory?.address ?? row.fsText?.address;
        if (anchor) return BigInt(anchor);
      } catch {}
    }
  } catch {}
  return null;
}

async function attach(client, pid) {
  const reply = await client.request(0x524f0017, SELF, [BigInt(pid), 0n, 0n, 0n]);
  if (reply.result || !reply.values[1]) return {error: reply.result};
  return {debug: reply.values[1]};
}

async function walk(client, debug, cap = 64) {
  const regions = [];
  let at = 0n, guard = 0;
  while (guard++ < cap && at < 2n ** 47n) {
    const q = await client.request(0x524f0019, SELF, [debug, at, 0n, 0n]);
    if (q.result) break;
    const v = q.values;
    const base = v[2], size = v[3];
    if (!size || base + size <= at) break;
    regions.push({base, size, type: Number(v[4] & 0xffffffffn),
      attributes: Number(v[4] >> 32n), permissions: Number(v[5] & 0xffffffffn)});
    at = base + size;
  }
  return regions;
}

async function fetchBuffer(memory, length) {
  const own = await memory.request({command: 'root-native-info'});
  const fetchAt = Number(own.ownedBase) + 0x1800000;
  if (!(Number(own.ownedBytes) > 0x1810000) ||
    fetchAt + 0x10000 > Number(own.ownedBase) + Number(own.ownedBytes))
    throw Error('owned region too small for the fetch buffer');
  const fetched = await memory.request({command: 'root-native-owned-fetch', address: fetchAt, length});
  return Buffer.from(fetched.hex, 'hex');
}

async function readChunk(client, memory, debug, address, length) {
  const reply = await client.request(0x524f0018, SELF, [debug, address, BigInt(length), 0n]);
  if (reply.result) throw Error('debug read failed: 0x' + reply.result.toString(16));
  const bytes = await fetchBuffer(memory, length);
  if (bytes.length !== length) throw Error('fetch returned ' + bytes.length + ' of ' + length);
  return bytes;
}

const SERVICE_HINTS = ['pm:shell', 'pm:dmnt', 'pm:info', 'fsp-srv', 'fsp-ldr', 'fsp:pr',
  'ldr:ro', 'sm:', 'ncm', 'ns:am2', 'am:', 'glue', 'loader', 'fatal:'];

async function main() {
  const outDir = path.join(latest.directory, 'pm-dump');
  fsSync.mkdirSync(outDir, {recursive: true});
  const client = await openClient();
  const memory = client.memory;
  const excl = exclusions(client);
  console.log(JSON.stringify({session: latest.session, monitorPid: Number(client.pid),
    exclusions: [...excl.entries()]}));
  const anchor = fsTextAnchor();
  if (anchor) console.log('fs text anchor (qualification): 0x' + anchor.toString(16));

  if (flag('list')) {
    // svc 0x65 is OFF the table (monitor killer, fw23 numbering unverified).
    // --list = the PROVEN pm:dmnt id-7 sweep instead (pid -> tid + programId).
    const info = await memory.request({command: 'root-native-info'});
    const pmDmnt = (info.services || []).find(x => x.name === 'pm:dmnt');
    if (!pmDmnt) throw Error('pm:dmnt is not held');
    const rows = [];
    for (let pid = 1; pid <= 300; pid++) {
      if (excl.has(pid)) continue;
      const hex = Buffer.alloc(8); hex.writeBigUInt64LE(BigInt(pid));
      let reply;
      try {reply = await memory.request({command: 'root-native-ipc',
        handle: pmDmnt.handle, id: 7, hex: hex.toString('hex')});}
      catch (e) {break;}
      if (!reply || reply.result) continue;
      const data = Buffer.from(reply.hex || reply.data || '', 'hex');
      if (data.length < 16) continue;
      rows.push({pid, tid: data.readBigUInt64LE(0).toString(),
        programId: data.readBigUInt64LE(8).toString(16).padStart(16, '0')});
      if (pid % 50 === 0) console.error('swept to pid', pid, ':', rows.length, 'running');
    }
    fsSync.writeFileSync(path.join(outDir, 'processes.json'), JSON.stringify(rows, null, 1));
    console.log('sweep:', rows.length, 'running processes (id-7)');
    for (const r of rows) console.log('  pid', r.pid, 'tid 0x' + r.tid.toString(16), 'program', r.programId);
    return;
  }

  const target = Number(flag('pid') ?? flag('probe') ?? flag('dump'));
  if (!target || !Number.isInteger(target)) throw Error('give --list, --probe <pid> or --dump <pid>');
  if (excl.has(target)) throw Error('pid ' + target + ' is excluded: ' + excl.get(target) +
    ' (attaching it can kill the session)');
  const dumpMode = process.argv.includes('--dump');

  const attached = await attach(client, target);
  if (attached.error) throw Error('attach failed: 0x' + attached.error.toString(16));
  const debug = attached.debug;
  console.log('attached pid', target, 'debug handle', debug);
  let isFs = false;
  try {
    const regions = await walk(client, debug, Number(flag('walk-cap', 64)));
    fsSync.writeFileSync(path.join(outDir, 'regions-' + target + '.json'), JSON.stringify(regions, null, 1));
    for (const r of regions)
      console.log('  0x' + r.base.toString(16) + '+0x' + r.size.toString(16),
        't' + r.type, 'a' + r.attributes, 'p' + r.permissions);
    if (anchor) for (const r of regions)
      if (r.type === 3 && anchor >= r.base && anchor < r.base + r.size) {
        isFs = true;
        console.log('*** pid', target, 'covers the fs text anchor = THE FS PROCESS ***');
      }

    const types = String(flag('types', '3,4')).split(',').map(Number);
    if (!dumpMode) {
      // --probe: read the head of the first text and first rodata region,
      // grep service strings, report. Cheap identification.
      let done = 0;
      for (const want of [3, 4]) {
        const r = regions.find(x => x.type === want && x.attributes === 0);
        if (!r || done >= 2) continue;
        const length = Number(Math.min(0x10000n, r.size));
        const bytes = await readChunk(client, memory, debug, r.base, length);
        const file = path.join(outDir, 'probe-' + target + '-t' + want + '.bin');
        fsSync.writeFileSync(file, bytes);
        const text = bytes.toString('latin1');
        const hits = SERVICE_HINTS.filter(s => text.includes(s));
        const strings = (text.match(/[\x20-\x7e]{6,}/g) || []).slice(0, 40);
        console.log('type', want, 'head @0x' + r.base.toString(16), '->', file);
        console.log('  service hits:', JSON.stringify(hits));
        for (const s of strings.slice(0, 12)) console.log('    |', s);
        done++;
      }
    } else {
      if (isFs) throw Error('refusing to --dump the fs process (session-critical)');
      const maxRegion = Number(flag('max-region', 8 * 1024 * 1024));
      const maxChunks = Number(flag('max-chunks', 24));
      let chunks = 0;
      const manifest = [];
      for (const r of regions) {
        if (chunks >= maxChunks) {console.log('chunk budget reached — rerun to resume'); break;}
        if (!types.includes(r.type) || r.attributes !== 0 || r.size > BigInt(maxRegion)) {
          console.log('skip 0x' + r.base.toString(16) + '+0x' + r.size.toString(16), 't' + r.type);
          continue;
        }
        const name = 'pid' + target + '-r-' + r.base.toString(16) + '-' + r.size.toString(16) + '.bin';
        const out = path.join(outDir, name);
        let done = 0;
        if (fsSync.existsSync(out)) done = fsSync.statSync(out).size;
        if (done > Number(r.size)) done = 0;
        done -= done % 0x10000;
        if (done >= Number(r.size)) {console.log('already complete:', name); continue;}
        const fd = fsSync.openSync(out, done ? 'a' : 'w');
        try {
          for (let off = BigInt(done); off < r.size && chunks < maxChunks; off += 0x10000n) {
            const length = Number(Math.min(0x10000n, r.size - off));
            const tRig = Date.now();
            const bytes = await readChunk(client, memory, debug, r.base + off, length);
            fsSync.writeSync(fd, bytes);
            chunks++;
            if (chunks % 4 === 0 || off + BigInt(length) >= r.size)
              console.log('  ' + name + ' +0x' + off.toString(16) + ': rig ' +
                (Date.now() - tRig) + 'ms (' + chunks + ' chunks)');
          }
        } finally {fsSync.closeSync(fd);}
        if (fsSync.statSync(out).size === Number(r.size))
          manifest.push({pid: target, name, base: r.base.toString(), size: Number(r.size), sha256: sha(fsSync.readFileSync(out))});
      }
      fsSync.writeFileSync(path.join(outDir, 'manifest-' + target + '.json'),
        JSON.stringify({session: latest.session, at: new Date().toISOString(), types, manifest}, null, 1));
      console.log('dumped', chunks, 'chunks this run');
    }
  } finally {
    const close = await client.request(0x524f001a, SELF, [debug, 0n, 0n, 0n]);
    console.log('detach: 0x' + close.result.toString(16), isFs ? '(was fs — brief pause only)' : '');
  }
}

main().catch(e => {console.error(e.stack || e); process.exitCode = 1;});