// fs-heap registry chase — route 1 (FAH/FAC descriptor hunt).
//
// TWO read channels, TWO VA classes:
//  - rig 0011 (RO monitor, svc MapProcessMemory): fast, <=128 B per call —
//    but ONLY type 3/4 (text/rodata): svc 0x74 categorically refuses type-5
//    heap (0xd401, JrcXEE-proven).
//  - window slide (tools/fs-memory.cjs Memory client -> retained-read/write
//    -> readMemory/writeMemory -> setPointer): 16 KiB per round-trip,
//    arbitrary fs VA (guards relaxed to 2^48 in retained-memory.cjs) —
//    REACHES fs heap. Live-proven by fix-session-identity (pid promotion
//    writes) and every root-graph chase since.
//
// HARD RULE (ueJtC lesson, enforced here): a slide target must lie inside a
// region returned by THIS boot's own 0010 walk (banked by --regions into
// chase.json). No blind values from chases. --slide-raw overrides only for
// the recorded run-dir proofs (never live exploration).
//
// Modes (netns-wrapped, live READY session):
//   --regions                 0010 walk of fs address space -> chase.json
//   --read <addr> [--length]  rig 0011 (t3/t4 only), --read-elf for elf VAs
//   --list                    registry PTR_LOOP list walk (rig 0011)
//   --slide-read <addr>       window-slide read (default 0x100), hex out
//   --slide-dump <addr> <len> slide + bank to fs-heap-chase/<name>.bin
//   --slide-chase <addr> <off> [<off>..] manual u64 chase (no 2^39 guard)
//   --slide-write <addr> <expectedHex> <replacementHex>  compare-verified
//
// Rig discipline: slide modes open NO rig session (zero monitor slots);
// rig modes close the client in a top-level finally (sessions[4] leak
// lesson, JrcXEE). Addresses print decimal (client convention) and hex.
'use strict';
const fsSync = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fsSync.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json')));
const {Client} = require(path.join(latest.directory, 'switch2', 'process', 'client.cjs'));
const {connect} = require(path.join(latest.directory, 'switch2', 'tools', 'fs-memory.cjs'));
const arg = (name, fallback = null) => {
  const hit = process.argv.find(a => a === '--' + name || a.startsWith('--' + name + '='));
  if (!hit) return fallback;
  if (hit.includes('=')) return hit.slice(name.length + 3);
  const i = process.argv.indexOf(hit);
  const next = process.argv[i + 1];
  return next !== undefined && !next.startsWith('--') ? next : true;
};
const num = v => typeof v === 'bigint' ? v : BigInt(String(v).replace(/^(0x)?/i, '0x'));
const hx = v => '0x' + num(v).toString(16);
const dec = v => num(v).toString();

// elf anchors (fw23-live-fs build; delta = liveBase - ELF_SEG2)
const ELF_SEG2 = 0x599223e000n;
const PTR_LOOP = 0x59922a7030n;
const FSP_PR_NAME = 0x5992242facn;
const SELF = 0xffff8001;
const outDir = path.join(latest.directory, 'fs-heap-chase');

function loadRegions() {
  const file = path.join(outDir, 'regions.json');
  if (!fsSync.existsSync(file))
    throw Error('no walk banked: run --regions first (the slide target rule needs this boot\'s 0010 map)');
  return JSON.parse(fsSync.readFileSync(file)).map(r =>
    ({base: num(r.base), size: num(r.size), type: r.type, attributes: r.attributes, permissions: r.permissions}));
}
function validateWalkAddress(address, {slideRaw = false} = {}) {
  if (slideRaw) return {inside: true, raw: true};
  const regions = loadRegions();
  const a = num(address);
  for (const r of regions)
    if (a >= r.base && a < r.base + r.size)
      return {inside: true, region: r};
  throw Error('slide target ' + hx(a) + ' is outside every walked region (ueJtC rule); re-walk or --slide-raw for recorded proofs only');
}

async function slideClient() {
  const memory = await connect();
  const info = memory.info;
  if (!info.ready) throw Error('retained endpoint not ready');
  return memory;
}
const u64At = (memory, at) => memory.read(Number(num(at)), 8).then(b => b.readBigUInt64LE(0));
async function chaseManual(memory, base, offsets) {
  let target = num(base), trace = [];
  for (const off of offsets.map(num)) {
    const field = target + off;
    const value = await u64At(memory, field);
    trace.push({field: dec(field), hex: hx(field), value: dec(value), valueHex: hx(value)});
    if (value < 0x100000000n) throw Error('non-pointer value ' + hx(value) + ' at ' + hx(field));
    target = value;
  }
  return {target, hex: hx(target), trace};
}

let clientRef = null;
async function rigClient() {
  const client = await new Client().open();
  clientRef = client;
  return client;
}
async function fsFacts(client) {
  const fsHandle = await client.fsProcess();
  const info = await client.info(fsHandle);
  if (info.result || !info.pid) throw Error('fs probe failed: 0x' + info.result.toString(16));
  const qualDir = path.join(latest.directory, 'switch2', 'process');
  const qualFile = fsSync.readdirSync(qualDir).find(f => f.includes('qualification'));
  const qual = JSON.parse(fsSync.readFileSync(path.join(qualDir, qualFile), 'utf8'));
  const fsTextBase = num(qual.fsText.memory.address);
  if (num(qual.fsText.memory.size) !== 0x58000n)
    throw Error('fsText size differs from the elf LOAD-2: different build, delta anchoring invalid');
  return {fsHandle, fsPid: BigInt(info.pid), delta: fsTextBase - ELF_SEG2};
}

async function main() {
  fsSync.mkdirSync(outDir, {recursive: true});
  const mode =
    arg('regions') ? 'regions' :
    arg('list') ? 'list' :
    arg('read') ? 'read' :
    arg('read-elf') ? 'read-elf' :
    arg('slide-read') ? 'slide-read' :
    arg('slide-dump') ? 'slide-dump' :
    arg('slide-chase') ? 'slide-chase' :
    arg('slide-write') ? 'slide-write' : null;
  if (!mode) throw Error('modes: --regions | --read <addr> | --list | --slide-read <addr> | --slide-dump <a> <len> | --slide-chase <a> <off..> | --slide-write <a> <exp> <new>');
  const log = {session: latest.session, mode, at: new Date().toISOString(), steps: []};
  const saveLog = name => fsSync.writeFileSync(path.join(outDir, name + '.json'), JSON.stringify(log, null, 1));

  if (mode === 'regions') {
    const client = await rigClient();
    try {
      const {fsHandle, fsPid, delta} = await fsFacts(client);
      log.delta = delta.toString();
      const query = async address => {
        const r = await client.info(fsHandle, num(address));
        if (r.result) return {error: r.result};
        const m = r.memory || {};
        return {base: num(m.address), size: num(m.size), type: m.type,
          attributes: m.attributes, permissions: m.permissions};
      };
      // Full walk from 0 (the earlier partial-anchor walk missed low holes).
      const regions = [];
      let at = 0n, guard = 0;
      while (guard++ < 4096 && at < 2n ** 48n) {
        const q = await query(at);
        if (q.error || !q.size) break;
        regions.push(q);
        const next = q.base + q.size;
        if (next <= at) break;
        at = next;
      }
      log.regions = regions.map(r => ({base: dec(r.base), size: dec(r.size), type: r.type,
        attributes: r.attributes, permissions: r.permissions}));
      for (const r of regions)
        console.error(hx(r.base), '+', hx(r.size), 't' + r.type, 'a' + r.attributes, 'p' + r.permissions);
      fsSync.writeFileSync(path.join(outDir, 'regions.json'), JSON.stringify(log.regions, null, 1));
      await saveLog('chase');
      console.log(JSON.stringify({regions: regions.length, file: path.join(outDir, 'regions.json')}));
    } finally { await clientRef.close(); }
    return;
  }

  if (mode === 'slide-read' || mode === 'slide-dump' || mode === 'slide-chase' || mode === 'slide-write') {
    const memory = await slideClient();
    log.fsPid = memory.info.session;
    const raw = !!arg('slide-raw');
    if (mode === 'slide-chase') {
      // --slide-chase <base> <off> [<off>..]: positional after the flag.
      const iChase = process.argv.indexOf('--slide-chase');
      const vals = process.argv.slice(iChase + 1).filter(a => /^[0-9x]+$/i.test(a) && !a.startsWith('--'));
      const [base, ...offsets] = vals;
      if (!base || !offsets.length) throw Error('--slide-chase <base> <off> [<off>..] (hex or decimal)');
      validateWalkAddress(base, {slideRaw: raw});
      const chain = await chaseManual(memory, base, offsets);
      for (const step of chain.trace) validateWalkAddress(step.value, {slideRaw: raw});
      log.steps.push({base: dec(num(base)), chain});
      await saveLog('chase');
      console.log(JSON.stringify({target: chain.hex, trace: chain.trace.map(t => ({field: t.hex, value: t.valueHex}))}));
      return;
    }
    const target = arg('slide-read') ?? arg('slide-dump') ?? arg('slide-write');
    if (!target || target === true) throw Error('missing <addr>');
    const check = validateWalkAddress(target, {slideRaw: raw});
    if (check.region) console.error('target inside walked region', hx(check.region.base), '+', hx(check.region.size), 't' + check.region.type);
    if (mode === 'slide-read') {
      const length = Number(arg('length', 256));
      // The Memory client's guards take Numbers (Number.isSafeInteger); the
      // slide channels accept the same. Convert, never pass BigInt.
      const bytes = await memory.read(Number(num(target)), length);
      console.log(bytes.toString('hex'));
      log.steps.push({address: dec(num(target)), length, hex: bytes.toString('hex')});
      await saveLog('chase');
      return;
    }
    if (mode === 'slide-dump') {
      // --slide-dump <addr> <length>: both positional after the flag.
      const iDump = process.argv.indexOf('--slide-dump');
      const L = Number(process.argv[iDump + 2]);
      if (!Number.isInteger(L) || L <= 0 || L > 0x600000)
        throw Error('--slide-dump <addr> <length 1..6MiB>');
      const parts = [];
      const targetNum = Number(num(target));
      for (let at = 0; at < L; at += 0x4000) {
        const size = Math.min(0x4000, L - at);
        validateWalkAddress(num(target) + BigInt(at), {slideRaw: raw});
        parts.push(await memory.read(targetNum + at, size));
      }
      const bytes = Buffer.concat(parts);
      const name = 'slide-' + hx(num(target)).replace('0x', '') + '-' + L.toString(16) + '.bin';
      const file = path.join(outDir, name);
      fsSync.writeFileSync(file, bytes);
      const crypto = require('node:crypto');
      log.steps.push({address: dec(num(target)), length: L, file,
        sha256: crypto.createHash('sha256').update(bytes).digest('hex')});
      await saveLog('chase');
      console.log(JSON.stringify({file, bytes: L, sha256: log.steps[0].sha256}));
      return;
    }
    // slide-write: --slide-write <addr> <expectedHex> <replacementHex>
    const i = process.argv.indexOf('--slide-write');
    const [expectedHex, replacementHex] = process.argv.slice(i + 1, i + 3);
    if (!/^[0-9a-f]+$/i.test(String(expectedHex)) || !/^[0-9a-f]+$/i.test(String(replacementHex)) ||
      expectedHex.length !== replacementHex.length || expectedHex.length % 2)
      throw Error('--slide-write <addr> <expectedHex> <replacementHex> (equal lengths)');
    const result = await memory.write(Number(num(target)),
      Buffer.from(String(expectedHex), 'hex'), Buffer.from(String(replacementHex), 'hex'));
    log.steps.push({address: dec(num(target)), length: expectedHex.length / 2,
      expectedHex, replacementHex, verified: result.verified});
    await saveLog('chase');
    console.log(JSON.stringify({verified: result.verified, address: hx(num(target))}));
    return;
  }

  // rig modes (--read / --read-elf / --list): unchanged semantics.
  const client = await rigClient();
  try {
    const {fsHandle, fsPid, delta} = await fsFacts(client);
    console.error('fs pid', fsPid, '| delta', dec(delta), hx(delta));
    const read = async (address, length = 128) => {
      const r = await client.read(fsHandle, fsPid, num(address), Number(length));
      if (r.result) return {error: r.result};
      if (!r.hex || r.length !== Number(length)) return {error: 'short'};
      return {hex: r.hex};
    };
    const readLoop = async (address, length) => {
      const bytes = [];
      let at = num(address), end = at + BigInt(length);
      while (at < end) {
        const remaining = end - at;
        const step = Number(remaining < 128n ? remaining : 128n);
        const r = await read(at, step);
        if (r.error) return {error: r.error, at};
        bytes.push(Buffer.from(r.hex, 'hex'));
        at += BigInt(step);
      }
      return {buffer: Buffer.concat(bytes)};
    };
    if (mode === 'list') {
      const nameCheck = await read(num(FSP_PR_NAME) + delta, 8);
      console.error('fsp-pr check:', nameCheck.error ? 'ERR' : JSON.stringify(Buffer.from(nameCheck.hex, 'hex').toString('latin1')));
      const container = await readLoop(num(PTR_LOOP) + delta + 0x30n, 16);
      if (container.error) throw Error('head container read failed at ' + hx(container.at));
      const head = container.buffer.readBigUInt64LE(0);
      const nodes = [];
      let cur = head, guard = 0;
      const seen = new Set();
      while (cur && cur > 0x10000n && !seen.has(cur.toString()) && guard++ < 64) {
        seen.add(cur.toString());
        const n = await readLoop(cur, 32);
        if (n.error) {nodes.push({at: hx(cur), error: '0x' + n.error.toString(16)}); break;}
        const b = n.buffer;
        nodes.push({at: hx(cur), prev: hx(b.readBigUInt64LE(0)), next: hx(b.readBigUInt64LE(8)),
          pid: b.readBigUInt64LE(16).toString(), programId: hx(b.readBigUInt64LE(24))});
        console.error(JSON.stringify(nodes[nodes.length - 1]));
        cur = b.readBigUInt64LE(8);
      }
      log.registryNodes = nodes;
      await saveLog('chase');
      console.log(JSON.stringify({nodes: nodes.length}));
      return;
    }
    const readArg = mode === 'read' ? arg('read') : arg('read-elf');
    if (!readArg || readArg === true) throw Error('missing <addr>');
    let at = num(readArg);
    if (mode === 'read-elf') at += delta;
    const length = Number(arg('length', 128));
    const r = await readLoop(at, length);
    if (r.error) throw Error('read failed at ' + hx(r.at) + ': 0x' + r.error.toString(16));
    console.log(r.buffer.toString('hex'));
    log.steps.push({address: at.toString(), length, hex: r.buffer.toString('hex')});
    await saveLog('chase');
  } finally { await clientRef.close(); }
}

main()
  .catch(e => {console.error(e.stack || e); process.exitCode = 1;})
  .finally(async () => {
    if (clientRef) {try {await clientRef.close();} catch (e) {console.error('client close:', e.message);}}
  });