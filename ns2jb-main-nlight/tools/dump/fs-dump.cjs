// fs-process memory dumper — banks the MISSING fs sysmodule binary + live state.
//
// The fw23 dump lacks fs (boot-critical, never enumerated). The wave runs
// INSIDE the fs process: its code/data regions are plain readable memory.
// Region walk = the proven RO rig (client.info = QueryProcessInformation via
// the monitor, used by the qualification at every boot); reads = memory.read
// (the boot's own primitive).
//
// Usage (netns-wrapped, live READY session):
//   sudo -n ip netns exec switchlab runuser -u nlight -- node fs-dump.cjs
//   ... --calibrate  (time one rig read + retained fetches at 4/16/64KB)
'use strict';
const fsSync = require('node:fs');
const path = require('node:path');
const latest = JSON.parse(fsSync.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json')));
const {Client} = require(path.join(latest.directory, 'switch2', 'process', 'client.cjs'));

const outDir = path.join(latest.directory, 'fs-dump');

async function main() {
  fsSync.mkdirSync(outDir, {recursive: true});
  // Fresh boot: no ro:dmnt is open yet (the sm-get budget is unused) — the
  // standard Client.open() path is right. If the budget is ever exhausted
  // (0x615), fall back to an existing owned rig session: all ro:dmnt
  // sessions are served by the same monitor process, so the kernel-PID
  // check passes on any of them.
  const execution = JSON.parse(fsSync.readFileSync(
    path.join(latest.directory, 'switch2', 'ro', 'current-execution.json')));
  let client;
  try {
    client = await new Client().open();
    console.log('opened a fresh ro:dmnt rig session');
  } catch (error) {
    const {connect} = require(path.join(latest.directory, 'switch2', 'tools', 'fs-memory.cjs'));
    const memory = await connect();
    const state = await memory.request({command: 'root-native-info'});
    const owned = (state.services || []).filter(x => x.name === 'ro:dmnt').pop();
    if (!owned) throw error;
    client = new Client();
    client.memory = memory;
    client.pid = execution.pid;
    client.handle = owned.handle;
    client.record = {session: execution.session, report: execution.report, roPid: execution.pid,
      payloadSha256: execution.payloadSha256, started: new Date().toISOString(), calls: []};
    client.file = path.join(latest.directory, 'switch2', 'process',
      execution.session + '-fsdump-' + Date.now() + '.json');
    console.log('fell back to owned ro:dmnt', owned.handle, '(', error.message.slice(0, 60), ')');
  }
  const memory = client.memory;
  const fsHandle = await client.fsProcess();
  const fsInfo = await client.info(fsHandle);
  const check = (c, m) => { if (!c) throw Error(m); };
  check(!fsInfo.result && fsInfo.pid, 'fs process probe failed');
  const fsPid = BigInt(fsInfo.pid);
  console.log('fs process handle', fsHandle, 'pid', fsPid);

  // Anchor from this boot's qualification: the fs text/rodata regions.
  const qual = JSON.parse(fsSync.readFileSync(
    path.join(latest.directory, 'switch2', 'process',
      fsSync.readdirSync(path.join(latest.directory, 'switch2', 'process'))
        .find(f => f.includes('qualification')))));
  const textAnchor = Number(qual.fsText.memory.address);
  console.log('text anchor 0x' + textAnchor.toString(16));

  // Walk regions around the anchor: from the anchor, step region-by-region
  // down and up while regions look like module code/rodata/data (RX/RO/RW,
  // sane sizes, contiguous-ish).
  const walk = async (start, dir) => {
    const regions = [];
    let at = start;
    for (let i = 0; i < 40; i++) {
      let info;
      try { info = await client.info(fsHandle, BigInt(at)); }
      catch (e) { break; }
      if (info.result) break;
      const m = info.memory || {};
      const base = Number(m.address), size = Number(m.size);
      if (!size || base > 2 ** 40) break;
      regions.push({base, size, type: m.type, permissions: m.permissions, attributes: m.attributes});
      const next = dir > 0 ? base + size : base - 1;
      if (next <= 0 || next > 2 ** 42) break;
      at = next;
      if (dir < 0) {
        // after moving down, re-query at the guessed base
        at = next;
      }
    }
    return regions;
  };
  console.log('walking regions...');
  const up = await walk(textAnchor, 1);
  const down = await walk(textAnchor - 1, -1);
  const all = [...down.reverse(), ...up];
  console.log(`mapped ${all.length} regions around the anchor`);
  const summary = [];
  for (const r of all) {
    const perms = r.permissions & 1 ? 'R' : '-';
    summary.push(`0x${r.base.toString(16)}+0x${r.size.toString(16)} t${r.type} p${r.permissions} a${r.attributes}`);
  }
  fsSync.writeFileSync(path.join(outDir, 'regions.json'), JSON.stringify(all, null, 1));
  console.log(summary.join('\n'));

  // SAFETY (ueJtpC death): ONLY type-3 (RX code) and type-4 (RO rodata)
  // regions with attributes 0 get dumped. Type-1/12 RW blocks can be device
  // aliases or special mappings — a bulk read of one killed the session.
  // The fs module = t3 text + t4 rodata; everything else is off-limits.
  let total = 0;
  // Safety ordering: readable regions (pure proven ops) come first; the
  // permission-flip text experiment goes LAST so everything bankable is
  // already on disk before the first unproven op.
  const order = all.slice().sort((a, b) =>
    ((a.type === 3 && a.permissions === 4) ? 1 : 0) - ((b.type === 3 && b.permissions === 4) ? 1 : 0));
  // Slice control: a hard per-chunk fetch ceiling and a chunk budget make
  // every invocation bounded; resume picks up where the files end.
  const maxChunks = Number((process.argv.find(a => a.startsWith('--max-chunks=')) || '').slice(13)) || 24;
  const maxFetchMs = 120000;
  let chunksThisRun = 0;
  for (const r of order) {
    // sfIxbr lesson: fs text = EXECUTE-ONLY (p4) — the wave read rejects it
    // cleanly. Only dump READABLE (permissions & 1) module regions.
    if (![3, 4].includes(r.type) || r.attributes !== 0 || !(r.permissions & 1) && !(r.type === 3 && r.permissions === 4)) {
      console.log(`skip (unsafe type) 0x${r.base.toString(16)}+0x${r.size.toString(16)} t${r.type} p${r.permissions}`);
      continue;
    }
    if (r.size > 8 * 1024 * 1024) { console.log(`skip big 0x${r.base.toString(16)}+0x${r.size.toString(16)}`); continue; }
    const name = `r-${r.base.toString(16)}-${r.size.toString(16)}.bin`;
    const out = path.join(outDir, name);
    // (resume logic below handles existing/partial/complete files)
    // Rig bulk read (0x524f0016): the monitor maps the page range into
    // itself and copies into the owned buffer — pure monitor-side code, no
    // wave involvement, clean error codes. The wave/retained paths CANNOT
    // read module pages (hangs/dead sessions — see NEXT-RUN rules).
    // Execute-only text (p4) first gets its READ bit flipped via rig
    // 0x524f0015 (SetProcessMemoryPermission, X-only -> RX), then flipped
    // back after the region is banked.
    const flipped = [];
    try {
      if (!(r.permissions & 1) && r.type === 3 && (r.permissions & 4) === 4) {
        const flip = await client.request(0x524f0015, fsHandle,
          [fsPid, r.base, r.size, 5]);
        if (flip.result) throw Error('read-bit flip failed: 0x' + flip.result.toString(16));
        flipped.push(r);
        console.log(`flipped X->RX 0x${r.base.toString(16)}+0x${r.size.toString(16)}`);
      }
      // The rig copies into the owned fs buffer at s.base+0x1800000; the
      // retained read (heap-only, proven) fetches it PC-side. sfIxbr lesson:
      // fetch in the PROVEN 64KB class with per-chunk timing + progress —
      // never a multi-MB retained fetch in one request.
      const info = await memory.request({command: 'root-native-info'});
      const fetchAt = Number(info.ownedBase) + 0x1800000;
      check(Number(info.ownedBytes) > 0x1810000, 'owned region too small for the fetch buffer');
      check(fetchAt + 0x10000 <= Number(info.ownedBase) + Number(info.ownedBytes),
        'fetch buffer outside the owned region');
      // Resume: a partial file's completed prefix is kept.
      let done = 0;
      if (fsSync.existsSync(out)) done = fsSync.statSync(out).size;
      if (done > r.size) done = 0;
      done -= done % 0x10000;
      if (done >= r.size) { console.log(`already complete: ${name}`); continue; }
      const fd = fsSync.openSync(out, done ? 'a' : 'w');
      try {
        let chunkCount = 0;
        for (let off = done; off < r.size; off += 0x10000) {
          if (chunksThisRun >= maxChunks) { console.log('chunk budget reached — slice complete, rerun to resume'); return; }
          const len = Math.min(0x10000, r.size - off);
          const tRig = Date.now();
          const reply = await client.request(0x524f0016, fsHandle,
            [fsPid, r.base + off, len, 0]);
          const tRigDone = Date.now();
          check(reply.result === 0, 'rig bulk read failed: 0x' + reply.result.toString(16));
          const tFetch0 = Date.now();
          const fetchWatch = setInterval(() => {
            if (Date.now() - tFetch0 > maxFetchMs)
              process.stderr.write('FETCH-SLOW ' + (Date.now() - tFetch0) + 'ms\n');
          }, 30000);
          let bytes;
          try {
            // qpJIeS freeze lesson: NEVER fetch via the retained read
            // (2+ min per 64KB). The dispatch's readOwned = the fast
            // alias-read channel (the CodeFS capture path).
            const fetched = await memory.request({command: 'root-native-owned-fetch',
              address: fetchAt, length: len});
            bytes = Buffer.from(fetched.hex, 'hex');
          } finally { clearInterval(fetchWatch); }
          check(bytes.length === len, 'owned fetch returned ' + bytes.length + ' of ' + len);
          chunksThisRun++;
          fsSync.writeSync(fd, bytes);
          total += len;
          chunkCount++;
          if (chunkCount % 8 === 0 || off + len >= r.size)
            console.log(`  ${name} +0x${off.toString(16)}: rig ${tRigDone - tRig}ms, fetch ${Date.now() - tRigDone}ms (${total} banked)`);
        }
      } finally { fsSync.closeSync(fd); }
      console.log(`dumped ${name} (${r.size} bytes)`);
    } finally {
      // Restore execute-only state on every path (leave no permission trace).
      for (const f of flipped) {
        const back = await client.request(0x524f0015, fsHandle,
          [fsPid, f.base, f.size, 4]);
        console.log(`restored RX->X 0x${f.base.toString(16)}: 0x${back.result.toString(16)}`);
      }
    }
  }
  console.log(`total dumped: ${total} bytes -> ${outDir}`);
}

main().catch(e => {console.error(e.stack || e); process.exitCode = 1;});
