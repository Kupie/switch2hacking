const path = require('node:path');
const {packet, response} = require("../../shared/ipc.cjs");
const check = (ok, message) => { if (!ok) throw Error(message); };
const cancelCode = {offset: 0x158414, bytes: '210300d4c0035fd6'};

async function cancelWorkers(context) {
  const {s, live, report} = context;
  const workers = report.nativeRo.apiWorkers;
  check(workers?.length === 7 && workers.every(w => s.handles.has(w.handle)), 'API-worker copies are missing');
  await s.verifyCode(cancelCode, 'CancelSynchronization');
  const replies = await s.rpc.batch(workers.map(w => ({fn: live.sdk + cancelCode.offset, args: [w.handle, 0, 0]})));
  return replies.map((r, i) => ({handle: workers[i].handle, result: r.result}));
}

async function dispatch(context, request, state, domain) {
  const {s, live, save} = context;
  const directory = path.join(__dirname, '../app');
  const native = require(path.join(directory, 'native-worker.cjs'));
  const events = require(path.join(directory, 'events.cjs'));
  const workerCode = require(path.join(directory, 'worker.cjs'));
  const command = request.command.slice('root-native-'.length);
  if (command === 'worker-bind') {
    const rows = request.workers;
    check(Array.isArray(rows) && rows.length === 7 && new Set(rows.map(w => w.handle)).size === 7,
      'Expected seven different native API-worker copies');
    check(rows.every(w => state.events.some(e => e.handle === w.handle) && s.handles.has(w.handle) &&
      state.calls.some(e => e.operation === 'thread-id' && e.handle === w.handle && e.result === 0 && Number(e.value) === w.id)),
    'Worker copies lack their native thread-ID checks');
    await s.verifyCode(cancelCode, 'CancelSynchronization');
    state.apiWorkers = rows;
    await save();
    return rows;
  }
  if (command === 'worker-cancel') {
    const replies = await cancelWorkers(context);
    (state.cancellations ||= []).push({at: new Date().toISOString(), replies});
    await save();
    check(replies.every(r => r.result === 0), 'Foreign thread cancellation was rejected');
    return replies;
  }
  if (command === 'worker-prepare') {
    check(!s.threads.size && (!state.worker || state.worker.joined), 'A native worker is still active');
    await workerCode.verifyWorkerCode(s);
    await events.verify(s);
    const area = s.base + 0x2100000, gate = area, slot = area + 0x10;
    check(area + 0x60000 <= s.base + s.bytes, 'Worker area exceeds the retained allocation');
    await events.initialize(s, gate);
    const handle = Number(request.handle);
    check(request.kind === 'app-service' || s.handles.has(handle), 'Worker IPC requires a retained caller handle');
    const batchInputs = request.kind === 'notifier-probe' && request.candidates;
    if (batchInputs) check(Array.isArray(batchInputs) && batchInputs.length > 0 && batchInputs.length <= 16 &&
      batchInputs.every(n => Number.isInteger(n) && n >= 0 && n <= 0xffffffff), 'Expected 1..16 candidate handles');
    const count = batchInputs ? batchInputs.length : request.kind === 'control-test' ? 2 : 1;
    const upload = batchInputs ? Buffer.alloc(count * 0x1000) : null;
    check(['control-test', 'cmif-control', 'pm-launch', 'sm-get', 'app-service', 'ro-probe', 'ro-process', 'notifier-probe', 'ro-rig', 'ro-relay', 'ro-exec'].includes(request.kind), 'Unknown worker operation');
    const calls = [{function: live.sdk + events.code.wait.offset, args: [gate, 0, 0, 0]}];
    for (let i = 0; i < count; i++) {
      let bytes;
      const address = area + 0x1000 * (i + 1);
      if (request.kind === 'app-service') {
        check(typeof request.name === 'string' && /^[a-z0-9:-]{1,8}$/.test(request.name), 'Invalid application service name');
        const code = require("../../shared/sdk-functions.json").getService;
        await s.verifyCode(code, 'Application GetService');
        bytes = Buffer.alloc(32); bytes.write(request.name, 8);
        await s.write(address, bytes);
        calls.push({function: live.sdk + code.offset, args: [address, address + 8, request.name.length, 0]});
        continue;
      } else if (request.kind === 'cmif-control') {
        const service = state.services.find(item => item.handle === handle);
        check(service && ['fsp-srv', 'spl:fs', 'pm:dmnt'].includes(service.name) &&
          [0, 3].includes(request.id), 'Expected an owned qualification session and manager command 0 or 3');
        bytes = domain.wire.control(request.id);
      } else if (request.kind === 'control-test') bytes = domain.wire.control(3);
      else if (request.kind === 'sm-get') {
        check(state.services.some(x => x.sm === handle) && typeof request.name === 'string' &&
          /^[a-z0-9:-]{1,8}$/.test(request.name), 'SM worker requires the established borrowed client and a service name');
        bytes = Buffer.alloc(256); bytes.writeUInt32LE(0x11); bytes.writeUInt32LE(2, 4); bytes.write(request.name, 8);
      } else if (request.kind === 'ro-probe') {
        check(typeof request.hex === 'string' && /^[0-9a-fA-F]{16}$/.test(request.hex), 'RO proof needs one 64-bit challenge');
        bytes = packet(0x524f0001, Buffer.from(request.hex, 'hex'));
      } else if (request.kind === 'ro-rig') {
        // Side-channel rig: hex = sub u64 + argument u64 (32 hex), or for
        // sub 21 (HIPC2): sub + handle|wc + cmd|seq + 3 args (96 hex).
        check(typeof request.hex === 'string' && /^[0-9a-fA-F]{32,112}$/.test(request.hex) &&
          request.hex.length % 16 === 0, 'Rig request needs 2..7 u64s (16 hex chars each)');
        check(state.services.some(x => x.name === 'ro:dmnt' && x.handle === handle), 'Rig request requires the owned RO service');
        bytes = packet(0x524f0002, Buffer.from(request.hex, 'hex'));
      } else if (request.kind === 'ro-relay') {
        // Debug relay: hex = sub u64 + op + a0 + a1 + a2 (80 hex chars).
        // Sub 17 queues {op, args} for the creport executor; sub 18 reads
        // the latest executor report. Same owned ro:dmnt session as the rig.
        check(typeof request.hex === 'string' && /^[0-9a-fA-F]{80}$/.test(request.hex), 'Relay request needs sub + op + 3 args');
        check(state.services.some(x => x.name === 'ro:dmnt' && x.handle === handle), 'Relay request requires the owned RO service');
        bytes = packet(0x524f0002, Buffer.from(request.hex, 'hex'));
      } else if (request.kind === 'ro-exec') {
        // Hot-reload exec rig: hex = raw 0x524f0003 payload (8..208 bytes).
        check(typeof request.hex === 'string' && /^([0-9a-fA-F]{2}){8,208}$/.test(request.hex),
          'Exec request needs 8..208 payload bytes');
        check(state.services.some(x => x.name === 'ro:dmnt' && x.handle === handle), 'Exec request requires the owned RO service');
        bytes = packet(0x524f0003, Buffer.from(request.hex, 'hex'));
      } else if (request.kind === 'ro-process') {
        const target = Number(request.processHandle), id = Number(request.id);
        check(state.services.some(x => x.name === 'ro:dmnt' && x.handle === handle), 'Process probe requires the owned RO service');
        check(s.handles.has(target) || target === 0xffff8001, 'Target process handle is not owned');
        // 0x524f0017..1a = the read-only debug suite (attach/query/read/detach):
        // the debug handle is monitor-internal and rides in the input words;
        // target is ignored payload-side (a SELF dup is transferred and closed).
        check([0x524f0010, 0x524f0011, 0x524f0012, 0x524f0013, 0x524f0014,
          0x524f0015, 0x524f0016, 0x524f0017, 0x524f0018, 0x524f0019,
          0x524f001a, 0x524f001b].includes(id), 'Unknown process probe');
        const size = id === 0x524f0014 ? 128 : 64;
        check(typeof request.hex === 'string' && request.hex.length === size && /^[0-9a-fA-F]+$/.test(request.hex),
          'Process probe input length differs');
        const receive = [];
        if (id === 0x524f0016 || id === 0x524f0018 || id === 0x524f001b) {
          // 16: bulk map-alias read (length at word 2, 4 MiB cap); 18: debug
          // read (length at word 2, 64 KiB cap); 1b: process list (max at
          // word 0 -> u64 pid array in the receive buffer, 256 pid cap).
          const raw = Buffer.from(request.hex, 'hex');
          const length = id === 0x524f001b
            ? Math.min(Number(raw.readBigUInt64LE(0)), 256) * 8
            : Number(raw.readBigUInt64LE(16));
          const cap = id === 0x524f0016 ? 0x400000 : id === 0x524f0018 ? 0x10000 : 256 * 8;
          const output = s.base + 0x1800000;
          check(Number.isInteger(length) && length > 0 && length <= cap &&
            output + length <= s.base + s.bytes, 'Bulk RO read exceeds the owned buffer');
          receive.push({address: output, size: length});
        }
        bytes = packet(id, Buffer.from(request.hex, 'hex'), {pid: true, copies: [target], receive});
      } else if (request.kind === 'notifier-probe') {
        check(state.notifiers.includes(handle), 'Native execution probe requires our owned FS notifier');
        const input = Buffer.alloc(batchInputs ? 4 : 0);
        if (batchInputs) input.writeUInt32LE(batchInputs[i]);
        bytes = packet(0, input);
      } else {
        check(state.services?.some(x => x.name === 'pm:shell' && x.handle === handle), 'Launch requires the owned PM session');
        const flags = Number(request.flags ?? 0);
        check(flags === 0 || flags === 0x10, 'Unsupported launch flags');
        const storage = Number(request.storage ?? 3);
        check([3, 4].includes(storage) &&
          ['0x0400000000000037', '0x0400000000000036', '0x0400000000000039',
           // Mario Kart World: storage 4 (BuiltInUser) - the loader's own
           // authorized CodeFS open, recorded in the gate ledger.
           '0x0400c3f00006e000',
           // Error-class probes (mkw-create route, 2026-10-25): a second
           // installed app (MK8D) and a bogus app title - never started,
           // LaunchTitle validation only.
           '0x0100152000022000', '0x0100c9100b06a000',
           '0x0400c3f00006e123'].includes(request.title),
          'Only a pinned policy target may be launched');
        const input = Buffer.alloc(24); input.writeUInt32LE(flags);
        input.writeBigUInt64LE(BigInt(request.title), 8); input[16] = storage;
        bytes = packet(0, input);
      }
      if (upload) bytes.copy(upload, i * 0x1000);
      else await s.write(address, bytes);
      calls.push({function: live.sdk + require("../../shared/sdk-functions.json").send.offset,
        args: [address, 4096, handle, 0]});
    }
    if (upload) await s.write(area + 0x1000, upload);
    state.worker = await native.start(s, area + 0x20000, 0x40000, slot, calls,
      'ro-' + request.kind + '-' + Date.now());
    Object.assign(state.worker, {kind: request.kind, handle, gate, area, count, released: false,
      serviceName: request.name, challenge: request.hex, candidates: batchInputs || undefined,
      processCommand: request.kind === 'ro-process' ? Number(request.id) : undefined,
      launchTitle: request.kind === 'pm-launch' ? request.title : undefined,
      launchFlags: request.kind === 'pm-launch' ? Number(request.flags ?? 0) : undefined});
    await save();
    return {kind: state.worker.kind, thread: state.worker.thread, gate, count};
  }
  if (command === 'worker-hipc2-prepare' || command === 'worker-hipc2-resume') {
    // TLS-safe HIPC2 sender. A fresh worker is spawned PARKED at its start
    // gate; its OWN (quiescent, kernel-registered) TLS pointer is read from
    // its pthread struct and patched into the memcpy/send argument slots of
    // its call frame; the driver then releases the gate. The worker runs
    // memcpy(TLS, frame, 0x100) -> send(TLS, 0x100, handle) ->
    // memcpy(reply, TLS, 0x100) entirely on its own thread.
    // 2ddp51 lesson: NEVER send HIPC2 from a serving RPC executor — its
    // TLS+0..0x100 is live wave state and clobbering it kills the session.
    const resuming = command === 'worker-hipc2-resume';
    check(resuming || (!s.threads.size && (!state.worker || state.worker.joined)),
      'A native worker is still active');
    await workerCode.verifyWorkerCode(s);
    await events.verify(s);
    const area = s.base + 0x2100000, gate = area, slot = area + 0x10;
    check(area + 0x60000 <= s.base + s.bytes, 'Worker area exceeds the retained allocation');
    // NEVER re-initialize the gate event on resume — the abandoned worker is
    // parked waiting on it; re-init could wake it with unpatched args.
    if (!resuming) await events.initialize(s, gate);
    const handle = Number(request.handle);
    check(s.handles.has(handle), 'HIPC2 send requires a retained service handle');
    const frame = Buffer.from(request.frameHex || '', 'hex');
    check(resuming ? frame.length === 0 || frame.length === 0x100 : frame.length === 0x100,
      'HIPC2 frame must be 256 bytes');
    const cfgFrame = area + 0x1000, replyArea = area + 0x1200;
    const sendOffset = require("../../shared/sdk-functions.json").send.offset;
    // ROOT-CAUSE FIX (3 console deaths): the pipeline's worker-prepare
    // PREPENDS wait(gate) as call0 — that leading SDK wait IS the park.
    // Without it, call0 runs the instant pthread_create returns, and a
    // placeholder-arg call0 (memcpy dst 0) = instant NULL write = fs death.
    // Frame: call0 = wait(gate) [parks], call1 = memcpy(TLS, frame, 0x100),
    // call2 = send(TLS, 0x100, handle), call3 = memcpy(reply, TLS, 0x100).
    const calls = [
      {function: live.sdk + events.code.wait.offset, args: [gate, 0, 0, 0]},   // PARK
      {function: live.sdk + 0x586fb0, args: [0, cfgFrame, 0x100, 0]},     // memcpy(TLS, frame, 0x100)
      {function: live.sdk + sendOffset, args: [0, 0x100, handle, 0]},      // send(TLS, 0x100, handle)
      {function: live.sdk + 0x586fb0, args: [replyArea, 0, 0x100, 0]},     // memcpy(reply, TLS, 0x100)
    ];
    if (frame.length) await s.write(cfgFrame, frame);
    await s.write(replyArea, Buffer.alloc(0x100));
    if (resuming) {
      // The abandoned worker is already parked in its wait(gate) call0 —
      // same frame/area. Re-run the scan against it; clear the flag so the
      // scan's success path can finish the patch and the release guard opens.
      check(state.worker?.hipc2Abandoned && state.worker.base === area + 0x20000,
        'No matching abandoned hipc2 worker to resume');
      state.worker.hipc2Abandoned = null;
    } else {
      state.worker = await native.start(s, area + 0x20000, 0x40000, slot, calls,
        'ro-hipc2-' + Date.now());
    }
    const abandon = async reason => {
      // 0dSsB1/Jer6aO lesson: NEVER release a worker whose args were not
      // fully validated — svc 0x22 with a NULL/partially-patched frame kills
      // the fs process ("app crashed" console fatal). A worker parked at its
      // start gate is proven harmless; it stays parked forever. The native
      // worker slot is then stuck for THIS BOOT ONLY (future worker-prepare
      // calls fail with 'A native worker is still active') — the safe cost.
      (state.abandoned ||= []).push({at: new Date().toISOString(), reason,
        thread: state.worker.thread, gate, area, handle});
      // Keep the derivables on the worker so cfg/patch/resume commands work.
      Object.assign(state.worker, {gate, area, cfgFrame, replyArea, handle});
      state.worker.hipc2Abandoned = reason;
      await save();
      throw Error('hipc2 prepare abandoned (worker left parked, slot stuck this boot): ' + reason);
    };
    // Locate the tpidr field: cross-thread distinct pointers in the ring
    // structs whose +0x1f8 loads agree (the process-global hipc2 client ptr).
    // SAFETY (Jer6aO lesson): a raw s.read of an UNMAPPED derived address
    // (e.g. a size field that looked pointer-like) SEGFAULTS THE FS PROCESS
    // and kills the console. Every read below goes through safeRead, which
    // query-gates each address with the kernel memory query (never faults).
    // Every failure past this point rolls the parked worker back cleanly.
    try {
      // VkpjcN lesson: the query returns the containing malloc BLOCK — the
      // ThreadType sits mid-block, so requiring one region to cover the whole
      // read range rejects valid structs. Gate the range ENDS instead (both
      // must land in mapped regions); heap reads between mapped ends are safe.
      const safeRead = async (address, len) => {
        const mapped = async at => {
          const region = await s.rpc.query(at);
          return !region.result && !!region.type && Number(region.address) <= at &&
            Number(region.address) + Number(region.size) >= at + 8;
        };
        if (!await mapped(address) || !await mapped(address + len - 8)) return null;
        return await s.read(address, len);
      };
      const diag = entry => {state.hipc2Diag ||= []; state.hipc2Diag.push({at: new Date().toISOString(), ...entry}); return save();};
      const ringFile = path.join(__dirname, live.session + '-thread-ring.json');
      const ring = JSON.parse(require('node:fs').readFileSync(ringFile));
      // Use the SAME criteria as prepare-workers (unique 7-worker group by
      // common entry), not a naive first-3 slice — other threads share the
      // size/argument pattern but have different struct layouts.
      const groups = new Map();
      for (const node of ring.nodes.filter(t => t.state === 3 && t.size === 0xc000 && t.argument === 0)) {
        if (!groups.has(node.entry)) groups.set(node.entry, []);
        groups.get(node.entry).push(node);
      }
      const matches = [...groups.values()].filter(rows => rows.length === 7);
      check(matches.length === 1, 'Thread ring does not have the unique API-worker group');
      const structs = matches[0].slice(0, 3);
      await diag({step: 'ring-matched', nodes: structs.length});
      const structVals = [];
      for (let i = 0; i < structs.length; i++) {
        const node = structs[i];
        const raw = await safeRead(node.address, 0x1c0);
        check(raw, 'Thread ring struct ' + i + ' is not readable (query-gated)');
        await diag({step: 'ring-read', i, address: node.address});
        const vals = {};
        for (let o = 0; o + 8 <= 0x1c0; o += 8) {
          const v = raw.readBigUInt64LE(o);
          if (v > 0x10000n && v < 2n ** 40n && (v & 7n) === 0n) vals[o] = v;
        }
        structVals.push(vals);
      }
      await diag({step: 'ring-structs-done'});
      let tpidrOffset = -1, ringGlobal = 0n;
      for (const key of Object.keys(structVals[0])) {
        const off = Number(key);
        const vals = structVals.map(v => v[off]);
        if (vals.some(v => v === undefined) || new Set(vals.map(String)).size < 3) continue;
        const b1 = await safeRead(Number(vals[0]) + 0x1f8, 8);
        const b2 = await safeRead(Number(vals[1]) + 0x1f8, 8);
        if (!b1 || !b2) continue;
        const g1 = b1.readBigUInt64LE(), g2 = b2.readBigUInt64LE();
        if (g1 === g2 && g1 > 0x10000n && g1 < 2n ** 40n) { tpidrOffset = off; ringGlobal = g1; break; }
      }
      await diag({step: 'tpidr-scan-done', tpidrOffset});
      check(tpidrOffset >= 0, 'Could not locate the tpidr field in the thread structs');
      const wstruct = await safeRead(state.worker.thread, 0x1c0);
      check(wstruct, 'Worker thread struct is not readable');
      const tls = wstruct.readBigUInt64LE(tpidrOffset);
      check(tls > 0x10000n && tls < 2n ** 40n, 'Worker TLS pointer is implausible');
      const wTokenRaw = await safeRead(Number(tls) + 0x110, 8);
      const wGlobalRaw = await safeRead(Number(tls) + 0x1f8, 8);
      check(wTokenRaw && wGlobalRaw, 'Worker TLS is not readable');
      check(wTokenRaw.readBigUInt64LE() !== 0n && wGlobalRaw.readBigUInt64LE() === ringGlobal,
        'Worker TLS validation failed');
      await diag({step: 'worker-tls-validated', tls: tls.toString(), token: wTokenRaw.readBigUInt64LE().toString()});
      // Patch the parked worker's call-frame argument slots with its TLS.
      // With the leading wait(gate) as call0, the hipc2 calls are indices
      // 1,2,3: call1's arg0 (memcpy dst) = sp_0+0xe8; call2's arg0 (send
      // buffer) = sp_1+0xe8; call3's arg1 (memcpy src) = sp_3+0x10.
      const u64 = v => {const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return b;};
      const stack = state.worker.stackOffset;
      await s.write(state.worker.base + stack + 0xe8, u64(tls));            // call1 x0 (memcpy dst)
      await s.write(state.worker.base + stack + 0x140 + 0xe8, u64(tls));  // call2 x0 (send buffer)
      await s.write(state.worker.base + stack + 3 * 0x140 + 0x10, u64(tls)); // call3 x1 (memcpy src)
      Object.assign(state.worker, {kind: 'hipc2-send', handle, gate, area, cfgFrame, replyArea,
        tls: tls.toString(), tpidrOffset, ringGlobal: ringGlobal.toString(), released: false, count: 1});
      await save();
      return {thread: state.worker.thread, tls: tls.toString(), tpidrOffset, replyArea,
        base: state.worker.base, stackOffset: stack};
    } catch (prepareError) {
      await abandon(String(prepareError?.message || prepareError));
    }
  }
  if (command === 'worker-hipc2-cfg') {
    // Write the HIPC2 frame into the parked worker's config slot.
    check(state.worker && state.worker.hipc2Abandoned !== null && state.worker.hipc2Abandoned !== undefined,
      'No parked hipc2 worker');
    const area = state.worker.area ?? s.base + 0x2100000;
    const cfgFrame = state.worker.cfgFrame ?? area + 0x1000, replyArea = state.worker.replyArea ?? area + 0x1200;
    const frame = Buffer.from(request.frameHex || '', 'hex');
    check(frame.length === 0x100, 'HIPC2 frame must be 256 bytes');
    await s.write(cfgFrame, frame);
    await s.write(replyArea, Buffer.alloc(0x100));
    await save();
    return {written: true, cfgFrame, replyArea, handle: state.worker.handle};
  }
  if (command === 'worker-hipc2-patch') {
    // PC-side ring scan (memory.read — the boot's own proven primitive on
    // these exact structs) derived the worker's TLS; this command only
    // writes the three owned frame slots and re-arms the parked worker.
    check(state.worker && (state.worker.hipc2Abandoned !== null && state.worker.hipc2Abandoned !== undefined),
      'No parked hipc2 worker to patch (no abandon record)');
    const worker = state.worker;
    check(s.handles.has(worker.handle), 'Parked worker handle is no longer retained');
    const tls = BigInt(request.tls);
    check(tls > 0x10000n && tls < 2n ** 40n, 'Implausible TLS pointer');
    const u64 = v => {const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return b;};
    const stack = worker.stackOffset;
    await s.write(worker.base + stack + 0xe8, u64(tls));              // call1 x0 (memcpy dst)
    await s.write(worker.base + stack + 0x140 + 0xe8, u64(tls));      // call2 x0 (send buffer)
    await s.write(worker.base + stack + 3 * 0x140 + 0x10, u64(tls)); // call3 x1 (memcpy src)
    worker.hipc2Abandoned = null;
    worker.tls = tls.toString();
    await save();
    return {patched: true, thread: worker.thread, tls: tls.toString(), replyArea: worker.replyArea};
  }
  const worker = state.worker;
  check(worker && !worker.joined && s.threads.has(worker.thread), 'No active native worker');
  if (command === 'worker-discard-unreleased-launch') {
    check(worker.kind === 'pm-launch' && worker.launchTitle === '0x0400000000000037' &&
      worker.launchFlags === 0x10 && !worker.released, 'Only this unreleased helper launch may be discarded');
    const before = await s.readOwned(worker.area + 0x1000, 256);
    check(before.readUInt32LE() === 4 && before.toString('ascii', 16, 20) === 'SFCI' &&
      before.readUInt32LE(24) === 0, 'The pending request is not the prepared PM launch');
    // Replace the not-yet-issued launch with the read-only application-PID query.
    await s.write(worker.area + 0x1000, packet(6));
    worker.discardedLaunch = before.toString('hex'); await save();
    return {discarded: true};
  }
  if (command === 'worker-release') {
    check(!worker.released, 'Worker start gate was already released');
    check(!worker.hipc2Abandoned,
      'Worker was abandoned with an unpatched frame — releasing it would execute NULL-pointer calls');
    await events.signal(s, worker.gate);
    worker.released = true;
    await save();
    return {released: true};
  }
  if (command === 'worker-state' || command === 'worker-join') {
    const finished = await s.rpc.call3(live.sdk + workerCode.code.tryWait.offset, worker.thread, 0, 0);
    const raw = await s.readOwned(worker.base + worker.resultOffsets[0], worker.resultOffsets.length * 8);
    const values = worker.logicalResultIndices.map(i => raw.readBigUInt64LE(i * 8).toString());
    const result = {finished: !!finished, values, sentinel: workerCode.SENTINEL.toString()};
    if (command === 'worker-join') {
      check(finished, 'Worker is still pending');
      await native.join(s, worker, 1000);
      worker.results = worker.results.map(String);
      result.responses = [];
      for (let i = 0; i < worker.count; i++) {
        const raw = await s.readOwned(worker.area + 0x1000 * (i + 1), 256);
        if (values[i + 1] !== '0') { result.responses.push({transport: Number(values[i + 1]), raw: raw.toString('hex')}); continue; }
        if (worker.kind === 'app-service') {
          const handle = raw.readUInt32LE();
          check(handle > 0 && handle < 0xffff8000, 'Application SM returned no handle');
          s.handles.add(handle);
          state.services.push({name: worker.serviceName, handle, application: true});
          result.responses.push({result: 0, handle, raw: raw.subarray(0, 32).toString('hex')});
        } else if (worker.kind === 'sm-get') {
          check(raw.readUInt32LE() === 0x11 && raw.readUInt32LE(4) === 0x80000001 &&
            raw.readUInt32LE(8) === 0x20, 'Unexpected native SM reply');
          const handle = raw.readUInt32LE(12), status = raw.readUInt32LE(16);
          const reply = {result: status, handle, raw: raw.subarray(0, 32).toString('hex')};
          result.responses.push(reply);
          if (!status) {
            check(handle > 0, 'SM returned a null session');
            s.handles.add(handle);
            state.services.push({name: worker.serviceName, handle, sm: worker.handle});
          }
        } else {
          const reply = response(raw);
          if (worker.kind === 'notifier-probe') {
            for (const handle of [...reply.copies, ...reply.moves]) {
              s.handles.add(handle); state.events.push({handle, operation: 'notifier-probe'});
            }
          }
          if (worker.kind === 'control-test') {
            for (const handle of [...reply.copies, ...reply.moves]) {
              s.handles.add(handle);
              (state.domainCopies ||= []).push({handle, domainHandle: worker.handle, controlTest: true});
            }
          }
          const kernelPid = raw.readUInt32LE(4) >>> 31 && raw.readUInt32LE(8) & 1 ?
            raw.readBigUInt64LE(12).toString() : null;
          result.responses.push({...reply, kernelPid, data: reply.data.toString('hex'), raw: raw.toString('hex')});
          if (worker.processCommand === 0x524f0016 && !reply.result) {
            const length = Number(Buffer.from(worker.challenge, 'hex').readBigUInt64LE(16));
            check(Number(reply.data.readBigUInt64LE(48)) === length, 'RO bulk output length differs');
            const bulk = require(path.join(directory, 'bulk-transfer.cjs'));
            const data = await bulk.read(s, s.base + 0x1800000, length);
            const fs = require('node:fs/promises'), crypto = require('node:crypto');
            const outputFile = path.join(__dirname,
              live.session + '-ro-bulk-' + Date.now() + '.bin');
            await fs.writeFile(outputFile, data, {mode: 0o600});
            Object.assign(result.responses.at(-1), {outputFile, length,
              sha256: crypto.createHash('sha256').update(data).digest('hex')});
          }
        }
      }
      await events.finalize(s, worker.gate);
      worker.completion = result;
      await save();
    }
    return result;
  }
  throw Error('Unknown native worker command');
}

module.exports = {dispatch, cancelWorkers, cancelCode};
