// Ordinary IPC on a dedicated owned root, serialized by the memory controller.
const path = require('node:path');
const fs = require('node:fs/promises');
const crypto = require('node:crypto');
const {check, u64} = require("./session.cjs");
const source = require('node:fs').readFileSync(__filename);
const sourceHash = crypto.createHash('sha256').update(source).digest('hex');

function pathRequest(command, input, address, length) {
  const {packet} = require("../../shared/ipc.cjs");
  const bytes = packet(command, input), pointer = BigInt(address);
  bytes.writeUInt32LE(4 | (1 << 16));
  bytes.writeUInt32LE(Number((BigInt(length) << 16n) | ((pointer >> 36n) & 7n) << 6n |
    ((pointer >> 32n) & 15n) << 12n), 8);
  bytes.writeUInt32LE(Number(pointer & 0xffffffffn), 12);
  return bytes;
}

async function dispatch(context, request) {
  if (request.command.startsWith('root-native-')) {
    // Hot-reload the native dispatch chain per request so rig and worker
    // handlers can be edited live (mirrors fs-memory-control.freshRequire).
    // Purge JSON too: handler modules require manifests under ro/.
    for (const key of Object.keys(require.cache))
      if (key.includes('/ro/')) delete require.cache[key];
    return require("../ro/control.cjs").dispatch(context, request);
  }
  const {s, live, report, save, label} = context;
  const domain = require(path.join(__dirname, '../app/domain.cjs'));
  const state = report.ownedRoot ||= {session: live.session, clones: [], storages: [], probes: []};
  if (!state.implementations?.some(item => item.sha256 === sourceHash)) {
    const sourceFile = path.join(__dirname, label + '-root-control-' + sourceHash.slice(0, 12) + '.cjs');
    await fs.writeFile(sourceFile, source, {mode: 0o600});
    (state.implementations ||= state.implementation ? [state.implementation] : []).push({sourceFile, sha256: sourceHash});
    state.implementation = {sourceFile, sha256: sourceHash};
    await save();
  }
  if (request.command === 'root-info') return state;
  check(await s.ready(), 'The native bridge is not ready');

  if (request.command === 'root-capture-syscalls') {
    const offset = 0x158000;
    const bytes = await s.read(live.sdk + offset, 4096);
    const outputFile = path.join(__dirname, label + '-current-sdk-syscalls.bin');
    await fs.writeFile(outputFile, bytes, {mode: 0o600});
    state.syscalls = {offset, outputFile, sha256: crypto.createHash('sha256').update(bytes).digest('hex')};
    await save();
    return state.syscalls;
  }

  if (request.command === 'root-open') {
    if (state.clones.length) {
      // A server-closed session (unknown-command closes on fw23) must not wedge
      // root-open forever: probe with the proven-safe SetCurrentProcess shape,
      // rebuild from scratch when the peer is gone.
      let alive = true;
      try {
        await s.ipc('Dedicated root liveness re-initialize', state.clones[0], 1, u64(0), {pid: true});
      } catch (e) { alive = false; }
      if (alive) return {...state, recovered: false};
      state.clones = [];
      state.initialized = false;
      (state.recoveries ||= []).push({at: new Date().toISOString(), reason: 'root session closed by peer'});
      await save();
    }
    const handle = await s.openService('fsp-srv');
    state.clones.push(handle);
    state.initialized = false;
    state.created = new Date().toISOString();
    await save();
    if (request.initialize === false) return state;
  }

  check(state.clones.length && state.clones.every(handle => s.handles.has(handle)),
    'No dedicated root is retained');
  const root = state.clones[0];
  if (request.command === 'root-initialize' || request.command === 'root-open') {
    check(!state.initialized, 'The dedicated root is already initialized');
    const initialized = await s.ipc('Initialize dedicated PID-test root', root, 1, u64(0), {pid: true});
    check(!initialized.result, 'Dedicated root initialization failed');
    state.initialized = true;
    state.initializedAt = new Date().toISOString();
    await save();
    return state;
  }
  if (request.command === 'root-clones') {
    const count = Number(request.count);
    check(Number.isInteger(count) && count >= 1 && count <= 16, 'Root clone count must be 1..16');
    const before = state.clones.length;
    while (state.clones.length < count) {
      const reply = await domain.send(s, 'Clone dedicated PID-test root', root, domain.wire.control(2));
      state.clones.push(domain.oneHandle(reply));
      await save();
    }
    while (state.clones.length > count) {
      await s.close(state.clones.at(-1));
      state.clones.pop();
      await save();
    }
    const change = {at: new Date().toISOString(), before, after: count};
    (state.referenceChanges ||= []).push(change);
    await save();
    return {...change, handles: state.clones};
  }

  if (request.command === 'root-probe-bis') {
    check(state.initialized, 'Initialize the dedicated root before probing BIS');
    const id = Number(request.id);
    check(Number.isInteger(id) && id >= 0 && id <= 255, 'BIS identifier must be 0..255');
    const existing = state.storages.find(item => item.id === id && s.handles.has(item.handle));
    if (existing) {
      const size = (await domain.storageSize(s, existing.handle)).toString();
      return {at: new Date().toISOString(), id, result: 0, opened: true, reused: true,
        handle: existing.handle, size};
    }
    const input = Buffer.alloc(4); input.writeUInt32LE(id);
    const reply = await s.ipc('Dedicated root OpenBisStorage ' + id, root, 12, input);
    const probe = {at: new Date().toISOString(), id, result: reply.canonicalResult, opened: !reply.result};
    state.probes.push(probe);
    await save();
    if (!reply.result) {
      probe.handle = domain.oneHandle(reply);
      const storage = {id, handle: probe.handle};
      state.storages.push(storage);
      await save();
      storage.size = (await domain.storageSize(s, storage.handle)).toString();
      probe.size = storage.size;
      await save();
    }
    return probe;
  }

  if (request.command === 'root-read-bis') {
    const id = Number(request.id), offset = Number(request.offset ?? 0), length = Number(request.length ?? 4096);
    const storage = state.storages.find(item => item.id === id && s.handles.has(item.handle));
    check(storage && Number.isSafeInteger(offset) && offset >= 0 && Number.isInteger(length) && length > 0 &&
      length <= 0x4000 && BigInt(offset + length) <= BigInt(storage.size), 'Invalid retained BIS read');
    const reply = await context.readStorage(storage.handle, length, offset, 0xa5);
    check(!reply.result && reply.bytes?.length === length, 'BIS read failed');
    const outputFile = path.join(__dirname, label + '-bis-' + id + '-' + offset + '-' + length + '.bin');
    await fs.writeFile(outputFile, reply.bytes, {mode: 0o600});
    const read = {at: new Date().toISOString(), id, offset, length, outputFile,
      sha256: crypto.createHash('sha256').update(reply.bytes).digest('hex')};
    (state.reads ||= []).push(read);
    await save();
    return read;
  }

  if (request.command === 'root-ping') {
    return {pong: new Date().toISOString(), mark: 'rootlist-v7'};
  }

  // Shared helpers for BIS filesystem commands (USER 30 / SYSTEM 31).
  async function bisFilesystem(id) {
    check(state.initialized, 'Initialize the dedicated root before BIS commands');
    check(id === 30 || id === 31, 'BIS commands support USER (30) and SYSTEM (31)');
    const existing = state.filesystems?.find(item => item.id === id && s.handles.has(item.handle));
    check(existing, 'Open the BIS filesystem first with root-probe-bis-filesystem');
    return existing.handle;
  }
  async function bisStagePath(filePath) {
    const staged = Buffer.alloc(0x301);
    Buffer.from(filePath, 'utf8').copy(staged);
    await context.put(context.input, staged);
  }
  const bisDataAddr = () => {
    // Staging must stay clear of the live worker ring (b+0x100000..0x240000):
    // the probe's big-write region at b+0x1000000 is idle once waves are done.
    return s.base + 0x1000000;
  };
  if (request.command === 'root-hipc2-stage') {
    // Stage an HIPC2 request frame (doubles as the reply buffer) in the
    // idle big-write region. The fs-side svc-0x22 stub sends it in-place.
    const bytes = Buffer.from(request.hex ?? '', 'hex');
    check(bytes.length >= 8 && bytes.length <= 0x1000 && bytes.length % 8 === 0,
      'The staged frame must be 8..0x1000 bytes, 8-aligned');
    const address = bisDataAddr();
    await s.write(address, bytes);
    const entry = {at: new Date().toISOString(), operation: request.command,
      address: address.toString(), bytes: bytes.length};
    (state.calls ||= []).push(entry);
    await save();
    return entry;
  }
  if (request.command === 'root-hipc2-fetch') {
    // Fetch the staged frame back (the svc 0x22 reply lands in-place).
    const address = Number(request.address), length = Number(request.length);
    check(Number.isSafeInteger(address) && address >= 0x1000 && Number.isInteger(length) &&
      length > 0 && length <= 0x1000, 'Invalid hipc2 fetch span');
    const bytes = await s.readOwned(address, length);
    const entry = {at: new Date().toISOString(), operation: request.command, address, length};
    (state.calls ||= []).push(entry);
    await save();
    return {address, length, hex: bytes.toString('hex')};
  }


  if (request.command === 'root-list-save') {
    check(state.initialized, 'Initialize the dedicated root before save listings');
    const dirPath = String(request.path ?? '/');
    check(dirPath.startsWith('/') && !dirPath.includes('..') && Buffer.byteLength(dirPath) < 0x300,
      'Invalid save path');
    const saveFs = await require('../app/mounted-save.cjs').cloneMountedFilesystem(s, 'save');
    await bisStagePath(dirPath);
    const input = Buffer.alloc(4); input.writeUInt32LE(3);
    const opened = await domain.send(s, 'Save OpenDirectory ' + dirPath, saveFs,
      pathRequest(9, input, context.input, 0x301));
    check(!opened.result, 'Save OpenDirectory failed: 0x' + (opened.result ?? 0).toString(16));
    const directory = domain.oneHandle(opened);
    const entries = [];
    try {
      for (let batch = 0; batch < 64 && entries.length < 256; batch++) {
        const reply = await s.ipc('Save ReadDirectory ' + dirPath, directory, 0, Buffer.alloc(0),
          {receive: [{address: bisDataAddr(), size: 4 * 0x310, mode: 0}]});
        check(!reply.result, 'Save ReadDirectory failed: 0x' + (reply.result ?? 0).toString(16));
        const count = Number(reply.data.readBigUInt64LE());
        check(count >= 0 && count <= 4, 'Unexpected save directory batch');
        if (!count) break;
        const bytes = await s.read(bisDataAddr(), count * 0x310);
        for (let i = 0; i < count; i++) {
          const entry = bytes.subarray(i * 0x310, (i + 1) * 0x310);
          const name = entry.subarray(0, 0x301).toString('utf8').split('\0')[0];
          entries.push({name, type: entry[0x304], size: entry.readBigUInt64LE(0x308).toString()});
        }
      }
    } finally { await s.close(directory); }
    await save();
    return {path: dirPath, entries};
  }

  if (request.command === 'root-write-save-file') {
    // Write a file into the app's own save mount (journal-committed), e.g.
    // /f/###/TNS2. Read-back verified; the save filesystem Commit is mandatory.
    check(state.initialized, 'Initialize the dedicated root before save writes');
    const filePath = String(request.path ?? '');
    check(filePath.startsWith('/f/###/') && !filePath.includes('..') &&
      Buffer.byteLength(filePath) < 0x300, 'Save writes are restricted to /f/###/');
    const bytes = Buffer.from(request.hex ?? '', 'hex');
    check(bytes.length > 0 && bytes.length <= 0x20000, 'Save write payload is 1..128 KiB');
    const dataAddr = bisDataAddr();
    await s.write(dataAddr, bytes);

    const saveFs = await require('../app/mounted-save.cjs').cloneMountedFilesystem(s, 'save');
    await bisStagePath(filePath);
    // CreateFile first (0-based command 0); 0x402 = already exists.
    const createInput = Buffer.concat([u64(bytes.length), Buffer.alloc(8)]);
    const created = await domain.send(s, 'Save CreateFile ' + filePath, saveFs,
      pathRequest(0, createInput, context.input, 0x301));
    check(created.result === 0 || [2, 0x402].includes(created.result >>> 0),
      'Save CreateFile failed: 0x' + (created.result ?? 0).toString(16));
    await bisStagePath(filePath);
    const opened = await domain.send(s, 'Save OpenFile write ' + filePath, saveFs,
      pathRequest(8, Buffer.from([3, 0, 0, 0]), context.input, 0x301));
    check(!opened.result, 'Save OpenFile(write) failed: 0x' + (opened.result ?? 0).toString(16));
    const fileHandle = domain.oneHandle(opened);
    try {
      const sized = await s.ipc('Save SetSize ' + filePath, fileHandle, 3, u64(bytes.length));
      check(!sized.result, 'Save SetSize failed: 0x' + (sized.result ?? 0).toString(16));
      const written = await s.ipc('Save WriteFile ' + filePath, fileHandle, 1,
        Buffer.concat([u64(0), u64(0), u64(bytes.length)]),
        {send: [{address: dataAddr, size: bytes.length, mode: 1}]});
      check(!written.result, 'Save WriteFile failed: 0x' + (written.result ?? 0).toString(16));
      const flushed = await s.ipc('Save Flush ' + filePath, fileHandle, 2, Buffer.alloc(0));
      check(!flushed.result, 'Save Flush failed: 0x' + (flushed.result ?? 0).toString(16));
    } finally { await s.close(fileHandle); }
    // The savedata journal requires the filesystem-level commit.
    const commit = await s.ipc('Save Commit ' + filePath, saveFs, 10, Buffer.alloc(0));
    check(!commit.result, 'Save Commit failed: 0x' + (commit.result ?? 0).toString(16));

    await bisStagePath(filePath);
    const verify = await domain.send(s, 'Save OpenFile read ' + filePath, saveFs,
      pathRequest(8, Buffer.from([1, 0, 0, 0]), context.input, 0x301));
    check(!verify.result, 'Save OpenFile(read) failed: 0x' + (verify.result ?? 0).toString(16));
    const readHandle = domain.oneHandle(verify);
    let readback;
    try {
      const reply = await s.ipc('Save ReadFile ' + filePath, readHandle, 0,
        Buffer.concat([u64(0), u64(0), u64(bytes.length)]),
        {receive: [{address: dataAddr, size: bytes.length, mode: 1}]});
      check(!reply.result, 'Save ReadFile failed: 0x' + (reply.result ?? 0).toString(16));
      readback = await s.read(dataAddr, bytes.length);
    } finally { await s.close(readHandle); }
    const record = {at: new Date().toISOString(), path: filePath, bytes: bytes.length,
      sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
      readSha256: crypto.createHash('sha256').update(readback).digest('hex'),
      verified: readback.equals(bytes)};
    (state.saveWrites ||= []).push(record);
    await save();
    check(record.verified, 'Save read-back differs from the written bytes');
    return record;
  }

  if (request.command === 'root-list-romfs') {
    // Read-only enumeration of any mounted content filesystem (RomFS handles
    // opened via root-native-ipc, e.g. OpenDataFileSystemByCurrentProcess as
    // the running app). Mirrors root-list-bis but takes a raw handle.
    const fsHandle = Number(request.handle);
    check(s.handles.has(fsHandle), 'RomFS listing requires a retained filesystem handle');
    const dirPath = String(request.path ?? '/');
    check(dirPath.startsWith('/') && !dirPath.includes('\0') && !dirPath.includes('..') && Buffer.byteLength(dirPath) < 0x300,
      'Invalid RomFS directory path');
    await bisStagePath(dirPath);
    const input = Buffer.alloc(4); input.writeUInt32LE(3);
    const openPacket = pathRequest(9, input, context.input, 0x301);
    await s.write(s.base, openPacket);
    const openTransport = await s.call('send', s.base, 4096, fsHandle);
    check(!openTransport, 'RomFS OpenDirectory transport failed');
    const openRaw = await s.readOwned(s.base, 256);
    const opened = require("../../shared/ipc.cjs").response(openRaw);
    for (const child of opened.moves) s.handles.add(child);
    check(!opened.result, 'RomFS OpenDirectory failed: 0x' + (opened.result ?? 0).toString(16));
    const directory = opened.moves[0];
    const entries = [];
    try {
      for (let batch = 0; batch < 64 && entries.length < 256; batch++) {
        const reply = await s.ipc('RomFS ReadDirectory ' + dirPath, directory, 0, Buffer.alloc(0),
          {receive: [{address: bisDataAddr(), size: 4 * 0x310, mode: 0}]});
        check(!reply.result, 'RomFS ReadDirectory failed: 0x' + (reply.result ?? 0).toString(16));
        const count = Number(reply.data.readBigUInt64LE());
        check(count >= 0 && count <= 4, 'Unexpected RomFS directory batch');
        if (!count) break;
        const bytes = await s.readOwned(bisDataAddr(), count * 0x310);
        for (let i = 0; i < count; i++) {
          const entry = bytes.subarray(i * 0x310, (i + 1) * 0x310);
          const name = entry.subarray(0, 0x301).toString('utf8').split('\0')[0];
          check(name && !name.includes('/') && !name.includes('\\'), 'Unexpected RomFS entry name');
          entries.push({name, type: entry[0x304], size: entry.readBigUInt64LE(0x308).toString()});
        }
      }
    } finally { await s.close(directory); }
    (state.romfsListings ||= []).push({at: new Date().toISOString(), handle: fsHandle, path: dirPath, count: entries.length});
    await save();
    return {handle: fsHandle, path: dirPath, entries};
  }

  if (request.command === 'root-list-bis') {
    // Read-only enumeration of an open BIS filesystem.
    const id = Number(request.id);
    const fsHandle = await bisFilesystem(id);
    const dirPath = String(request.path ?? '/');
    check(dirPath.startsWith('/') && !dirPath.includes('\0') && Buffer.byteLength(dirPath) < 0x300,
      'Invalid BIS directory path');
    await bisStagePath(dirPath);
    const input = Buffer.alloc(4); input.writeUInt32LE(3);
    const opened = await domain.send(s, 'BIS OpenDirectory ' + id + ' ' + dirPath, fsHandle,
      pathRequest(9, input, context.input, 0x301));
    check(!opened.result, 'BIS OpenDirectory failed: 0x' + (opened.result ?? 0).toString(16));
    const directory = domain.oneHandle(opened);
    const entries = [];
    try {
      for (let batch = 0; batch < 64 && entries.length < 256; batch++) {
        const reply = await s.ipc('BIS ReadDirectory ' + id, directory, 0, Buffer.alloc(0),
          {receive: [{address: bisDataAddr(), size: 4 * 0x310, mode: 0}]});
        check(!reply.result, 'BIS ReadDirectory failed: 0x' + (reply.result ?? 0).toString(16));
        const count = Number(reply.data.readBigUInt64LE());
        check(count >= 0 && count <= 4, 'Unexpected BIS directory batch');
        if (!count) break;
        const bytes = await s.read(bisDataAddr(), count * 0x310);
        for (let i = 0; i < count; i++) {
          const entry = bytes.subarray(i * 0x310, (i + 1) * 0x310);
          const name = entry.subarray(0, 0x301).toString('utf8').split('\0')[0];
          check(name && !name.includes('/') && !name.includes('\\'), 'Unexpected BIS entry name');
          entries.push({name, type: entry[0x304], size: entry.readBigUInt64LE(0x308).toString()});
        }
      }
    } finally { await s.close(directory); }
    (state.bisListings ||= []).push({at: new Date().toISOString(), id, path: dirPath, count: entries.length});
    await save();
    return {id, path: dirPath, entries};
  }

  if (request.command === 'root-mkdir-bis') {
    const id = Number(request.id);
    check(id === 30 || (id === 31 && request.system === true),
      'BIS mkdir: USER (30) only unless request.system is true');
    const dirPath = String(request.path ?? '');
    check(dirPath.startsWith('/') && !dirPath.includes('..') && Buffer.byteLength(dirPath) < 0x300,
      'Invalid BIS directory path');
    check(id !== 30 || dirPath.startsWith('/temp/'), 'USER directories are restricted to /temp/');
    const fsHandle = await bisFilesystem(id);
    await bisStagePath(dirPath);
    // CreateDirectory = command 2 (0-based).
    const created = await domain.send(s, 'BIS CreateDirectory ' + dirPath, fsHandle,
      pathRequest(2, Buffer.alloc(0), context.input, 0x301));
    const result = created.canonicalResult;
    check(result === 0 || [2, 0x402].includes(result >>> 0),
      'BIS CreateDirectory failed: 0x' + (result ?? 0).toString(16));
    const listing = (state.bisListings ||= []).slice(-1);
    await save();
    return {id, path: dirPath, createResult: result};
  }

  if (request.command === 'root-delete-bis-file') {
    const id = Number(request.id);
    check(id === 30 || (id === 31 && request.system === true),
      'BIS delete: USER (30) only unless request.system is true');
    const filePath = String(request.path ?? '');
    check(id !== 30 || filePath.startsWith('/temp/'), 'USER deletes are restricted to /temp/');
    const fsHandle = await bisFilesystem(id);
    await bisStagePath(filePath);
    // DeleteFile = command 1 (0-based).
    const deleted = await domain.send(s, 'BIS DeleteFile ' + filePath, fsHandle,
      pathRequest(1, Buffer.alloc(0), context.input, 0x301));
    check(!deleted.result, 'BIS DeleteFile failed: 0x' + (deleted.result ?? 0).toString(16));
    const commit = await s.ipc('BIS Commit after delete', fsHandle, 10, Buffer.alloc(0));
    check(!commit.result, 'BIS Commit failed: 0x' + (commit.result ?? 0).toString(16));
    await save();
    return {id, path: filePath, deleted: true};
  }

  if (request.command === 'root-read-romfs-file') {
    // Read a file from a mounted content filesystem (RomFS handle from
    // root-native-ipc). Mirrors root-read-bis-file with offset support for
    // multi-chunk capture of large files.
    const fsHandle = Number(request.handle);
    check(s.handles.has(fsHandle), 'RomFS read requires a retained filesystem handle');
    const filePath = String(request.path ?? '');
    check(filePath.startsWith('/') && !filePath.includes('..') && Buffer.byteLength(filePath) < 0x300,
      'Invalid RomFS file path');
    const offset = BigInt(request.offset ?? 0);
    const length = Math.min(Number(request.length ?? 0x1000), 0x40000);
    check(offset >= 0n && length > 0, 'Invalid RomFS read range');
    await bisStagePath(filePath);
    const openPacket = pathRequest(8, Buffer.from([1, 0, 0, 0]), context.input, 0x301);
    await s.write(s.base, openPacket);
    const openTransport = await s.call('send', s.base, 4096, fsHandle);
    check(!openTransport, 'RomFS OpenFile transport failed');
    const openRaw = await s.readOwned(s.base, 256);
    const opened = require("../../shared/ipc.cjs").response(openRaw);
    for (const child of opened.moves) s.handles.add(child);
    check(!opened.result, 'RomFS OpenFile(read) failed: 0x' + (opened.result ?? 0).toString(16));
    const fileHandle = opened.moves[0];
    let bytes;
    try {
      const reply = await s.ipc('RomFS ReadFile ' + filePath, fileHandle, 0,
        Buffer.concat([u64(0), u64(offset), u64(length)]),
        {receive: [{address: bisDataAddr(), size: length, mode: 1}]});
      check(!reply.result, 'RomFS ReadFile failed: 0x' + (reply.result ?? 0).toString(16));
      bytes = await s.read(bisDataAddr(), length);
    } finally { await s.close(fileHandle); }
    (state.romfsReads ||= []).push({at: new Date().toISOString(), handle: fsHandle,
      path: filePath, offset: offset.toString(), length});
    await save();
    return {handle: fsHandle, path: filePath, offset: offset.toString(), length,
      sha256: crypto.createHash('sha256').update(bytes).digest('hex'), bytes: bytes.toString('hex')};
  }

  if (request.command === 'root-read-bis-file') {
    const id = Number(request.id);
    const fsHandle = await bisFilesystem(id);
    const filePath = String(request.path ?? '');
    check(filePath.startsWith('/') && !filePath.includes('..') && Buffer.byteLength(filePath) < 0x300,
      'Invalid BIS file path');
    const length = Math.min(Number(request.length ?? 0x1000), 0x40000);
    await bisStagePath(filePath);
    const opened = await domain.send(s, 'BIS OpenFile read ' + filePath, fsHandle,
      pathRequest(8, Buffer.from([1, 0, 0, 0]), context.input, 0x301));
    check(!opened.result, 'BIS OpenFile(read) failed: 0x' + (opened.result ?? 0).toString(16));
    const fileHandle = domain.oneHandle(opened);
    let bytes;
    try {
      const reply = await s.ipc('BIS ReadFile ' + filePath, fileHandle, 0,
        Buffer.concat([u64(0), u64(0), u64(length)]),
        {receive: [{address: bisDataAddr(), size: length, mode: 1}]});
      check(!reply.result, 'BIS ReadFile failed: 0x' + (reply.result ?? 0).toString(16));
      bytes = await s.read(bisDataAddr(), length);
    } finally { await s.close(fileHandle); }
    return {id, path: filePath, length, sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
      headHex: bytes.toString('hex').slice(0, 256), bytes: bytes.toString('hex')};
  }

  if (request.command === 'root-write-bis-file') {
    // Write a file on an open BIS filesystem with read-back verification.
    // USER (30) is restricted to /temp/ until write behavior is proven.
    const id = Number(request.id);
    check(id === 30 || (id === 31 && request.system === true),
      'BIS writes: USER (30) only unless request.system is true');
    const filePath = String(request.path ?? '');
    check(filePath.startsWith('/') && !filePath.includes('..') && Buffer.byteLength(filePath) < 0x300,
      'Invalid BIS file path');
    check(id !== 30 || filePath.startsWith('/temp/'), 'USER writes are restricted to /temp/');
    const bytes = Buffer.from(request.hex ?? '', 'hex');
    check(bytes.length > 0 && bytes.length <= 0x40000, 'Write payload is 1..256 KiB');
    const fsHandle = await bisFilesystem(id);
    const dataAddr = bisDataAddr();
    const record = {at: new Date().toISOString(), id, path: filePath, bytes: bytes.length};

    await bisStagePath(filePath);
    // FsFileSystem commands are 0-based: 0=CreateFile, 1=DeleteFile.
    const createInput = Buffer.concat([u64(bytes.length), Buffer.alloc(8)]);
    const created = await domain.send(s, 'BIS CreateFile ' + filePath, fsHandle,
      pathRequest(0, createInput, context.input, 0x301));
    record.createResult = created.canonicalResult;
    check(created.result === 0 || [2, 0x402].includes(created.result >>> 0),
      'BIS CreateFile failed: 0x' + (created.result ?? 0).toString(16));

    const openInput = Buffer.alloc(4); openInput.writeUInt32LE(3);
    const opened = await domain.send(s, 'BIS OpenFile write ' + filePath, fsHandle,
      pathRequest(8, openInput, context.input, 0x301));
    check(!opened.result, 'BIS OpenFile(write) failed: 0x' + (opened.result ?? 0).toString(16));
    const fileHandle = domain.oneHandle(opened);
    try {
      const sized = await s.ipc('BIS SetSize ' + filePath, fileHandle, 3, u64(bytes.length));
      check(!sized.result, 'BIS SetSize failed: 0x' + (sized.result ?? 0).toString(16));
      await s.write(dataAddr, bytes);
      // IFile WriteFile input matches the verified read shape: (0, offset, size).
      const written = await s.ipc('BIS WriteFile ' + filePath, fileHandle, 1,
        Buffer.concat([u64(0), u64(0), u64(bytes.length)]),
        {send: [{address: dataAddr, size: bytes.length, mode: 1}]});
      check(!written.result, 'BIS WriteFile failed: 0x' + (written.result ?? 0).toString(16));
      const flushed = await s.ipc('BIS Flush ' + filePath, fileHandle, 2, Buffer.alloc(0));
      check(!flushed.result, 'BIS Flush failed: 0x' + (flushed.result ?? 0).toString(16));
    } finally { await s.close(fileHandle); }
    // Commit the filesystem journal: without it the written cluster stays in
    // the journal and reads of a freshly allocated file resolve stale content.
    const commit = await s.ipc('BIS Commit ' + filePath, fsHandle, 10, Buffer.alloc(0));
    check(!commit.result, 'BIS Commit failed: 0x' + (commit.result ?? 0).toString(16));
    record.committed = true;

    await bisStagePath(filePath);
    const verify = await domain.send(s, 'BIS OpenFile read ' + filePath, fsHandle,
      pathRequest(8, Buffer.from([1, 0, 0, 0]), context.input, 0x301));
    check(!verify.result, 'BIS OpenFile(read) failed: 0x' + (verify.result ?? 0).toString(16));
    const readHandle = domain.oneHandle(verify);
    let readback;
    try {
      const reply = await s.ipc('BIS ReadFile ' + filePath, readHandle, 0,
        Buffer.concat([u64(0), u64(0), u64(bytes.length)]),
        {receive: [{address: dataAddr, size: bytes.length, mode: 1}]});
      check(!reply.result, 'BIS ReadFile failed: 0x' + (reply.result ?? 0).toString(16));
      readback = await s.read(dataAddr, bytes.length);
    } finally { await s.close(readHandle); }
    record.sha256 = crypto.createHash('sha256').update(bytes).digest('hex');
    record.readSha256 = crypto.createHash('sha256').update(readback).digest('hex');
    record.verified = readback.equals(bytes);
    (state.bisWrites ||= []).push(record);
    await save();
    check(record.verified, 'BIS read-back differs from the written bytes');
    return record;
  }

  if (request.command === 'root-content-path') {
    // ns:am2 GetApplicationContentPath (cmd 21): canonical NCA path for a
    // title's content ("@UserContent://..." on fw23). Returns the patch
    // variant when an update is installed. Buffer-backed receive IPC.
    check(state.initialized, 'Initialize the dedicated root first');
    const contentType = Number(request.contentType ?? 2);
    const tid = String(request.tid);
    check(Number.isInteger(contentType) && contentType >= 0 && contentType <= 8, 'Invalid content type');
    if (!state.nsAm2 || !s.handles.has(state.nsAm2)) {
      state.nsAm2 = await s.openService('ns:am2');
      await save();
    }
    const u64b = v => {const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return b;};
    const shape = String(request.shape ?? 'A');
    const input = shape === 'C' ? Buffer.concat([Buffer.from([contentType]), u64b(tid)])
      : shape === 'B' ? Buffer.concat([u64b(tid), Buffer.from([contentType]), Buffer.alloc(7)])
      : Buffer.concat([Buffer.from([contentType]), Buffer.alloc(7), u64b(tid)]);
    let reply;
    try {
      reply = await s.ipc('ns:am2 GetApplicationContentPath ct=' + contentType + ' tid=' + tid,
        state.nsAm2, 21, input, {receive: [{address: bisDataAddr(), size: 0x301, mode: 1}]});
    } catch (e) {
      state.nsAm2 = null; await save();
      throw e;
    }
    if (reply.result) return {contentType, shape, result: reply.result, canonical: reply.canonicalResult};
    const bytes = await s.read(bisDataAddr(), 0x301);
    const path = bytes.toString('utf8').split('\0')[0];
    (state.contentPaths ||= []).push({at: new Date().toISOString(), tid, contentType, shape, path});
    await save();
    return {contentType, shape, result: 0, path, headHex: bytes.subarray(0, 96).toString('hex')};
  }

  if (request.command === 'root-mount-content') {
    // fsp-srv cmd 10 OpenFileSystemWithId (16.0+ layout): {u8 attr, u32 fsType,
    // u64 id} + path buffer. The caller is the takeover-host process, so the
    // mount is judged by fs's own content resolution, not an app's rights.
    check(state.initialized && state.clones.length, 'No dedicated root is retained');
    const fsType = Number(request.fsType ?? 6);
    const attr = Number(request.attr ?? 0);
    const tid = String(request.tid ?? '0');
    const contentPath = String(request.path ?? '');
    check(contentPath.length > 3 && contentPath.length < 0x300, 'Invalid content path');
    await bisStagePath(contentPath);
    const cmdId = Number(request.cmdId ?? 10);
    let input, wire;
    if (cmdId === 618 || cmdId === 609) {
      // GetProgramId / GetRightsIdByPath: {u8 attr} inline + X path buffer.
      input = Buffer.alloc(8);
      input.writeUInt8(attr, 0);
    } else if (cmdId === 8) {
      // pre-16.0 shape: {u32 fsType @0; u64 id @4}, 12 bytes packed.
      input = Buffer.alloc(12);
      input.writeUInt32LE(fsType, 0);
      input.writeBigUInt64LE(BigInt(tid), 4);
    } else {
      input = Buffer.alloc(16);
      input.writeUInt8(attr, 0);
      input.writeUInt32LE(fsType, 4);
      input.writeBigUInt64LE(BigInt(tid), 8);
    }
    const reply = await domain.send(s, 'fsp-srv OpenFileSystemWithId cmd' + cmdId + ' tid=' + tid + ' type=' + fsType + ' attr=' + attr,
      root, pathRequest(cmdId, input, context.input, 0x301));
    if (reply.result) return {result: reply.result, canonical: reply.canonicalResult, fsType, attr, tid, cmdId};
    if (cmdId === 618) {
      // u64 program id inline in the reply.
      return {result: 0, cmdId, attr, path: contentPath,
        programId: '0x' + reply.data.readBigUInt64LE().toString(16), raw: reply.data.subarray(0, 16).toString('hex')};
    }
    if (cmdId === 609) {
      return {result: 0, cmdId, attr, path: contentPath, raw: reply.data.subarray(0, 32).toString('hex')};
    }
    const handle = domain.oneHandle(reply);
    const record = {at: new Date().toISOString(), tid, fsType, attr, path: contentPath, handle};
    (state.contentMounts ||= []).push(record);
    await save();
    if (request.prove !== false) {
      try {
        await bisStagePath('/');
        const opened = await domain.send(s, 'Content OpenDirectory /', handle,
          pathRequest(9, Buffer.from([3, 0, 0, 0]), context.input, 0x301));
        record.openResult = opened.canonicalResult;
        if (!opened.result) {
          const directory = domain.oneHandle(opened);
          const listed = await s.ipc('Content ReadDirectory', directory, 0, Buffer.alloc(0),
            {receive: [{address: bisDataAddr(), size: 4 * 0x310, mode: 0}]});
          if (!listed.result) {
            const count = Number(listed.data.readBigUInt64LE());
            record.count = count;
            record.entries = [];
            if (count > 0) {
              const bytes = await s.read(bisDataAddr(), Math.min(count, 4) * 0x310);
              for (let i = 0; i < Math.min(count, 4); i++) {
                const e = bytes.subarray(i * 0x310, (i + 1) * 0x310);
                record.entries.push({name: e.subarray(0, 0x301).toString('utf8').split('\0')[0], type: e[0x304]});
              }
            }
          } else record.readResult = listed.canonicalResult;
          await s.close(directory);
        }
      } catch (e) { record.proveError = String(e.message || e).slice(0, 160); }
      await save();
    }
    return {...record, result: 0};
  }

  if (request.command === 'root-reopen-candidate') {
    // Reopen the controlled cache slot over the canary (resume-style) and
    // verify the primed content. Restores the retained endpoint after an
    // emergency disarm.
    check(state.initialized && state.clones.length, 'No dedicated root is retained');
    const root = state.clones[0];
    const reopened = await s.ipc('Reuse the canary slot with own content', root, 200);
    check(!reopened.result, 'Candidate reopen failed: 0x' + (reopened.result ?? 0).toString(16));
    const handle = domain.oneHandle(reopened);
    const prime = await context.readStorage(handle, 16);
    const expected = report.cacheAlias?.expectedAliasHex;
    check(!prime.result && prime.bytes?.toString('hex') === expected,
      'The reopened candidate content differs from the recorded alias control');
    await save();
    return {reopened: true, handle, prime: prime.bytes.toString('hex')};
  }

  if (request.command === 'root-probe-bis-filesystem') {
    check(state.initialized, 'Initialize the dedicated root before probing BIS');
    const id = Number(request.id);
    check([30, 31].includes(id), 'This read-only probe supports USER and SYSTEM');
    const existing = state.filesystems?.find(item => item.id === id && s.handles.has(item.handle));
    const probe = {at: new Date().toISOString(), kind: 'filesystem', id};
    if (existing) Object.assign(probe, {result: 0, opened: true, reused: true, handle: existing.handle});
    else {
      const input = Buffer.alloc(4); input.writeUInt32LE(id);
      // The BIS mount-name parameter: an empty string by default (historic
      // behavior), or a caller-chosen name when request.mountName is set —
      // the name becomes addressable in fs paths (cmd 10 path tests).
      const labelBuf = Buffer.alloc(0x301);
      if (request.mountName) {
        check(/^[A-Za-z0-9]{1,8}$/.test(String(request.mountName)), 'Invalid BIS mount name');
        labelBuf.write(String(request.mountName));
      }
      await context.put(context.input, labelBuf);
      const reply = await domain.send(s, 'Dedicated root OpenBisFileSystem ' + id, root,
        pathRequest(11, input, context.input, 0x301));
      Object.assign(probe, {result: reply.canonicalResult, opened: !reply.result});
      if (!reply.result) {
        probe.handle = domain.oneHandle(reply);
        (state.filesystems ||= []).push({id, handle: probe.handle});
      }
    }
    state.probes.push(probe);
    await save();
    if (probe.opened) {
      const rootPath = Buffer.alloc(0x301); rootPath.write('/');
      await context.put(context.input, rootPath);
      const entry = await domain.send(s, 'BIS root GetEntryType ' + id, probe.handle,
        pathRequest(7, Buffer.alloc(0), context.input, 0x301));
      probe.entryResult = entry.canonicalResult;
      if (!entry.result) probe.entryType = entry.data.readUInt32LE();
      await save();
    }
    return probe;
  }
  throw Error('Unknown dedicated-root command');
}

module.exports = {dispatch};
