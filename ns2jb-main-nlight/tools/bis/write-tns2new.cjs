// Write the forged v8 console program (rich logging) as /f/###/TNS2NEW.
// Based on the proven probe-save-update.cjs write path (Flush, no journal
// commit on the cloned session — the journal-commit path wedged once).
// The original TNS2 is never touched. Resolves the latest session dynamically.
'use strict';
const fs = require('node:fs/promises');
const fsSync = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const latest = JSON.parse(fsSync.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json'), 'utf8'));
const runDir = path.resolve(latest.directory, 'switch2');
const session = require(runDir + '/memory/session.cjs');
const mounted = require(runDir + '/app/mounted-save.cjs');
const filesys = require(runDir + '/app/filesystem.cjs');
const {u64} = require(runDir + '/memory/session.cjs');

const TNS2NEW = '/f/###/TNS2NEW';
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

async function main() {
  const forge = process.argv[2] ||
    path.join(runDir, 'forged-TNS2NEW-v11.bin');
  const newBytes = await fs.readFile(forge);
  console.log('source:', forge, '(' + newBytes.length + ' bytes, sha256 ' + hash(newBytes).slice(0, 16) + ')');
  const {s} = await session.connect('tns2new-write', 0x40000);
  const handles = [];
  try {
    s.bulkDownloads = false;
    const saveFs = await mounted.cloneMountedFilesystem(s, 'save');
    handles.push(saveFs);

    async function putString(address, text) {
      const bytes = Buffer.from(text, 'utf8');
      const buffer = Buffer.alloc(0x304);
      bytes.copy(buffer);
      await s.write(address, buffer);
      return bytes.length + 1;
    }

    async function createFile(pathname, size) {
      const pathLen = await putString(s.base + 0x2000, pathname);
      const reply = await s.ipc('CreateFile ' + pathname, saveFs, 1,
        Buffer.concat([u64(size), Buffer.alloc(8)]),
        {send: [{address: s.base + 0x2000, size: pathLen, mode: 1}]});
      return reply.result;
    }

    async function openForWrite(pathname) {
      const {u32} = require(runDir + '/app/session.cjs');
      const reply = await filesys.openFile(s, saveFs, pathname, u32(3)); // read+write
      return reply;
    }

    async function setFileSize(handle, size) {
      const reply = await s.ipc('SetFileSize', handle, 3, u64(size));
      if (reply.result) throw Error('SetSize failed 0x' + reply.result.toString(16));
    }

    async function writeAt(handle, offset, bytes) {
      const dataAddr = s.base + 0x30000;
      await s.write(dataAddr, bytes);
      const reply = await s.ipc('WriteFile', handle, 1,
        Buffer.concat([u64(offset), u64(bytes.length), u64(0)]),
        {send: [{address: dataAddr, size: bytes.length, mode: 1}]});
      if (reply.result) throw Error('WriteFile failed 0x' + reply.result.toString(16));
      const flush = await s.ipc('Flush', handle, 2, Buffer.alloc(0));
      if (flush.result) throw Error('Flush failed 0x' + flush.result.toString(16));
    }

    async function readAll(pathname) {
      const reply = await filesys.openFile(s, saveFs, pathname);
      if (reply.result) throw Error('OpenFile failed 0x' + reply.result.toString(16) + ' for ' + pathname);
      handles.push(reply.handle);
      const size = Number(await filesys.fileSize(s, reply.handle));
      const bytes = await filesys.readFile(s, reply.handle, 0, Math.min(size, 0x40000));
      await s.close(reply.handle);
      handles.pop();
      return bytes;
    }

    const created = await createFile(TNS2NEW, newBytes.length);
    console.log('create TNS2NEW result:', created === 0 ? 'ok (new)' : '0x' + (created >>> 0).toString(16));
    const target = await openForWrite(TNS2NEW);
    if (target.result) throw Error('OpenFile TNS2NEW failed 0x' + (target.result >>> 0).toString(16));
    handles.push(target.handle);
    await setFileSize(target.handle, newBytes.length);
    await writeAt(target.handle, 0, newBytes);
    await s.close(target.handle); handles.pop();

    const readback = await readAll(TNS2NEW);
    if (!readback.equals(newBytes)) throw Error('TNS2NEW readback differs');
    console.log('TNS2NEW written and verified (' + readback.length + ' bytes, sha256 ' + hash(readback).slice(0, 16) + ')');
  } finally {
    for (const handle of handles.reverse()) { try { await s.close(handle); } catch {} }
    try { await s.cleanup(); } catch {}
  }
}

main().catch(error => { console.error(error.stack); process.exitCode = 1; });
