// Update the SmileBASIC program text on the console save filesystem.
// Modes:
//   node probe-save-update.cjs read              — dump TNS2/T@BACKUP.PRG/META locally
//   node probe-save-update.cjs write <newFile>   — back up TNS2 -> TNS2BAK, write new TNS2, verify
// Every file handle and the session are closed in finally blocks; a leaked
// save-file handle wedges the console (learned the hard way).
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

const PROG_DIR = '/f/###';
const TNS2 = PROG_DIR + '/TNS2';
const TNS2BAK = PROG_DIR + '/TNS2BAK';
const outDir = path.join(runDir, 'save-explore');
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

async function main() {
  const mode = process.argv[2];
  if (!['read', 'write'].includes(mode)) throw Error('Usage: node probe-save-update.cjs read | write <newFile>');
  const {s} = await session.connect('save-update', 0x40000);
  const handles = [];
  try {
    s.bulkDownloads = false;
    const saveFs = await mounted.cloneMountedFilesystem(s, 'save');
    handles.push(saveFs);

    async function putString(address, text) {
      const bytes = Buffer.from(text, 'utf8');
      bytes.copy(Buffer.alloc(0x301).copy ? bytes : bytes); // no-op guard
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
      const reply = await filesys.openFile(s, saveFs, pathname, u32ModeWrite());
      return reply;
    }
    function u32ModeWrite() { // OpenFile mode input: 1=Read, 2=Write, 4=Append
      const {u32} = require(runDir + '/app/session.cjs');
      return u32(3); // read + write
    }

    async function setFileSize(handle, size) {
      const reply = await s.ipc('SetFileSize', handle, 3, u64(size));
      if (reply.result) throw Error('SetSize failed 0x' + reply.result.toString(16) + ' for size ' + size);
    }

    async function writeAt(handle, offset, bytes) {
      bytes.copy(Buffer.alloc(0)); // keep reference alive
      const dataAddr = s.base + 0x30000;
      await s.write(dataAddr, bytes);
      const reply = await s.ipc('WriteFile', handle, 1,
        Buffer.concat([u64(offset), u64(bytes.length), u64(0)]),
        {send: [{address: dataAddr, size: bytes.length, mode: 1}]});
      if (reply.result) throw Error('WriteFile failed 0x' + reply.result.toString(16) +
        ' at offset ' + offset + ' (' + bytes.length + ' bytes)');
      const flush = await s.ipc('Flush', handle, 2, Buffer.alloc(0));
      if (flush.result) throw Error('Flush failed 0x' + flush.result.toString(16));
    }

    async function readAll(pathname, expectSize) {
      const reply = await filesys.openFile(s, saveFs, pathname);
      if (reply.result) throw Error('OpenFile failed 0x' + reply.result.toString(16) + ' for ' + pathname);
      handles.push(reply.handle);
      const size = Number(await filesys.fileSize(s, reply.handle));
      const bytes = await filesys.readFile(s, reply.handle, 0, Math.min(size, 0x40000));
      await s.close(reply.handle);
      handles.pop();
      return bytes;
    }

    if (mode === 'read') {
      for (const [name, file] of [['TNS2', TNS2], ['TBACKUP', PROG_DIR + '/T@BACKUP.PRG'], ['META', PROG_DIR + '/META']]) {
        try {
          const bytes = await readAll(file);
          await fs.mkdir(outDir, {recursive: true, mode: 0o700});
          await fs.writeFile(path.join(outDir, name + '.bin'), bytes, {mode: 0o600});
          const utf16 = bytes[0] === 0xff && bytes[1] === 0xfe;
          const text = utf16 ? bytes.subarray(2).swap16().toString('utf16le') : bytes.toString('utf8');
          console.log(name, bytes.length, 'bytes utf16le:', utf16, 'head:', JSON.stringify(text.slice(0, 80)));
        } catch (error) { console.log(name, 'FAILED:', error.message); }
      }
      console.log('read done');
      return;
    }

    // ---------- write mode ----------
    const newBytes = await fs.readFile(process.argv[3]);
    const original = await fs.readFile(path.join(outDir, 'TNS2.bin'));
    if (!original.length) throw Error('Run read mode first to capture the original TNS2');
    console.log('original', original.length, 'bytes sha256', hash(original).slice(0, 16),
      '-> new', newBytes.length, 'bytes sha256', hash(newBytes).slice(0, 16));

    // 1. Backup TNS2BAK with the original bytes.
    let created = await createFile(TNS2BAK, original.length);
    console.log('create TNS2BAK result:', created === 0 ? 'ok (new)' : '0x' + (created >>> 0).toString(16));
    if (created === 0 || (created >>> 0) === 0x202) { // ok or already-exists style results
      const bak = await openForWrite(TNS2BAK);
      if (bak.result) throw Error('OpenFile TNS2BAK failed 0x' + (bak.result >>> 0).toString(16));
      handles.push(bak.handle);
      await setFileSize(bak.handle, original.length);
      await writeAt(bak.handle, 0, original);
      await s.close(bak.handle); handles.pop();
      const bakVerify = await readAll(TNS2BAK);
      if (!bakVerify.equals(original)) throw Error('TNS2BAK verification failed');
      console.log('TNS2BAK written and verified (' + bakVerify.length + ' bytes)');
    }

    // 2. Rewrite TNS2 with the new text.
    const target = await openForWrite(TNS2);
    if (target.result) throw Error('OpenFile TNS2 failed 0x' + (target.result >>> 0).toString(16));
    handles.push(target.handle);
    await setFileSize(target.handle, newBytes.length);
    await writeAt(target.handle, 0, newBytes);
    await s.close(target.handle); handles.pop();

    // 3. Verify readback.
    const readback = await readAll(TNS2);
    if (!readback.equals(newBytes)) throw Error('TNS2 readback differs from what was written');
    console.log('TNS2 updated and verified (' + readback.length + ' bytes, sha256 ' + hash(readback).slice(0, 16) + ')');
  } finally {
    for (const handle of handles.reverse()) { try {await s.close(handle);} catch {} }
    try {await s.cleanup();} catch {}
  }
}

main().catch(error => { console.error(error.stack); process.exitCode = 1; });
