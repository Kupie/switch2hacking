#!/usr/bin/env node
// Recursively list and dump a mounted content filesystem (RomFS handle from
// the memory session) to the PC, with per-file sha256 manifest.
//
// Usage (from the repo root, inside the netns):
//   sudo -n ip netns exec switchlab runuser -u nlight -- node dump-romfs.cjs \
//     --handle <romfs handle> --out <output directory> [--max-bytes N]
//
// The handle comes from OpenDataFileSystemByCurrentProcess (as the running
// app) or any other mounted content filesystem. Reads go through the
// root-read-romfs-file dispatch command (0x40000-byte chunks).
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

async function main() {
  const args = process.argv.slice(2);
  const handle = Number(args[args.indexOf('--handle') + 1]);
  const out = path.resolve(args[args.indexOf('--out') + 1]);
  const maxBytes = args.includes('--max-bytes') ? Number(args[args.indexOf('--max-bytes') + 1]) : Infinity;
  check(Number.isInteger(handle) && handle > 0, 'A valid --handle is required');
  check(out && out.startsWith('/'), 'An absolute --out directory is required');

  const latest = JSON.parse(await fs.readFile(path.join(__dirname, '..', '..', 'latest-session.json')));
  const dir = latest.directory;
  const {connect} = require(path.join(dir, 'switch2', 'tools', 'fs-memory.cjs'));
  const mem = await connect();

  await fs.mkdir(out, {recursive: true});
  const manifest = {handle, out, started: new Date().toISOString(), files: [], skipped: []};
  let total = 0;

  async function list(dirPath) {
    const r = await mem.request({command: 'root-list-romfs', handle, path: dirPath});
    check(!r.result, 'Listing failed for ' + dirPath + ': 0x' + (r.result ?? 0).toString(16));
    return r.entries || [];
  }

  async function dumpFile(filePath, size) {
    if (total + size > maxBytes) {manifest.skipped.push({path: filePath, size}); return;}
    const chunks = [];
    const hash = crypto.createHash('sha256');
    for (let offset = 0; offset < size; offset += 0x40000) {
      const length = Math.min(0x40000, size - offset);
      const r = await mem.request({command: 'root-read-romfs-file', handle,
        path: filePath, offset, length});
      check(!r.result, 'Read failed for ' + filePath + ' @' + offset + ': 0x' + (r.result ?? 0).toString(16));
      const bytes = Buffer.from(r.bytes, 'hex');
      check(bytes.length === length, 'Short read for ' + filePath + ' @' + offset);
      chunks.push(bytes); hash.update(bytes);
    }
    const rel = filePath.replace(/^\//, '');
    await fs.mkdir(path.join(out, path.dirname(rel)), {recursive: true});
    await fs.writeFile(path.join(out, rel), Buffer.concat(chunks), {mode: 0o600});
    total += size;
    manifest.files.push({path: rel, size, sha256: hash.digest('hex')});
    console.log(rel, size, 'bytes, total', total);
  }

  const queue = ['/'];
  while (queue.length) {
    const dirPath = queue.shift();
    const entries = await list(dirPath);
    for (const entry of entries) {
      const full = (dirPath === '/' ? '' : dirPath) + '/' + entry.name;
      if (entry.type === 0) queue.push(full);
      else await dumpFile(full, Number(entry.size));
    }
  }
  manifest.finished = new Date().toISOString();
  manifest.totalBytes = total;
  const manifestFile = path.join(out, 'manifest.json');
  await fs.writeFile(manifestFile, JSON.stringify(manifest, null, 2) + '\n', {mode: 0o600});
  console.log('DONE:', manifest.files.length, 'files,', total, 'bytes ->', manifestFile);
}

function check(ok, message) {if (!ok) {console.error('FAILED: ' + message); process.exit(1);}}

main().catch(e => {console.error('ERR', e.message); process.exit(1);});
