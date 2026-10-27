// Retry the dump files that errored with 0xe02 (BIS OpenFile read failures).
// Small retries with a pause; sequential to avoid handle pressure.
'use strict';
const path = require('node:path');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const crypto = require('node:crypto');
const OUT = __dirname + '/dumps/switch2-1u9ld7';
const dir = path.resolve(__dirname + '/runs/switch2-1u9ld7/switch2');
const {connect} = require(dir + '/tools/fs-memory.cjs');
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function main() {
  const manifest = JSON.parse(await fsp.readFile(path.join(OUT, 'dump-manifest.json'), 'utf8'));
  const errs = manifest.files.filter(f => f.error);
  console.log('retrying', errs.length, 'files');
  const memory = await connect();
  const id = f => f.source === 'system' ? 31 : 30;
  const retry = async f => {
    const size = Number(f.size);
    const parts = [];
    for (let at = 0; at < size; at += 0x40000) {
      const take = Math.min(0x40000, size - at);
      const r = await memory.request({command: 'root-read-bis-file', id: id(f), path: f.path,
        length: take, offset: at}).catch(e => ({error: e.message}));
      if (r.error) return {error: r.error};
      parts.push(Buffer.from(r.bytes, 'hex'));
    }
    const bytes = Buffer.concat(parts);
    const rel = f.path.replace(/^\//, '');
    const file = path.join(OUT, f.source, rel);
    await fsp.mkdir(path.dirname(file), {recursive: true});
    await fsp.writeFile(file, bytes);
    return {sha256: crypto.createHash('sha256').update(bytes).digest('hex'), bytes: bytes.length};
  };
  let fixed = 0, still = 0;
  for (const f of errs) {
    const result = await retry(f);
    if (result.error) { still++; console.log('STILL', f.path, result.error.slice(0, 60)); }
    else {
      fixed++;
      delete f.error;
      f.sha256 = result.sha256;
      console.log('FIXED', f.path, result.bytes, 'bytes');
    }
    await sleep(300);
  }
  await fsp.writeFile(path.join(OUT, 'dump-manifest.json'), JSON.stringify(manifest, null, 1) + '\n');
  console.log('retry done: fixed', fixed, '| still failing', still);
}

main().catch(e => { console.error('FAILED:', e.message); process.exit(1); });
