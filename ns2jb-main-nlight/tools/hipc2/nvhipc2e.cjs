// HIPC2 probe v3 — CORRECT frame (from pgl client disasm, 2026-10-25):
//   +0x00 u32 6        (HIPC2 type)
//   +0x04 u32 wordcount (payload words; 0xA observed for 1-arg cmd)
//   +0x10 "SFCI" (16-aligned; for a static buffer just use +0x10)
//   +0x14 u32 1        (token/version)
//   +0x18 u32 cmd
//   +0x1C u32 seq      (services: from TLS+0x1f8 -> ptr +0x100, ldar; probes: 0)
//   +0x20 args
// Send via svc 0x22 (root-native-raw-ipc bare) or the SDK send.
//
// The 0xF601 errors in earlier probes were MALFORMED FRAMES (SFCI at +8,
// handle in word1) — the services reject bad framing; no kernel TLS needed.
//
// Usage: netns-wrapped, live session:
//   sudo -n ip netns exec switchlab runuser -u nlight -- node nvhipc2e.cjs [service] [cmd]
'use strict';
const fs = require('node:fs/promises');
const path = require('node:path');

function hipc2(cmd, args = [], seq = 0) {
  const b = Buffer.alloc(0x100);
  b.writeUInt32LE(6, 0x00);
  b.writeUInt32LE(8 + 2 * args.length, 0x04);   // wordcount observed 0xA for 1 arg
  b.write('SFCI', 0x10);
  b.writeUInt32LE(1, 0x14);
  b.writeUInt32LE(cmd, 0x18);
  b.writeUInt32LE(seq, 0x1C);
  args.forEach((a, i) => b.writeBigUInt64LE(BigInt(a), 0x20 + i * 8));
  return b;
}

async function main() {
  const latest = JSON.parse(await fs.readFile(path.join(__dirname, '..', '..', 'latest-session.json')));
  const runDir = path.join(latest.directory, 'switch2');
  const {connect} = require(path.join(runDir, 'tools', 'fs-memory.cjs'));
  const m = await connect();
  const info = await m.request({command: 'root-native-info'});
  const sm = info.services?.find(s => s.name === 'pm:shell')?.sm;
  if (!sm) throw Error('no borrowed SM client');
  const name = process.argv[2] || 'nvdrv:t';
  const cmd = Number(process.argv[3] || 0);
  const svc = await m.request({command: 'root-native-sm-service', handle: sm, name});
  const handle = svc.moves[0];
  console.log(`${name} handle ${handle}`);

  // empty-args frame: try a couple of wordcounts (0xA baseline + minimal 4)
  for (const wc of [0xA, 4]) {
    const msg = Buffer.alloc(0x100);
    msg.writeUInt32LE(6, 0x00);
    msg.writeUInt32LE(wc, 0x04);
    msg.write('SFCI', 0x10);
    msg.writeUInt32LE(1, 0x14);
    msg.writeUInt32LE(cmd, 0x18);
    msg.writeUInt32LE(0, 0x1C);
    const r = await m.request({command: 'root-native-raw-ipc', handle, id: 0, bare: true,
      hex: msg.toString("hex")});
    const raw = r.raw || '';
    console.log(`cmd ${cmd} wc ${wc}: transport 0x${(r.transport >>> 0).toString(16)} result 0x${(r.result >>> 0).toString(16)} raw ${raw.slice(0, 96)}`);
    if (raw.includes('5346434f')) { console.log('  <<< "SFCO" SEEN — HIPC2 ANSWERED!'); break; }
  }
  const r2 = await m.request({command: 'root-native-raw-ipc', handle, id: cmd, bare: true,
    hex: hipc2(cmd).toString('hex')});
  console.log(`1-arg shape cmd ${cmd}: transport 0x${(r2.transport >>> 0).toString(16)} raw ${(r2.raw || '').slice(0, 96)}`);
  if ((r2.raw || '').includes('5346434f')) console.log('  <<< "SFCO" — HIPC2 CONFIRMED');
}

main().catch(e => {console.error(e.stack || e); process.exitCode = 1;});
