#!/usr/bin/env node
// nvdrv kernel-surface SURVEY (read-only, no fuzzing): maps which nvdrv
// services open from the retained session, which cmif command ids exist,
// which device paths open, and what result codes each returns. Output is the
// command/device grammar for nvdrv-fuzz.cjs.
//
// Run inside the netns like the other probes:
//   sudo -n ip netns exec switchlab runuser -u nlight -- node nvdrv-survey.cjs
const fs = require('node:fs/promises');
const path = require('node:path');
const check = (ok, message) => {if (!ok) throw Error(message);};

const SERVICE_NAMES = ['nvdrv:t', 'nvdrv:s', 'nvdrv:v', 'nvdrvdbg', 'nvgem:c', 'nvgem:cd'];
// Device paths extracted from the fw23 nvservices/rodump (see FIRMWARE_FINDINGS).
const DEVICES = [
  '/dev/nvhost-ctrl', '/dev/nvhost-ctrl-gpu', '/dev/nvhost-gpu', '/dev/nvhost-dbg-gpu',
  '/dev/nvhost-prof-gpu', '/dev/nvhost-prof-dev-gpu', '/dev/nvhost-as-gpu', '/dev/nvhost-vic',
  '/dev/nvhost-nvjpg', '/dev/nvmap', '/dev/nvmap-vm6', '/dev/nvmap-tsec', '/dev/nvdisp',
  '/dev/nvdec', '/dev/nvdec0', '/dev/nvdec1', '/dev/nvdec2', '/dev/nvdec3', '/dev/nvdec4',
  '/dev/nvdec5', '/dev/nvdec6', '/dev/nvdec7', '/dev/nvjpg0', '/dev/nvjpg1', '/dev/nvjpg2',
  '/dev/nvjpg3', '/dev/nvjpg4', '/dev/nvjpg5', '/dev/nvjpg6', '/dev/nvjpg7'
];

async function main() {
  const latest = JSON.parse(await fs.readFile(path.join(__dirname, '..', '..', 'latest-session.json')));
  const runDir = path.join(latest.directory, 'switch2');
  const {connect} = require(path.join(runDir, 'tools', 'fs-memory.cjs'));
  const m = await connect();
  const session = m.info.session;
  console.log('session:', session);

  const proof = {session, started: new Date().toISOString(), services: {}, notes: []};

  // Borrowed SM client (pm:shell sm) — same pattern as fw-dump.cjs.
  const info = await m.request({command: 'root-native-info'});
  const sm = info.services?.find(s => s.name === 'pm:shell')?.sm;
  check(sm, 'no borrowed SM client (pm:shell sm) in service state');

  const opened = [];
  for (const name of SERVICE_NAMES) {
    try {
      const svc = await m.request({command: 'root-native-sm-service', handle: sm, name});
      proof.services[name] = {result: svc.result, moves: svc.moves, copies: svc.copies};
      console.log(name, '->', JSON.stringify({result: svc.result, moves: svc.moves, copies: svc.copies}));
      if (!svc.result && (svc.moves?.length || svc.copies?.length)) opened.push({name, handle: (svc.moves || svc.copies)[0]});
    } catch (e) {
      proof.services[name] = {error: String(e.message || e)};
      console.log(name, '-> error', e.message);
    }
  }
  if (!opened.length) {proof.notes.push('no nvdrv service opened; fuzz needs at least one');}

  // Command surface survey per opened service: cmif ids 0..15 with 192B of
  // patterned payload (0x41 fill) + one send/receive alias region.
  proof.commandSurvey = {};
  for (const svc of opened) {
    const handle = svc.handle;
    const survey = [];
    for (let id = 0; id <= 15; id++) {
      const payload = Buffer.alloc(64, 0x41);
      payload.writeUInt32LE(id, 0);
      let entry;
      try {
        entry = await m.request({command: 'root-native-raw-ipc', handle, id,
          hex: payload.toString('hex'),
          receive: [{offset: 0x6000, size: 0x200, mode: 1}],
          send: [{offset: 0x6400, size: 0x200, mode: 1}]});
        survey.push({id, result: entry.result, canonical: entry.canonicalResult, transport: entry.transport,
          copies: entry.copies, moves: entry.moves, raw: (entry.raw || '').slice(0, 128)});
        console.log(`${svc.name} cmd ${id}: 0x${(entry.result >>> 0).toString(16)} raw=${(entry.raw || '').slice(0, 64)}`);
      } catch (e) {
        survey.push({id, error: String(e.message || e)});
        console.log(`${svc.name} cmd ${id}: ERROR ${e.message}`);
        break; // IPC layer broke — stop surveying this service.
      }
    }
    proof.commandSurvey[svc.name] = survey;
  }

  // Device-path survey: try the nvdrv "open device" flow for each path once we
  // know which command id takes a path buffer. Deferred to fuzz stage unless a
  // survey result shows an obvious signature; recorded here for continuity.
  proof.devices = DEVICES;

  proof.finished = new Date().toISOString();
  const file = path.join(runDir, `nvdrv-survey-${session}.json`);
  await fs.writeFile(file, JSON.stringify(proof, null, 2) + '\n', {mode: 0o600});
  console.log(JSON.stringify({file, services: Object.keys(proof.services)}));
}

main().catch(error => { console.error(error.stack); process.exitCode = 1; });
