// NPDM survey with the retarget budget in mind (2026-10-24 model fix).
//
// The console wedges after a per-boot budget of distinct-window retargets
// through the corrupted fs session (~10-15 observed on this unit). One
// module capture = at least one retarget, so an exhaustive 64-module sweep
// can never finish in one boot. Design consequences:
//   - captures accumulate in a persistent store (npdm-captures/) and are
//     skipped on later runs, so reboots only pay for what is missing;
//   - the default target list is the high-probability debug-suite holders
//     (creport first: attaching to crashed processes is its job), not the
//     full module list;
//   - the full list stays available via --all, strictly for accumulation
//     across many boots.
// Each run's captures are still written into the run dir (the code-open
// path requires it) and then copied into the persistent store.
const fs = require('node:fs');
const path = require('node:path');

const MODULES = {
  '0400000000000006': 'usb.gen2', '0400000000000008': 'boot2', '0400000000000009': 'settings',
  '040000000000000A': 'Bus', '040000000000000B': 'bluetooth.autog', '040000000000000C': 'bcat',
  '040000000000000E': 'friends', '040000000000000F': 'nifm', '0400000000000010': 'ptm.prod',
  '0400000000000012': 'bsdsocket', '0400000000000013': 'hid', '0400000000000014': 'audio',
  '0400000000000015': 'LogManager', '0400000000000016': 'wlan.autogen', '0400000000000018': 'ldn',
  '0400000000000019': 'nvservices', '040000000000001A': 'pcv', '040000000000001B': 'capmtp',
  '040000000000001D': 'pcie', '040000000000001E': 'account', '040000000000001F': 'ns',
  '0400000000000020': 'nfc', '0400000000000021': 'psc', '0400000000000022': 'capsrv',
  '0400000000000023': 'am', '0400000000000024': 'ssl', '0400000000000025': 'nim',
  '040000000000002B': 'erpt', '040000000000002E': 'pctl', '040000000000002F': 'npns',
  '0400000000000030': 'eupld', '0400000000000031': 'glue', '0400000000000032': 'eclct',
  '0400000000000033': 'es', '0400000000000034': 'fatal', '0400000000000035': 'grc',
  '0400000000000036': 'creport', '0400000000000037': 'ro', '0400000000000039': 'sdb',
  '040000000000003A': 'migration', '040000000000003C': 'jpegdec', '040000000000003E': 'olsc',
  '0400000000000042': 'pgl', '0400000000000045': 'omm', '0400000000000046': 'eth',
  '0400000000000047': 'imf', '040000000000004A': 'chat', '040000000000004D': 'lrp',
  '040000000000004F': 'nvkernel', '0400000000000050': 'ngc', '0400000000000052': 'cmptldr',
  '0400000000000062': 'gc', '0400000000000063': 'vi2.autogen', '0400000000000065': 'host1x',
  '0400000000000070': 'camera.autogen', '0400000000000071': 'capsrv2', '0400000000000072': 'adraw',
  '0400000000000080': 'gsvm', '0400000000000081': 'gsv1', '0400000000000083': 'gsv3',
  '0400000000000084': 'gsv4', '0400000000000088': 'speech', '0400000000000089': 'sdcard',
  '040000000000008D': 'tsec.autogen',
};

// Debug-suite likelihood, most likely first. creport attaches to crashed
// processes and dumps their memory (its literal purpose); the others are
// plausible holders worth one retarget each while a session is warm.
const PRIORITY = [
  '0400000000000036', // creport
  '0400000000000034', // fatal (crash UX, may share the debug path)
  '0400000000000039', // sdb (sdb/dev tooling family)
  '040000000000004D', // lrp (dev/remote partner services family)
];

const storeDir = path.join(__dirname, 'npdm-captures');
const stored = title => path.join(storeDir, title + '.npdm');

(async () => {
  const args = process.argv.slice(2);
  const all = args.includes('--all');
  const requested = args.filter(a => !a.startsWith('--'));
  fs.mkdirSync(storeDir, {recursive: true});
  let targets;
  if (requested.length) targets = requested.map(t => t.replace(/^0x/i, '').toLowerCase());
  else targets = all ? Object.keys(MODULES) : PRIORITY;
  const unknown = targets.filter(t => !MODULES[t]);
  if (unknown.length) {console.error('unknown titles:', unknown.join(' ')); process.exit(2);}

  const latest = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json')));
  const runDir = path.join(latest.directory, 'switch2');
  const {connect} = require(path.join(runDir, "tools", "fs-memory.cjs"));
  const m = await connect();
  const loaderRoot = JSON.parse(fs.readFileSync(
    path.join(runDir, 'ro', latest.directory.split('/').pop() + '-loader-root-copy.json')));
  const rootHandle = loaderRoot.copy.handle;
  const rows = [];
  for (const title of targets) {
    const line = {title, name: MODULES[title]};
    if (fs.existsSync(stored(title))) {line.skipped = 'already captured'; rows.push(line); continue;}
    try {
      const code = await m.request({command: 'root-native-code-open', handle: rootHandle, title: '0x' + title, fresh: true});
      if (code.result || !code.handle) {line.error = 'open 0x' + (code.result ?? 0).toString(16); rows.push(line); continue;}
      const capture = await m.request({command: 'root-native-file-capture', handle: code.handle, name: 'main.npdm'});
      line.file = capture.file;
      if (capture.file && fs.existsSync(capture.file)) {
        fs.copyFileSync(capture.file, stored(title));
        line.stored = stored(title);
      }
    } catch (error) {line.error = error.message.slice(0, 80);}
    rows.push(line);
    // Stop early rather than wedging the session: the budget is finite and
    // every capture spends it. A fresh boot resumes with the store.
    if (!line.file && !line.skipped) break;
  }
  fs.writeFileSync('/tmp/npdm-survey-files.json', JSON.stringify(rows, null, 2));
  const ok = rows.filter(r => r.stored);
  const skip = rows.filter(r => r.skipped);
  console.log('newly captured %d, already stored %d, listed %d', ok.length, skip.length, rows.length);
  for (const r of rows.filter(r => !r.stored && !r.skipped)) console.log('  MISS', r.title, r.name, r.error);
})().catch(e => {console.error(e.message); process.exitCode = 1;});