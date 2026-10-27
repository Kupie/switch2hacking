// L3 load generator: sustained fs-side USER-filesystem reads (READ-ONLY)
// while the RO monitor's rig 14 primes/probes shared L3. Stand-in victim for
// the cross-module contention experiment (FINDINGS.md, escalation track).
// Usage: node l3-load.cjs [seconds=20]
const fs = require('node:fs'), path = require('node:path');
const latest = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'latest-session.json')));
const {connect} = require(path.join(latest.directory, 'switch2', 'tools', 'fs-memory.cjs'));

(async () => {
  const seconds = Number(process.argv[2] || 20);
  const m = await connect();
  await m.request({command: 'root-probe-bis-filesystem', id: 30});
  // Find a real file: /Album/<year>/<photo>, else fall back to /PRF2SAFE.RCV.
  // Descend Album/<year>/<month>/ to a real FILE entry (type 2; 1=dir).
  const list = async p => (await m.request({command: 'root-list-bis', id: 30, path: p})).entries || [];
  const under = async p => (await list(p)).filter(e => e.type === 2).map(e => p + '/' + e.name);
  let files = [];
  try {
    for (const year of (await list('/Album')).filter(e => e.type === 1))
      for (const month of (await list('/Album/' + year.name)).filter(e => e.type === 1))
        files.push(...(await under('/Album/' + year.name + '/' + month.name)).slice(0, 4));
  } catch {}
  if (!files.length) files = ['/PRF2SAFE.RCV'];
  console.error('load files:', files.length, files[0]);
  const until = Date.now() + seconds * 1000;
  let n = 0, errors = 0;
  while (Date.now() < until) {
    // Throttle: keep the controller mostly free so the rig harness's
    // worker polls are never starved; 16 KiB reads keep fs churning.
    try {
      await m.request({command: 'root-read-bis-file', id: 30, path: files[n % files.length], length: 0x4000});
      n++;
    } catch {errors++;}
    await new Promise(r => setTimeout(r, 250));
  }
  console.log(JSON.stringify({reads: n, kib: n * 16, errors}));
})().catch(e => {console.error(e.message); process.exitCode = 1;});