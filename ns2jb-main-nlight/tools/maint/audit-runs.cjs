// Offline evidence audit. Never loads run-local code or contacts the console.
const fs = require('node:fs/promises');
const path = require('node:path');

async function optional(file, warnings, json = false) {
  try {
    const text = await fs.readFile(file, 'utf8');
    return json ? JSON.parse(text) : text;
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    if (error instanceof SyntaxError) {
      warnings.push(`Malformed JSON: ${path.basename(file)}`);
      return null;
    }
    throw error;
  }
}

async function inspect(directory) {
  const warnings = [];
  const log = await optional(path.join(directory, 'run.log'), warnings);
  const result = await optional(path.join(directory, 'result.json'), warnings, true);
  const resumeLog = await optional(path.join(directory, 'run-resume.log'), warnings);
  if (log === null) warnings.push('Missing run.log');
  if (result === null) warnings.push('Missing or unreadable result.json');
  const stages = [...new Set([...String(log ?? '').matchAll(/^(\d+)\/4\s/gm)]
    .map(match => Number(match[1])))].sort();
  const reachedReady = /^SESSION READY:/m.test(log ?? '');
  return {
    directory, started: result?.started ?? null,
    hasLog: log !== null, stages, reachedReady,
    finalVerified: typeof result?.verified === 'boolean' ? result.verified : null,
    hasResumeLog: resumeLog !== null,
    outcome: reachedReady ? 'ready-observed' : result?.verified === true
      ? 'completed-verified' : result?.error ? 'ended-with-error' : 'unknown',
    warnings,
  };
}

async function audit(roots) {
  const records = [], seen = new Set();
  for (const root of roots) {
    for (const entry of (await fs.readdir(root, {withFileTypes: true})).sort((a, b) => a.name.localeCompare(b.name))) {
      if (!entry.isDirectory() || !/^switch2-[A-Za-z0-9]{6}$/.test(entry.name)) continue;
      const directory = await fs.realpath(path.join(root, entry.name));
      if (seen.has(directory)) continue;
      seen.add(directory);
      records.push(await inspect(directory));
    }
  }
  const logged = records.filter(row => row.hasLog);
  const ready = logged.filter(row => row.reachedReady);
  return {
    note: 'Run directories are not unique boots. Resume logs are not new attempts. Missing readiness evidence does not prove failure. Copies under different paths are not deduplicated.',
    summary: {
      directories: records.length, loggedRuns: logged.length,
      readyObserved: ready.length,
      readyPercentOfLoggedRuns: logged.length ? 100 * ready.length / logged.length : null,
      readyButFinalUnverified: ready.filter(row => row.finalVerified === false).length,
      finalVerified: records.filter(row => row.finalVerified === true).length,
      unknown: records.filter(row => row.outcome === 'unknown').length,
      withResumeLogs: records.filter(row => row.hasResumeLog).length,
      stageReached: Object.fromEntries([1, 2, 3, 4].map(stage =>
        [stage, logged.filter(row => row.stages.includes(stage)).length])),
    },
    records,
  };
}

if (require.main === module) {
  const roots = process.argv.slice(2);
  audit(roots.length ? roots : [path.join(__dirname, 'runs')])
    .then(report => console.log(JSON.stringify(report, null, 2)))
    .catch(error => { console.error(error.message); process.exitCode = 1; });
}
module.exports = {audit};
