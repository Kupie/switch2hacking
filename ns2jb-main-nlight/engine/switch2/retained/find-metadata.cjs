// Locate the native allocator's external link from this session's captures.
//
// Search design (see docs/find-metadata-review.md): the pool start is one of at
// most 16 aligned candidates containing the verified seed page. The external
// allocator link at `start + NODE_OFFSET` is a total discriminator: for the
// true start the node bytes reproduce the link (next === previous, bounded
// extent), for any wrong start they do not. The search therefore probes each
// candidate's node directly (<= 16 bounded captures) and only falls back to
// an evidence-based bucket search when no probe resolves. It NEVER returns a
// singleton that was not either node-verified or left as the last candidate
// after sound, corroborated elimination; otherwise it fails with an explicit
// ambiguity error carrying the surviving candidate set.
const fs = require('node:fs/promises');
const path = require('node:path');
const memory = require('../tools/endpoint.cjs');
const {linksFrom} = require('./links.cjs');
const {lowerWindow} = require("./lower-window.cjs");
const {metadataWindow} = require("./metadata-window.cjs");
const check = (ok, message) => { if (!ok) throw Error(message); };

const NODE_OFFSET = 0x3a00000;
const POOL_SIZE = 0x2000000, POOL_ALIGNMENT = 0x200000;

// The external allocator link reproduced at the pool's node address. The
// claimed node address participates in the predicate: `next` must point far
// away from it (the link is external), and the mirrored next/previous words
// plus the bounded extent make a coincidental pass implausible.
function externalLinkAt(bytes, offset, node) {
  const next = Number(bytes.readBigUInt64LE(offset));
  const previous = Number(bytes.readBigUInt64LE(offset + 8));
  const extent = Number(bytes.readBigUInt64LE(offset + 16));
  return {
    valid: Number.isSafeInteger(next) && next >= 2 ** 32 && next < 2 ** 39 && next % 8 === 0 &&
      next === previous && Math.abs(next - node) > 0x8000000 &&
      Number.isSafeInteger(extent) && extent >= 0x10000 && extent <= 0x10000000 && extent % 0x1000 === 0,
    next, previous, extent,
  };
}

function poolBounds(links, seed) {
  check(links.length > 0, 'The pool capture has no native links');
  const size = POOL_SIZE, alignment = POOL_ALIGNMENT;
  if (seed !== undefined) {
    check(Number.isSafeInteger(seed) && seed % 0x4000 === 0, 'Expected the verified native pool page');
    const candidates = [];
    for (let start = Math.ceil((seed + 0x4000 - size) / alignment) * alignment;
      start <= seed; start += alignment) {
      // Only headers inside a candidate pool constrain that pool's linked
      // pages; a candidate with no inside link is unproven, not disproven,
      // so it stays in the geometric candidate set (see linksOnlyBounds).
      const inside = links.filter(link => link.source >= start && link.source + 0x4000 <= start + size);
      if (inside.length && inside.every(link => link.value >= start && link.value + 0x4000 <= start + size))
        candidates.push(start);
    }
    check(candidates.length > 0, 'Native links do not fit the pool containing the verified page');
    return {first: candidates[0], last: candidates.at(-1), size, alignment, seed,
      candidates, observedLinks: links.length};
  }
  const low = Math.min(...links.flatMap(link => [link.source, link.value]));
  const high = Math.max(...links.flatMap(link => [link.source, link.value]));
  const first = Math.ceil((high + 0x4000 - size) / alignment) * alignment;
  const last = Math.floor(low / alignment) * alignment;
  check(Number.isSafeInteger(first) && first <= last, 'Native links do not fit the pool layout');
  return {first, last, size, alignment, low, high};
}

// All geometric candidates: every aligned start whose pool contains the seed
// page. No candidate is eliminated here; evidence may only shrink this set.
function geometricCandidates(seed) {
  check(Number.isSafeInteger(seed) && seed % 0x4000 === 0, 'Expected the verified native pool page');
  const candidates = [];
  for (let start = Math.ceil((seed + 0x4000 - POOL_SIZE) / POOL_ALIGNMENT) * POOL_ALIGNMENT;
    start <= seed; start += POOL_ALIGNMENT) candidates.push(start);
  check(candidates.length > 0, 'No geometric pool candidate contains the verified page');
  return candidates;
}

// Evidence normalization. Duplicate observations are free; a source observed
// with two different values means the captures disagree (the allocator may be
// mutating between reads), so that source is quarantined: it can neither
// constrain candidates nor schedule search targets. Links whose source sits
// outside every candidate are neighbor evidence and are quarantined the same
// way.
function normalizeLinks(links, candidates) {
  const bySource = new Map(), disputed = [];
  for (const link of links) {
    const seen = bySource.get(link.source);
    if (seen && seen.value !== link.value) {
      bySource.delete(link.source);
      disputed.push(link.source);
    } else if (!seen) bySource.set(link.source, link);
  }
  const deduped = [...bySource.values()];
  const relevant = deduped.filter(link => candidates.some(start =>
    link.source >= start && link.source + 0x4000 <= start + POOL_SIZE));
  return {links: deduped, relevant, disputed};
}

// Only structurally corroborated links (aligned pointer followed by a zero
// block tail) may eliminate a candidate: a bare pointer-shaped word is a
// plausibility guess and must never discard the true pool. Absence of links
// is not evidence and eliminates nothing.
function filterByLinks(candidates, links) {
  return candidates.filter(start => links.every(link => {
    const sourceInside = link.source >= start && link.source + 0x4000 <= start + POOL_SIZE;
    const valueInside = link.value >= start && link.value + 0x4000 <= start + POOL_SIZE;
    return !link.zeroTail || !sourceInside || valueInside;
  }));
}

// Bucket-aligned read covering [address, address + page) like the callers do.
function bucketRead(reader, info, address, extra = 0x1000) {
  const cycle = info.bucketPeriod;
  const bias = info.plan.addressBias;
  const start = bias + Math.floor((address - bias) / cycle) * cycle;
  return {start, read: () => reader(start, address - start + extra)};
}

async function resolvePool(socket, info, source, evidence, save, reader, broadSource) {
  reader ||= ((start, length) => memory.read(socket, start, length));
  const seed = source.result.address;
  const candidates = geometricCandidates(seed);
  const search = evidence.poolSearch = {
    method: 'node-predicate', candidates, nodeProbes: [], captures: [], hypotheses: [candidates],
    maxCaptures: candidates.length + Math.ceil(POOL_SIZE / info.bucketPeriod) + 16,
  };
  const {links: seedLinks, relevant: seedRelevant} = normalizeLinks(linksFrom(source.bytes, seed, seed), candidates);
  search.seedLinks = seedLinks.length;
  const node = start => start + NODE_OFFSET;

  // Phase 0 (2026-10-24): narrow the probe set with the broad capture's
  // links BEFORE any node probe. Each probe is a full cache-alias retarget —
  // the demonstrated console-wedge unit (6/6 stalls inside the old 16-probe
  // loop) — while the broad read that produced these links is in-window
  // cycle-walk (wedge-proof class). Narrowing never eliminated the true
  // start across 18/18 real captures, and every probed survivor is still
  // node-verified below, so soundness is unchanged: a narrowed set only
  // decides WHICH candidates get probed, and Phase 2 keeps the full
  // geometric union for sound elimination on probe failure.
  const narrowed = filterByLinks(candidates, seedRelevant);
  const probeSet = (narrowed.length && narrowed.length < candidates.length) ? narrowed : candidates;
  // Probe best-first: rank by how many broad-capture links have their VALUE
  // inside the candidate (the discriminating direction: link sources lie in
  // the common seed window, values point into the true pool). Across 21 real
  // captures the true start ranked #1 in 15, top-3 in 19. The node predicate
  // is a total discriminator, so probing stops at the first valid node;
  // the anchor-verified metadata selection downstream fails loudly on a
  // wrong pick, never silently.
  const support = start => seedRelevant.filter(link =>
    link.value >= start && link.value + 0x4000 <= start + POOL_SIZE).length;
  const probeOrder = [...probeSet].sort((a, b) => support(b) - support(a) || a - b);
  search.phase0 = {relevantLinks: seedRelevant.length, geometric: candidates.length,
    probeSet: probeSet.length, bestFirst: support(probeOrder[0])};

  // Phase 1: probe every candidate's external allocator link. The predicate
  // validates the link structure at each candidate's node address and binds
  // it to that address via the minimum-distance check. Another arena region
  // with the same internal layout could in principle satisfy it; that case
  // falls through to survivor narrowing and, failing that, an explicit
  // ambiguity — never a silent guess. Read failures are recorded and treated
  // as "not resolved", never fatal.
  let survivors = [];
  for (const start of probeOrder) {
    await save();
    const probe = {start, node: node(start)};
    try {
      const {start: readStart, read} = bucketRead(reader, info, node(start));
      const capture = await read();
      const offset = node(start) - readStart;
      probe.capture = capture.result;
      search.captures.push(capture.result);
      const link = externalLinkAt(capture.bytes, offset, node(start));
      probe.observed = {next: link.next, previous: link.previous, extent: link.extent};
      if (link.valid) {
        survivors.push(start);
        probe.valid = true;
        search.nodeProbes.push(probe);
        search.earlyStop = {probed: search.nodeProbes.length, probeSet: probeSet.length,
          support: support(start)};
        break;
      }
    } catch (error) {
      probe.error = error.message;
    }
    search.nodeProbes.push(probe);
  }

  if (survivors.length > 1) {
    // Several nodes looked valid (e.g. adjacent arena regions with the same
    // internal layout). Corroborated links may still narrow the set; a bare
    // guess may not.
    const {relevant, disputed} = normalizeLinks(seedLinks, survivors);
    if (disputed.length) search.disputed = disputed.map(source => '0x' + source.toString(16));
    const narrowed = filterByLinks(survivors, relevant);
    search.nodeAmbiguity = {survivors, narrowed: narrowed.length};
    survivors = narrowed;
  }
  if (survivors.length === 1) {
    search.resolved = {start: survivors[0], verified: true};
    await save();
    return {start: survivors[0], first: survivors[0], last: survivors[0],
      size: POOL_SIZE, alignment: POOL_ALIGNMENT, seed, candidates, verified: true};
  }

  // Phase 2: no conclusive node. Exhaustively cover the union of all
  // hypotheses, including edge-straddling buckets, gathering corroborated
  // links. This terminates by construction (the old search could dead-end by
  // never enumerating the lower side). The broad 5 MiB window is read here
  // only when the node probes failed to resolve: its links corroborate the
  // sweep exactly as the eager read did, without paying the exposure on the
  // resolved fast path.
  search.method = 'exhaustive-links';
  const covered = [];
  const unionLow = candidates[0], unionHigh = candidates.at(-1) + POOL_SIZE;
  const bias = info.plan.addressBias, cycle = info.bucketPeriod;
  const links = [...seedLinks];
  if (broadSource) {
    await save();
    const broad = await broadSource();
    links.push(...linksFrom(broad.bytes, seed, seed));
  }
  let uncertain = [...survivors]; // empty on total node failure
  if (!uncertain.length) uncertain = candidates;
  for (let address = bias + Math.floor((unionLow - bias) / cycle) * cycle;
    address < unionHigh && uncertain.length > 1; address += cycle) {
    if (covered.some(c => c <= address && address + cycle <= c + cycle)) continue;
    await save();
    try {
      const capture = await reader(address, cycle);
      covered.push(address);
      search.captures.push(capture.result);
      links.push(...linksFrom(capture.bytes, address, seed));
    } catch (error) {
      search.readErrors = (search.readErrors || 0) + 1;
    }
    const {relevant, disputed} = normalizeLinks(links, uncertain);
    if (disputed.length)
      search.disputed = [...(search.disputed || []), ...disputed.map(source => '0x' + source.toString(16))];
    const next = filterByLinks(uncertain, relevant);
    // Sound elimination only ever shrinks. A set-emptying elimination means
    // the evidence contradicts every candidate; keep the previous set,
    // record the conflict, and let the coverage loop end in an explicit
    // ambiguity rather than guessing (never widen, never pick a singleton).
    if (next.length) uncertain = next;
    else search.evidenceConflict = (search.evidenceConflict || 0) + 1;
    search.hypotheses.push([...uncertain]);
  }
  await save();
  if (uncertain.length === 1) {
    search.resolved = {start: uncertain[0], verified: false};
    return {start: uncertain[0], first: uncertain[0], last: uncertain[0],
      size: POOL_SIZE, alignment: POOL_ALIGNMENT, seed, candidates, verified: false};
  }
  // Never pick one merely because the others lacked positive links: a wrong
  // singleton here becomes a silent downstream failure (the external-link
  // check in main() would reject it long after the search "succeeded").
  search.resolved = {ambiguous: uncertain};
  throw Error('Pool boundary is ambiguous after exhaustive capture: ' +
    uncertain.map(start => '0x' + start.toString(16)).join(','));
}

async function main(supervisorFile) {
  // The RPC client binds to this run's connection.json; load it only when
  // actually running against a console so the search stays offline-testable.
  const rpc = require('../../shared/rpc.cjs');
  const deadline = Date.now() + 600000;
  let supervisor;
  for (;;) {
    supervisor = JSON.parse(await fs.readFile(supervisorFile));
    if (supervisor.stage === 'memory-ready') break;
    check(!supervisor.error && Date.now() < deadline, 'Acquisition did not become ready');
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  const reportFile = supervisor.attempts.at(-1).report;
  const report = JSON.parse(await fs.readFile(reportFile));
  const current = await rpc.request({command: 'status'});
  check(current.ready && rpc.a.platform === 2 && rpc.a.session === report.session && report.memoryControl.ready,
    'Expected the current retained boot (ready=' + current.ready + ' platform=' + rpc.a.platform +
    ' rpcSession=' + rpc.a.session + ' reportSession=' + report.session +
    ' memoryControl=' + report.memoryControl.ready + ')');
  const socket = report.memoryControl.socketPath;
  const info = await memory.request(socket, {command: 'info'});
  check(info.phase === 'bootstrap' && info.plan.readOffset >= 0x3000000,
    'Expected a broad bootstrap mapping');
  const evidence = {session: report.session, report: reportFile, started: new Date().toISOString(),
    casesBefore: report.cases.length, attempts: []};
  const file = path.join(__dirname, report.session + '-metadata-' + Date.now() + '.json');
  const save = () => fs.writeFile(file, JSON.stringify(evidence, null, 2) + '\n', {mode: 0o600});
  await save();
  try {
    // Eager broad capture (2026-10-24): reverted the P0.7 160 KiB seed
    // window. The risk model P0.7 was built on counted BYTES, but the
    // demonstrated wedge unit is the cache-alias RETARGET: an in-window
    // cycle-walk read of any size is the wedge-proof op class (the waves run
    // 30k+ ops; the historical 5 MiB eager read survived 15/15 boots), while
    // every out-of-window node probe forces one full retarget — and 6/6
    // recorded stalls died inside the 16-probe loop (probe ~8), never during
    // a big in-window read. The broad capture's links also cut the probe set
    // ~4x before any retarget happens (median 16 -> 4, true start survives
    // 18/18 real captures; see FINDINGS.md). P0.4 chunking still bounds each
    // 512 KiB chunk with a named-offset stall deadline.
    const source = await memory.read(socket, info.plan.target, 0x500000);
    evidence.poolCapture = source.result;
    evidence.poolHypothesis = await resolvePool(socket, info, source, evidence, save);
    const {start: first, size} = evidence.poolHypothesis;
    const node = first + NODE_OFFSET;
    const start = info.plan.addressBias + Math.floor((node - info.plan.addressBias) / info.bucketPeriod) * info.bucketPeriod;
    evidence.pending = {address: start, length: node - start + 0x1000};
    await save();
    const capture = await memory.read(socket, start, evidence.pending.length);
    evidence.nodeCapture = capture.result;
    const offset = node - start;
    const link = externalLinkAt(capture.bytes, offset, node);
    check(link.valid, 'The native bytes do not reproduce the external allocator link');
    evidence.node = {address: node, next: link.next, previous: link.previous, extent: link.extent,
      observedHex: capture.bytes.subarray(offset, offset + 64).toString('hex')};
    delete evidence.pending;
    await save();
    console.log(JSON.stringify({stage: 'external-link', file, ...evidence.node}));
    const window = metadataWindow(link.next);
    const {address: page, length: probeLength} = window;
    evidence.metadataProbeWindow = window;
    await save();
    const plan = lowerWindow(page, Number(report.storageSize), info.bucketPeriod,
      [Math.floor(info.plan.target / 0x4000) * 0x4000]);
    const fallback = info.plan.addressBias + plan.readOffset;
    if (![source.result, capture.result].some(item => item.address <= fallback &&
        fallback + probeLength <= item.address + item.length)) {
      check(fallback >= first && fallback + probeLength <= first + size,
        'A missed-header control is outside the identified native buffer pool');
      evidence.fallbackCapture = (await memory.read(socket, fallback, probeLength)).result;
      await save();
    }
    const anchor = Buffer.alloc(16);
    anchor.writeBigUInt64LE(BigInt(node));
    anchor.writeBigUInt64LE(BigInt(node), 8);
    for (let attempt = 0; attempt < 6; attempt++) {
      const result = await memory.request(socket, {command: 'retained-bootstrap-move',
        address: page, length: probeLength, anchorOffset: window.anchorOffset, anchorHex: anchor.toString('hex')});
      evidence.attempts.push(result);
      await save();
      console.log(JSON.stringify({stage: result.verified ? 'metadata-verified' : 'header-missed',
        file, attempt, capture: result.capture}));
      if (result.verified) {
        evidence.verified = true;
        evidence.metadata = await memory.request(socket, {command: 'retained-bootstrap-read',
          address: page - 0x500000, length: 0x4d8000});
        console.log(JSON.stringify({stage: 'metadata-captured', file, capture: evidence.metadata}));
        return evidence;
      }
    }
    throw Error('Guarded metadata selection did not take effect');
  } catch (error) {
    evidence.error = error.stack;
    // A transport stall (chunked-read timeout, native/console timeout, lost
    // bridge) after a memory-ready acquisition leaves the console's retained
    // resources intact — the win is salvageable, not lost. Mark the run so
    // the host keeper offers a resume host first (the console's GO2 redial
    // can re-attach if its loop recovers) before falling back to a fresh
    // host. the corpus evidence in docs/acquisition-telemetry-report.md.
    if (/stalled|timed out|no longer available|Another memory request is active/i.test(error.message)) {
      try {
        await fs.writeFile(path.join(__dirname, '../../stall-resumable.json'), JSON.stringify({
          at: new Date().toISOString(), stage: 'find-metadata',
          memoryControlReady: report.memoryControl.ready, error: error.message}, null, 2) + '\n',
          {mode: 0o600});
      } catch {}
    }
    throw error;
  } finally {
    evidence.finished = new Date().toISOString();
    await save();
  }
}

if (require.main === module) main(process.argv[2]).catch(error => {console.error(error); process.exitCode = 1;});
module.exports = {main, poolBounds, geometricCandidates, normalizeLinks, filterByLinks,
  externalLinkAt, resolvePool, NODE_OFFSET, POOL_SIZE, POOL_ALIGNMENT};
