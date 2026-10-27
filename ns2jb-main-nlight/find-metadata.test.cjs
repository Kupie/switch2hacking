// Offline tests for the find-metadata pool search: no console, no network.
// The fake reader plays the role of the retained-memory read path.
const test = require('node:test');
const assert = require('node:assert/strict');
const {resolvePool, normalizeLinks, filterByLinks, geometricCandidates, poolBounds,
  externalLinkAt, NODE_OFFSET, POOL_SIZE, POOL_ALIGNMENT} =
  require('./engine/switch2/retained/find-metadata.cjs');

const PAGE = 0x4000, BIAS = 0, CYCLE = 0x28000;
const info = {bucketPeriod: CYCLE, plan: {addressBias: BIAS}};
const TRUE_START = 0x13c000000;            // pool-aligned
const SEED = 0x13d000000;                  // a verified page inside the pool
const FAR_LINK = 0x110000000;              // external allocator link target

function u64(value) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(value));
  return b;
}

// Sparse fake memory: word map + zero default.
function makeReader(words) {
  const reads = [];
  const reader = async (start, length) => {
    reads.push({start, length});
    const bytes = Buffer.alloc(length);
    for (const [address, value] of words) {
      if (address >= start && address + 8 <= start + length)
        u64(value).copy(bytes, address - start);
    }
    return {result: {address: start, length}, bytes};
  };
  reader.reads = reads;
  return reader;
}

function nodeWords(start, next = FAR_LINK, extent = 0x100000) {
  return [[start + NODE_OFFSET, next], [start + NODE_OFFSET + 8, next],
    [start + NODE_OFFSET + 16, extent]];
}

function sourceCapture(extraWords = []) {
  const words = [[SEED, SEED], ...extraWords]; // self-link by default
  const bytes = Buffer.alloc(0x500000);
  for (const [address, value] of words) {
    if (address >= SEED && address + 8 <= SEED + 0x500000) u64(value).copy(bytes, address - SEED);
  }
  return {result: {address: SEED, length: 0x500000}, bytes};
}

test('geometricCandidates contains the true start and is aligned', () => {
  const candidates = geometricCandidates(SEED);
  assert.ok(candidates.includes(TRUE_START));
  assert.ok(candidates.length <= 16);
  assert.ok(candidates.every(start => start % POOL_ALIGNMENT === 0 && start <= SEED &&
    SEED + PAGE <= start + POOL_SIZE));
});

test('node predicate enforces the external-link structure', () => {
  const bytes = Buffer.concat([u64(FAR_LINK), u64(FAR_LINK), u64(0x100000), Buffer.alloc(32)]);
  assert.equal(externalLinkAt(bytes, 0, TRUE_START + NODE_OFFSET).valid, true);
  // The link must be external: a `next` near the claimed node fails.
  const near = TRUE_START + NODE_OFFSET + 0x100000;
  const nearBytes = Buffer.concat([u64(near), u64(near), u64(0x100000)]);
  assert.equal(externalLinkAt(nearBytes, 0, TRUE_START + NODE_OFFSET).valid, false);
  // next !== previous must not pass.
  const broken = Buffer.concat([u64(FAR_LINK), u64(FAR_LINK + 8), u64(0x100000)]);
  assert.equal(externalLinkAt(broken, 0, TRUE_START + NODE_OFFSET).valid, false);
  // Implausible extent must not pass.
  const badExtent = Buffer.concat([u64(FAR_LINK), u64(FAR_LINK), u64(0x1000)]);
  assert.equal(externalLinkAt(badExtent, 0, TRUE_START + NODE_OFFSET).valid, false);
});

test('resolvePool: phase-0 broad links cut the probe set before any retarget', async () => {
  // The 2026-10-24 fix: links from the eager 5 MiB capture narrow the
  // geometric candidates BEFORE the node-probe loop (each probe is a
  // console cache-alias retarget — the demonstrated wedge unit). A
  // corroborated link inside every candidate but pointing only into the
  // true pool must shrink probeSet, and only narrowed candidates' nodes may
  // be read.
  const reader = makeReader(nodeWords(TRUE_START));
  const evidence = {};
  // Link sources spread over the first pages (inside every candidate).
  // Values span the pool's low END and high END: a low value excludes every
  // upward neighbor, a top-of-pool value (31 MiB, inside 32 MiB but beyond
  // any lower neighbor's reach) excludes every downward neighbor — so only
  // the true candidate holds both and ranks first.
  const corroboration = [
    [SEED + PAGE, TRUE_START + 0x1000],
    [SEED + 2 * PAGE, TRUE_START + 0x1f00000],
  ];
  const result = await resolvePool(null, info, sourceCapture(corroboration), evidence,
    async () => {}, reader);
  assert.equal(result.start, TRUE_START);
  assert.equal(result.verified, true);
  const search = evidence.poolSearch;
  assert.ok(search.phase0);
  assert.ok(search.phase0.probeSet < search.phase0.geometric,
    'phase0 must shrink the probe set when links corroborate');
  assert.ok(search.phase0.probeSet >= 1);
  // Best-first + early stop: the corroborated links rank the true start
  // first, so ONE probe read resolves the walk instead of probing the set.
  assert.ok(search.earlyStop, 'expected an early-stop record');
  assert.equal(search.earlyStop.probed, 1);
  assert.equal(reader.reads.length, 1);
  assert.equal(result.start, TRUE_START);
});

test('resolvePool: node probe resolves the true pool directly', async () => {
  const reader = makeReader(nodeWords(TRUE_START));
  const evidence = {};
  const result = await resolvePool(null, info, sourceCapture(), evidence, async () => {}, reader);
  assert.equal(result.start, TRUE_START);
  assert.equal(result.verified, true);
  assert.equal(evidence.poolSearch.method, 'node-predicate');
  // Best-first early stop: with tied link support the walk still resolves
  // the true pool with fewer reads than the full candidate set, and never
  // falls through to the exhaustive sweep.
  const search = evidence.poolSearch;
  assert.ok(search.earlyStop, 'expected early-stop on first valid node');
  assert.equal(reader.reads.length, search.earlyStop.probed);
  assert.ok(reader.reads.length <= search.candidates.length);
  assert.equal(search.method, 'node-predicate');
});

test('resolvePool: two valid nodes narrowed by a corroborated link', async () => {
  const wrong = TRUE_START + POOL_ALIGNMENT; // upward neighbor candidate
  const reader = makeReader([...nodeWords(TRUE_START), ...nodeWords(wrong)]);
  // Corroborated link: source at SEED (inside both), value at TRUE_START
  // (inside the true pool only).
  const source = sourceCapture([[SEED + PAGE, TRUE_START]]);
  const result = await resolvePool(null, info, source, {}, async () => {}, reader);
  assert.equal(result.start, TRUE_START);
  assert.equal(result.verified, true);
});

test('resolvePool: self-link seed with no node evidence never yields a wrong singleton', async () => {
  // The review's counterexample: identical zero bytes everywhere, one
  // self-link. The true start is indistinguishable from the other 15
  // candidates by links alone, and no node resolves.
  const reader = makeReader([]);
  const evidence = {};
  await assert.rejects(
    resolvePool(null, info, sourceCapture(), evidence, async () => {}, reader),
    error => error.message.includes('ambiguous') && error.message.includes('0x13c000000'));
  assert.equal(evidence.poolSearch.resolved.ambiguous.length, 16);
});

test('resolvePool: uncorroborated links never eliminate, ambiguity is reported', async () => {
  // A bare pointer-shaped word (nonzero tail) pointing outside every
  // candidate must not eliminate the true pool.
  const reader = makeReader([]);
  const evidence = {};
  await assert.rejects(
    resolvePool(null, info, sourceCapture([[SEED + PAGE, 0x13b000000], [SEED + PAGE + 8, 1]]),
      evidence, async () => {}, reader));
  assert.equal(evidence.poolSearch.resolved.ambiguous.length, 16);
});

test('resolvePool: corroborated links shrink toward the true pool', async () => {
  // zeroTail link: source at SEED, value at TRUE_START, everything after the
  // word zero. Eliminates every upward candidate; downward ones survive, so
  // the outcome is an explicit ambiguity, still never a wrong singleton.
  const reader = makeReader([]);
  const evidence = {};
  await assert.rejects(
    resolvePool(null, info, sourceCapture([[SEED + PAGE, TRUE_START]]), evidence, async () => {}, reader));
  const ambiguous = evidence.poolSearch.resolved.ambiguous;
  assert.ok(ambiguous.includes(TRUE_START));
  assert.ok(ambiguous.every(start => start <= TRUE_START));
  assert.ok(ambiguous.length < 16);
});

test('filterByLinks: only zeroTail links eliminate', () => {
  const candidates = [0x13c000000, 0x13c200000];
  const bare = [{source: SEED, value: 0x13a000000, zeroTail: false}];
  assert.deepEqual(filterByLinks(candidates, bare), candidates, 'bare links must not eliminate');
  const corroborated = [{source: SEED, value: 0x13c000000, zeroTail: true}];
  assert.deepEqual(filterByLinks(candidates, corroborated), [0x13c000000]);
  assert.deepEqual(filterByLinks(candidates, []), candidates, 'absence of evidence eliminates nothing');
});

test('normalizeLinks: disputed sources are quarantined, duplicates collapse', () => {
  const candidates = [TRUE_START];
  const links = [
    {source: SEED, value: 0x13c000000, zeroTail: true},
    {source: SEED, value: 0x13c000000, zeroTail: true},       // exact duplicate
    {source: SEED + PAGE, value: 0x13c010000, zeroTail: true},
    {source: SEED + PAGE, value: 0x13c020000, zeroTail: true}, // disputed source
  ];
  const result = normalizeLinks(links, candidates);
  assert.equal(result.links.length, 1);
  assert.deepEqual(result.disputed, [SEED + PAGE]);
  assert.equal(result.relevant.length, 1);
  // Neighbor evidence (source outside every candidate) never constrains.
  const neighbor = normalizeLinks([{source: 0x100000000, value: 0x13c000000, zeroTail: true}], candidates);
  assert.equal(neighbor.relevant.length, 0);
});

test('resolvePool: disputed sources are quarantined, not fatal', async () => {
  // The phase-2 bucket reads overlap the seed capture's range. A later read
  // observing a different value at a seed-capture source must quarantine that
  // source and finish with an explicit ambiguity, never a crash or a guess.
  const reader = async (start, length) => {
    const bytes = Buffer.alloc(length);
    u64(SEED).copy(bytes, 0); // harmless filler at capture-relative 0
    if (SEED >= start && SEED + 8 <= start + length)
      u64(TRUE_START).copy(bytes, SEED - start); // disputes the seed self-link
    return {result: {address: start, length}, bytes};
  };
  const evidence = {};
  await assert.rejects(
    resolvePool(null, info, sourceCapture(), evidence, async () => {}, reader));
  assert.equal(evidence.poolSearch.resolved.ambiguous.length, 16);
  assert.ok(evidence.poolSearch.disputed?.length, 'the disputed source should be recorded');
});

test('poolBounds regression: seeded filter keeps legacy behavior', () => {
  const links = [{source: SEED, value: SEED, zeroTail: true}];
  const bounds = poolBounds(links, SEED);
  assert.ok(bounds.candidates.length >= 1 && bounds.candidates.length <= 16);
  assert.ok(bounds.candidates.includes(TRUE_START));
});
