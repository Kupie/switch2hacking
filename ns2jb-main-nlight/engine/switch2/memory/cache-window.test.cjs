'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {windowThresholds} = require('./cache-window.cjs');

test('falls back to the fixed constants when no samples are available', () => {
  assert.deepEqual(windowThresholds([], []), {margin: 300, release: 0x2600});
  assert.deepEqual(windowThresholds([NaN, -Infinity], [0, -5]), {margin: 300, release: 0x2600});
});

test('accepts within a fraction of the best observed values', () => {
  const margins = [100, 400, 500, 250];
  const releases = [0x1000, 0x3000, 0x4000, 0x2000];
  const {margin, release} = windowThresholds(margins, releases);
  assert.equal(margin, Math.round(500 * 0.75));
  assert.equal(release, Math.round(0x4000 * 0.8));
});

test('ignores non-finite margins and non-positive releases when finding the best', () => {
  const margins = [NaN, 600, Infinity, 200];
  const releases = [0x5000, 0x2000, 10];
  const {margin, release} = windowThresholds(margins, releases);
  assert.equal(margin, Math.round(600 * 0.75));
  assert.equal(release, Math.round(0x5000 * 0.8));
});
