'use strict';

// Select the verified page containing the external allocator link (upstream
// kurumuz/ns2jb, c99f2da/9124089). Links in the first page of their 16 KiB
// block retain the established 16 KiB probe; links >= 4 KiB into the block
// need only their containing 4 KiB page, because a 16 KiB window there
// crosses into following pages that may not be readable — the fixed-window
// probe is the deterministic stage-3/4 killer this replaces.
function metadataWindow(next, override = process.env.NS2_METADATA_PROBE_4K) {
  if (!Number.isSafeInteger(next) || next < 2 ** 32 || next >= 2 ** 39)
    throw Error('Expected a canonical external allocator link');
  if (override !== undefined && override !== '0' && override !== '1')
    throw Error('NS2_METADATA_PROBE_4K must be 0 or 1');
  const originalBlockOffset = next % 0x4000;
  const narrow = override === '1' || (override !== '0' && originalBlockOffset >= 0x1000);
  const length = narrow ? 0x1000 : 0x4000;
  const address = Math.floor(next / length) * length;
  return {address, length, anchorOffset: next - address, originalBlockOffset,
    selection: override === undefined ? 'observed-link' : override === '1' ? 'forced-4k' : 'forced-16k'};
}

module.exports = {metadataWindow};