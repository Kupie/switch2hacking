'use strict';

function buildExtentPath({scratch, segments, basename, extent = 0x2440, end = extent}) {
  if (!Number.isInteger(end) || end > extent || end < scratch.length + basename.length + 2)
    throw Error('Invalid diagnostic path extent');
  const bytes = Buffer.alloc(extent + 1, '/');
  bytes[extent] = 0;
  bytes.write(scratch + '/');
  for (let i = 0; i < segments.length; i++) {
    const offset = (i + 1) * 0x800;
    if (offset >= end) break;
    const segment = '/' + segments[i] + '/';
    if (offset + Buffer.byteLength(segment) > end - Buffer.byteLength(basename))
      throw Error('Marker overlaps a segment');
    bytes.write(segment, offset);
  }
  bytes.write(basename, end - Buffer.byteLength(basename));
  bytes[end] = 0;
  const canonical = bytes.subarray(0, end).toString().replace(/\/{2,}/g, '/');
  return {bytes, canonical};
}

module.exports = {buildExtentPath};
