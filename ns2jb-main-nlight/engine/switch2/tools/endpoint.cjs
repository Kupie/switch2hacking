const net = require('node:net');
const fs = require('node:fs/promises');
const crypto = require('node:crypto');

function requestOnce(socketPath, command, timeoutMs = 180000) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath);
    let input = '';
    socket.setEncoding('utf8');
    socket.setTimeout(timeoutMs, () => socket.destroy(Error('Memory request timed out; it was not replayed')));
    socket.on('error', reject);
    socket.on('connect', () => socket.write(JSON.stringify(command) + '\n'));
    socket.on('data', part => {
      input += part;
      if (input.length > 16 * 1024 * 1024) socket.destroy(Error('Memory reply exceeded its limit'));
    });
    socket.on('end', () => {
      try {
        const result = JSON.parse(input);
        if (result.error) throw Error(result.error);
        resolve(result);
      } catch (error) {reject(error);}
    });
  });
}

async function request(socketPath, command, timeoutMs, busyWindowMs = 3000) {
  const deadline = Date.now() + busyWindowMs;
  for (;;) {
    try {return await requestOnce(socketPath, command, timeoutMs);}
    catch (error) {
      // The busy reply is sent before dispatch. Every other failure is final.
      if (error.message !== 'Another memory request is active' || Date.now() >= deadline) throw error;
      await new Promise(resolve => setTimeout(resolve, 50));
    }
  }
}

// Read in bounded chunks with a short per-chunk deadline. A single large
// read hides console-transport stalls behind the full request timeout and
// wedges the whole acquisition behind ~3 attempts x the full deadline; a
// chunked read surfaces a stall within one chunk-deadline and names the
// offset where the transport stopped. The aggregate reply keeps the field
// shape of a single-chunk reply ({result, address, length, sha256, ...}).
async function read(socketPath, address, length, {chunkSize = 0x80000, chunkTimeoutMs = 60000,
    busyWindowMs = 60000} = {}) {
  let first;
  const parts = [];
  for (let at = 0; at < length; at += chunkSize) {
    const size = Math.min(chunkSize, length - at);
    let reply;
    try {reply = await request(socketPath, {command: 'read', address: address + at, length: size},
      chunkTimeoutMs, busyWindowMs);}
    catch (error) {throw Error('Memory read stalled at offset 0x' + (address + at).toString(16) +
      ' (chunk ' + size + ' of ' + length + ' bytes): ' + error.message);}
    const bytes = await fs.readFile(reply.outputFile);
    if (reply.address !== address + at || reply.length !== size || bytes.length !== size ||
        crypto.createHash('sha256').update(bytes).digest('hex') !== reply.sha256)
      throw Error('Saved memory read differs from its request or hash');
    if (!first) first = {reply};
    parts.push(bytes);
  }
  const bytes = Buffer.concat(parts);
  const result = {...first.reply, address, length,
    sha256: crypto.createHash('sha256').update(bytes).digest('hex')};
  return {result, bytes};
}

module.exports = {request, read};
