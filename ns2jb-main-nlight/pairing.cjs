const fs = require('node:fs/promises');
const {pairingCode} = require('./engine/lib/connection.cjs');

async function savedPairing(file) {
  try {
    await fs.writeFile(file, JSON.stringify({version: 1, token: pairingCode()}) + '\n',
      {flag: 'wx', mode: 0o600});
  } catch (error) {if (error.code !== 'EEXIST') throw error;}
  const config = JSON.parse(await fs.readFile(file, 'utf8'));
  if (config.version !== 1 || !Array.isArray(config.token) || config.token.length !== 4 ||
      config.token.some(n => !Number.isSafeInteger(n) || n < 0 || n >= 2 ** 48))
    throw Error('Invalid saved pairing configuration; do not silently replace the console token');
  return config.token;
}
module.exports = {savedPairing};
