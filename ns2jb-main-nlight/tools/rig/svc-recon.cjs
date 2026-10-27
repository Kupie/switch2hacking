// Capability recon (read-only): probe which IPC services the game process
// can open through SM GetService. Each attempt opens + closes the handle.
// Runs on the live session; no writes, no crashes.
'use strict';
const path = require('node:path');
const fs = require('node:fs');
const dir = path.resolve(__dirname + '/runs/switch2-1u9ld7/switch2');
const session = require(dir + '/memory/session.cjs');

const SERVICES = [
  // expected for a game
  'fsp-srv', 'fsp:pr', 'fsp:ldr', 'fsp-si', 'fsp-pr',
  'ldr:ro', 'ro:1', 'ro:dmnt', 'ldr:dmnt',
  'bsd:u', 'bsd:s', 'bsd:a', 'bsd:n',
  'nvdrv', 'nvdrv:a', 'nvdrv:s', 'nvdrv:t', 'nvdbg',
  'sm:', 'sm:m', 'sm:dmnt',
  'pm:info', 'pm:dmnt', 'pm:shell', 'pm:boot',
  'spl:', 'spl:fs', 'spl:es', 'spl:ssl', 'spl:csrng', 'spl:manu',
  'es:', 'tc:', 'set:sys', 'set:cal', 'set:fd',
  'acc:u0', 'acc:aa', 'account:u', 'account:da',
  'time:u', 'time:a', 'time:s', 'time:sys',
  'hid', 'hid:dbg', 'hid:tmp', 'hid:sys',
  'vi:m', 'vi:u', 'vi:s',
  'appletAE', 'appletOC', 'apm', 'apm:sys',
  'gpio', 'i2c', 'uart', 'pinmux',
  'psm', 'psm:get', 'battery', 'lpdk:sk',
  'psc:m', 'pcv', 'pcv:arp', 'pcv: clock',
  'ncm', 'ncm:lru', 'prepo:u', 'prepo:sys', 'prepo:a2',
  'olsc:u', 'npns:sys', 'npns:u', 'err:e',
  'usb:pd', 'usb:hs', 'usb:pm', 'usb:ds', 'usb:obsv',
  'pd:c', 'pdm:qry', 'caps:a', 'caps:c', 'caps:u',
  'mm:u', 'odm', 'omm', 'omm:ipm',
  'tls:im', 'ssl:sys', 'ssl:u', 'dns:sys', 'dns:a',
  'srepo:u', 'srepo:sa', 'srepo:v',
  'wlan:loc', 'wlan:sf', 'nifm:u', 'nifm:s', 'nifm:a',
  'btm', 'bt:sys', 'btdrv', 'bluetooth', 'bluetooth:sys',
  'nfc:am', 'nfc:user', 'nfc:sys', 'nfp:user',
  'audio', 'audctl', 'audout:u', 'audin:u', 'audrec:u', 'audren:u',
  'codecctl', 'audioctrl',
  'fatal:p', 'fatal:u', 'creport:u', 'creport:s',
  'lm', 'lm:warn',
  'csysclip:r', 'csysclip:u', 'csysclip:m',
  'gpio:shared', 'tc:sys', 'tma', 'tma:sys',
  'gr:c', 'gr:u',
  'dpd', 'dps:e',
  'spsm', 'notification',
  'wlan:inf', 'wlan:dup',
  'ifsvc', 'miiimg', 'mii:u', 'mii:e', 'mii:sys',
  'lp2p:app', 'lp2p:sys',
  'bundle', 'boot:sys', 'boot:b', 'boot:d',
  'bpc', 'bpc:r', 'bpc:w',
  'battery:dep', 'charger',
  'fuse', 'fuse:private',
  'readonly', 'gc:vid', 'sdcard:cs',
];

async function main() {
  const {s} = await session.connect('svc-recon', 0x20000);
  const results = [];
  try {
    for (const name of SERVICES) {
      try {
        const handle = await s.openService(name);
        results.push({name, open: true, handle});
        try { await s.close(handle); } catch {}
        console.log('OPEN  ', name);
      } catch (e) {
        results.push({name, open: false, error: e.message.replace('Service unavailable: ', '')});
        console.log('closed', name, '|', e.message.replace('Service unavailable: ', '').slice(0, 40));
      }
    }
  } finally {
    try { await s.cleanup(); } catch {}
  }
  fs.writeFileSync(dir + '/svc-recon.json', JSON.stringify({at: new Date().toISOString(), results}, null, 1) + '\n');
  const opened = results.filter(r => r.open).map(r => r.name);
  console.log('\nOPENED (' + opened.length + '):', opened.join(', '));
}

main().catch(e => { console.error('FAILED:', e.message); process.exit(1); });
