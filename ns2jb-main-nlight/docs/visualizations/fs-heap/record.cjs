#!/usr/bin/env node
'use strict';
// Deterministic HTML/SVG capture; no console connection or device state is used.
const fs = require('node:fs');
const path = require('node:path');
const {pathToFileURL} = require('node:url');
const {spawn, spawnSync, execFileSync} = require('node:child_process');
const {once} = require('node:events');
const {performance} = require('node:perf_hooks');
const {chromium} = require('playwright-core');

function options(args) {
  const out = {width: 1920, fps: 30, workers: 4, encoder: 'auto', seconds: Infinity, preview: false};
  for (let i = 0; i < args.length; i++) {
    const key = args[i];
    if (key === '--preview') out.preview = true;
    else if (['--width', '--fps', '--workers', '--seconds', '--encoder'].includes(key)) {
      if (!args[i + 1] || args[i + 1].startsWith('--')) throw Error('Missing value for ' + key);
      const value = args[++i]; out[key.slice(2)] = key === '--encoder' ? value : Number(value);
    } else if (!key.startsWith('--') && !out.output) out.output = key;
    else throw Error('Unknown argument: ' + key);
  }
  if (![1280, 1920].includes(out.width) || ![24, 30, 60].includes(out.fps) ||
    !Number.isInteger(out.workers) || out.workers < 1 || out.workers > 8 || !(out.seconds > 0) ||
    !['auto', 'nvenc', 'cpu'].includes(out.encoder)) throw Error('Invalid renderer options');
  out.height = out.width * 9 / 16;
  out.output = path.resolve(out.output || path.join(__dirname, '../../../runs/visualizations/fs-heap-dark-1080p.mp4'));
  return out;
}
function encoderFor(wanted) {
  if (wanted === 'cpu') return 'libx264';
  // Test an actual encode, not just the compiled encoder list.
  const probe = spawnSync('ffmpeg', ['-hide_banner', '-loglevel', 'error', '-f', 'lavfi', '-i',
    'color=c=black:s=1920x1080:r=24', '-frames:v', '1', '-c:v', 'h264_nvenc', '-f', 'null', '-'],
    {encoding: 'utf8', timeout: 15000});
  if (probe.status === 0) return 'h264_nvenc';
  if (wanted === 'nvenc') throw Error('NVENC unavailable: ' + (probe.stderr || probe.error?.message));
  return 'libx264';
}
async function main() {
  const opt = options(process.argv.slice(2)), started = performance.now();
  fs.mkdirSync(path.dirname(opt.output), {recursive: true});
  const encoderName = opt.preview ? 'none' : encoderFor(opt.encoder);
  const executablePath = process.env.CHROME_BIN || execFileSync('which', ['google-chrome-stable'], {encoding: 'utf8'}).trim();
  const browser = await chromium.launch({executablePath, headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage']});
  const encoders = new Set(), errors = [];
  let temp;
  const pageFor = async () => {
    const page = await browser.newPage({viewport: {width: opt.width, height: opt.height}, deviceScaleFactor: 1});
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(pathToFileURL(path.join(__dirname, 'index.html')).href + '?capture');
    await page.evaluate(() => document.fonts.ready);
    return page;
  };
  try {
    const preview = await pageFor();
    const {duration, chapters} = await preview.evaluate(() => window.animation);
    if (opt.preview) {
      for (const [i, chapter] of chapters.entries()) {
        await preview.evaluate(t => window.renderAt(t), chapter.start + chapter.duration * .7);
        const overflow = await preview.evaluate(() => Array.from(document.querySelectorAll('svg text')).filter(el => {
          const box = el.getBBox(); return box.x < 0 || box.x + box.width > 1599;
        }).map(el => el.textContent));
        if (overflow.length) throw Error('Clipped text: ' + overflow.join(' | '));
        await preview.screenshot({path: path.join(path.dirname(opt.output), `chapter-${String(i + 1).padStart(2, '0')}.png`)});
      }
      if (errors.length) throw Error(errors.join('\n'));
      console.log('All beat previews passed at ' + opt.width + ' × ' + opt.height + '.');
      return;
    }
    await preview.close();
    const frames = Math.round(Math.min(duration, opt.seconds) * opt.fps);
    const workerCount = Math.min(opt.workers, frames);
    temp = fs.mkdtempSync(path.join(path.dirname(opt.output), '.fs-heap-render-'));
    let completed = 0;
    console.log(JSON.stringify({width: opt.width, height: opt.height, fps: opt.fps, frames, workers: workerCount, encoder: encoderName}));
    const progress = setInterval(() => console.log(`Rendered ${completed}/${frames} frames (${Math.round(completed / ((performance.now() - started) / 1000))} fps)`), 10000);
    async function renderPart(worker) {
      const page = await pageFor();
      const begin = Math.floor(frames * worker / workerCount), end = Math.floor(frames * (worker + 1) / workerCount);
      const filename = `part-${String(worker).padStart(3, '0')}.mp4`;
      const settings = encoderName === 'h264_nvenc'
        ? ['-c:v', encoderName, '-preset', 'p4', '-rc', 'vbr', '-cq', '24', '-b:v', '0']
        : ['-c:v', 'libx264', '-preset', 'veryfast', '-crf', '24', '-threads', '2'];
      const encoder = spawn('ffmpeg', ['-hide_banner', '-loglevel', 'error', '-y', '-f', 'image2pipe',
        '-vcodec', 'mjpeg', '-framerate', String(opt.fps), '-i', '-', '-an', ...settings,
        '-pix_fmt', 'yuv420p', '-video_track_timescale', '24000', path.join(temp, filename)],
        {stdio: ['pipe', 'inherit', 'inherit']});
      encoders.add(encoder);
      let encoderError;
      encoder.on('error', error => {encoderError = error;});
      encoder.stdin.on('error', error => {encoderError = error;});
      const complete = new Promise(resolve => encoder.once('close', code => resolve(code)));
      try {
        for (let frame = begin; frame < end; frame++) {
          if (encoderError) throw encoderError;
          await page.evaluate(t => window.renderAt(t), frame / opt.fps);
          const jpeg = await page.screenshot({type: 'jpeg', quality: 90});
          if (!encoder.stdin.write(jpeg)) await once(encoder.stdin, 'drain');
          completed++;
        }
        encoder.stdin.end();
        const code = await complete;
        if (code !== 0) throw Error(`Encoder ${worker} failed: ${code}`);
        return filename;
      } finally {
        if (encoder.exitCode === null) encoder.kill();
        encoders.delete(encoder);
        await page.close();
      }
    }
    let results;
    try {results = await Promise.allSettled(Array.from({length: workerCount}, (_, i) => renderPart(i)));}
    finally {clearInterval(progress);}
    const failed = results.filter(r => r.status === 'rejected');
    if (failed.length) throw new AggregateError(failed.map(r => r.reason), 'Capture failed');
    if (errors.length) throw Error(errors.join('\n'));
    fs.writeFileSync(path.join(temp, 'parts.txt'), results.map(r => `file '${r.value}'`).join('\n') + '\n');
    // Each part has the same codec settings; concatenate without re-encoding.
    execFileSync('ffmpeg', ['-hide_banner', '-loglevel', 'error', '-y', '-f', 'concat', '-safe', '1',
      '-i', path.join(temp, 'parts.txt'), '-c', 'copy', '-movflags', '+faststart',
      '-metadata', 'title=Inside the filesystem glitch', opt.output]);
    const elapsed = (performance.now() - started) / 1000;
    console.log(JSON.stringify({file: path.basename(opt.output), seconds: frames / opt.fps, fps: opt.fps,
      width: opt.width, height: opt.height, encoder: encoderName, workers: workerCount,
      renderSeconds: Number(elapsed.toFixed(2)), captureFps: Number((frames / elapsed).toFixed(1)), bytes: fs.statSync(opt.output).size}));
  } finally {
    for (const encoder of encoders) encoder.kill();
    await browser.close();
    if (temp) fs.rmSync(temp, {recursive: true, force: true});
  }
}
main().catch(error => {console.error(error.stack);
  for (const cause of error.errors || []) console.error(cause.stack || cause);
  process.exitCode = 1;
});
