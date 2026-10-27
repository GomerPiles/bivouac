'use strict';
// Manual-only fixture. Credentials and official action output stay in the
// disposable guest. Report only fixed outcomes and numeric measurements.
const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const crypto = require('node:crypto');
const {spawn} = require('node:child_process');
const {pipeline} = require('node:stream/promises');
const pin = '0057852bfaa89a56745cba8c7296529d2fc39830';
const mode = process.env.INPUT_MODE;
const nonce = process.env.INPUT_NONCE;
const root = path.join(process.env.RUNNER_TEMP, 'bivouac-cache-validation');
// 24 MiB fits one Put Blob; 192 MiB takes three 64 MiB blocks and a block list,
// so a relayed save exercises both upload paths.
const sizes = [24, 192].map(n => n * 1024 * 1024);
const directories = sizes.map((_, i) => path.join(root, 'archive-' + i));
const keys = sizes.map((_, i) => ['bivouac-validation', process.platform, nonce, i].join('-'));
const bundles = {};
let stage = 'inputs';
// A fixed, credential-free checkpoint lets an isolated host owner inject an
// outage at the intended stage without retaining official-action output.
function checkpoint(value) {
  stage = value;
  const temporary = path.join(root, 'stage.tmp');
  fs.writeFileSync(temporary, JSON.stringify({stage: value}), {mode: 0o600});
  fs.renameSync(temporary, path.join(root, 'stage.json'));
}

let storing = false;
function check(value, message) {
  if (!value) {
    console.error('Validation check failed: ' + message);
    throw new Error(message);
  }
}
function get(url, options = {}) {
  return new Promise((resolve, reject) => {
    const request = https.get(url, options, resolve);
    request.setTimeout(30000, () => request.destroy());
    request.on('error', reject);
  });
}
async function metrics() {
  if (!process.env.BIVOUAC_CACHE_CONFIG) return;
  const b = JSON.parse(fs.readFileSync(process.env.BIVOUAC_CACHE_CONFIG));
  storing = b.store_uploads === true;
  const response = await get(b.url + '/metrics', {ca: b.ca, agent: false,
    headers: {authorization: 'Bearer ' + b.token}});
  check(response.statusCode === 200, 'metrics status');
  let body = '';
  for await (const chunk of response) { body += chunk; check(body.length <= 4096, 'metrics bound'); }
  return JSON.parse(body);
}
// The host commits a relayed save after acknowledging it, so wait briefly for
// the guest's upload counters to account for both archives. Every save must
// have gone through the relay, none back to direct upload.
async function uploads(before, field) {
  const deadline = Date.now() + 60000;
  let after = await metrics();
  while (after.uploads[field] - before.uploads[field] < sizes.length && Date.now() < deadline) {
    await new Promise(resolve => setTimeout(resolve, 500));
    after = await metrics();
  }
  const delta = name => after.uploads[name] - before.uploads[name];
  const other = field === 'stored' ? 'skipped' : 'stored';
  check(delta('relayed') === sizes.length && delta(field) === sizes.length && delta(other) === 0 && delta('fallbacks') === 0, 'upload storage ' + field);
  const u = after.uploads;
  console.log('Upload storage verified: relayed=' + u.relayed + ' stored=' + u.stored + ' skipped=' + u.skipped + ' fallbacks=' + u.fallbacks);
}
// Wait up to two minutes for the operator to stop the isolated controller.
// Returns the last counters read while the service was still available.
async function outage(last) {
  checkpoint('awaiting-outage');
  console.log('Waiting for isolated cache-service outage');
  const deadline = Date.now() + 120000;
  while (Date.now() < deadline) {
    try { last = await metrics(); } catch { return last; }
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  check(false, 'cache service remained available');
}
async function bundle(kind) {
  const target = path.join(root, kind + '.cjs');
  const response = await get('https://raw.githubusercontent.com/actions/cache/' + pin + '/dist/' + kind + '-only/index.js');
  check(response.statusCode === 200, 'official action download');
  await pipeline(response, fs.createWriteStream(target, {mode: 0o600}));
  bundles[kind] = target;
}
function child(binary, args, env = process.env, observe, cwd) {
  return new Promise((resolve, reject) => {
    const p = spawn(binary, args, {env, cwd, stdio: ['ignore', 'pipe', 'pipe']});
    let bytes = 0, saved = false, restored = false, tail = '', category = 'unclassified';
    // Inspect only fixed markers. Action output may contain keys or raw errors;
    // never replay it, retain it on the host, or write it to diagnostics.
    const inspect = chunk => {
      if (observe) observe(chunk);
      bytes += chunk.length;
      const text = tail + chunk.toString();
      saved ||= text.includes('Cache saved with key:');
      restored ||= text.includes('Cache restored from key:');
      if (/ENOMEM|allocation failed|heap out of memory/i.test(text)) category = 'memory';
      else if (/ENOSPC|not enough space|disk full/i.test(text)) category = 'capacity';
      else if (/ECONNRESET|socket hang up|ETIMEDOUT|TLS|socket closed|stream closed/i.test(text)) category = 'transport';
      else if (/reserve cache|already exists|already being created|another job|409|conflict/i.test(text)) category = 'reservation';
      else if (/tar failed|tar.*exit|archive.*failed|Unable to resolve|Path Validation/i.test(text)) category = 'archive_filesystem';
      else if (/Event Validation|Key is not specified|not supported|not saving cache/i.test(text)) category = 'input_or_skip';
      else if (/Failed to save|Cache save failed|Cache service responded/i.test(text) && category === 'unclassified') category = 'upstream_save';
      else if (/Cache not found|Failed to restore/i.test(text) && category === 'unclassified') category = 'restore';
      tail = text.slice(-64);
      if (bytes > 1024 * 1024) p.kill();
    };
    p.stdout.on('data', inspect);
    p.stderr.on('data', inspect);
    p.on('error', () => reject(new Error('child unavailable')));
    p.on('close', code => {
      if (code === 0) resolve({saved, restored, category});
      else { console.error('Validation child failed: exit=' + Number(code) + ' category=' + category); reject(new Error('child failed')); }
    });
  });
}
async function archive(kind, i, suffix = '', directory = directories[i]) {
  const output = path.join(root, kind + '-' + i + suffix + '.output');
  const state = path.join(root, kind + '-' + i + suffix + '.state');
  // The official Windows BSD-tar/zstd extraction uses a relative cache.tar.
  // Concurrent action processes need separate working directories for it.
  const working = path.join(root, 'work-' + kind + '-' + i + suffix);
  fs.mkdirSync(working);
  fs.writeFileSync(output, ''); fs.writeFileSync(state, '');
  const result = await child(process.execPath, [bundles[kind]], {
    ...process.env, INPUT_PATH: directory, INPUT_KEY: keys[i] + suffix,
    INPUT_RESTORE_KEYS: '', INPUT_FAIL_ON_CACHE_MISS: 'true', INPUT_LOOKUP_ONLY: 'false',
    GITHUB_OUTPUT: output, GITHUB_STATE: state
  }, undefined, working);
  const succeeded = kind === 'save' ? result.saved : result.restored;
  if (!succeeded) console.error('Archive result missing: operation=' + kind + ' index=' + i + ' category=' + result.category);
  check(succeeded, 'official archive operation');
  if (kind === 'restore') {
    const fields = fs.readFileSync(output, 'utf8');
    check(fields.includes('cache-hit=true') || /cache-hit<<[^\n]+\ntrue\r?\n/.test(fields), 'exact GitHub archive hit');
    const data = fs.readFileSync(path.join(directories[i], 'payload'));
    const expected = fs.readFileSync(path.join(directories[i], 'checksum'), 'utf8');
    check(data.length === sizes[i] && crypto.createHash('sha256').update(data).digest('hex') === expected, 'restored integrity');
  }
}
function prepare(i, directory = directories[i]) {
  fs.mkdirSync(directory);
  const output = fs.openSync(path.join(directory, 'payload'), 'wx');
  const hash = crypto.createHash('sha256');
  try {
    for (let n = 0; n < sizes[i]; n += 1024 * 1024) {
      const bytes = crypto.randomBytes(1024 * 1024);
      fs.writeSync(output, bytes); hash.update(bytes);
    }
  } finally { fs.closeSync(output); }
  fs.writeFileSync(path.join(directory, 'checksum'), hash.digest('hex'));
}
async function releases() {
  const url = 'https://github.com/cli/cli/releases/download/v2.102.0/gh_2.102.0_windows_amd64.zip';
  const signatures = [];
  for (let i = 0; i < 2; i++) {
    const target = path.join(root, 'release-' + i);
    let headers = '';
    // A unique canonical request gets a fresh GitHub redirect. Inspect response
    // headers only in guest memory; signed locations never reach output/files.
    const fresh = url + '?bivouac_validation=' + process.env.GITHUB_RUN_ID + '-' + i;
    await child(process.platform === 'win32' ? 'curl.exe' : 'curl',
      ['--fail', '--silent', '--show-error', '--location', '--max-time', '180', '--dump-header', '-', '--output', target, fresh],
      process.env, chunk => { headers = (headers + chunk.toString()).slice(0, 32768); });
    const location = /^location:\s*(https:\/\/(?:release-assets|objects)\.githubusercontent\.com\/[^\r\n]+)/im.exec(headers);
    check(location, 'signed release redirect missing');
    signatures.push(new URL(location[1]).search);
    const data = fs.readFileSync(target);
    check(data.length === 15512013 && crypto.createHash('sha256').update(data).digest('hex') ===
      'ae64e556ecc240b200f7eba60d550e4bb60d78e860e69dd88c449405b86067f4', 'public release integrity');
    if (i === 0) await new Promise(resolve => setTimeout(resolve, 1100));
  }
  check(signatures[0] !== signatures[1], 'release signatures did not rotate');
  console.log('Fresh signed release URLs verified: distinct=true');
}
async function main() {
  check(['save', 'restore', 'fallback', 'outage', 'interrupt', 'limited', 'mixed'].includes(mode) && /^[a-z0-9-]{1,64}$/.test(nonce), 'validation inputs');
  check(!fs.existsSync(root), 'fresh guest sentinel');
  fs.mkdirSync(root, {mode: 0o700});
  checkpoint('bundles');
  await Promise.all(['save', 'restore'].map(bundle));
  checkpoint('metrics');
  const before = await metrics();
  if (mode === 'fallback') check(!before, 'cache must be disabled for fallback validation');
  else check(before, 'cache integration missing');
  if (mode === 'limited' || mode === 'interrupt') check(storing, mode + ' validation requires store_uploads');
  if (mode === 'outage') {
    checkpoint('release-before-outage');
    await releases();
    const primed = await metrics();
    check(primed.release_proxy.hits > before.release_proxy.hits, 'release cache hit before outage');
    console.log('Release cache verified before outage: hits=' + primed.release_proxy.hits + ' misses=' + primed.release_proxy.misses);
    checkpoint('outage');
    await outage(primed);
  }
  if (mode === 'interrupt') {
    // Both saves go through the relay; the controller stops before they finish,
    // and the storage SDK's retries must reach Azure directly.
    checkpoint('interrupt');
    sizes.forEach((_, i) => prepare(i));
    const saves = Promise.all(sizes.map((_, i) => archive('save', i)));
    saves.catch(() => {});
    let relayed = before;
    const deadline = Date.now() + 60000;
    while (relayed.uploads.relayed - before.uploads.relayed < sizes.length && Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 200));
      relayed = await metrics();
    }
    check(relayed.uploads.relayed - before.uploads.relayed === sizes.length, 'saves not relayed');
    console.log('Relayed saves started: archives=2');
    const last = await outage(relayed);
    const ended = (last.uploads.stored + last.uploads.skipped + last.uploads.fallbacks) -
      (before.uploads.stored + before.uploads.skipped + before.uploads.fallbacks);
    check(ended < sizes.length, 'relayed saves finished before the outage');
    await saves;
    console.log('Relayed saves interrupted by the outage reached GitHub: archives=2 unfinished=' + (sizes.length - ended));
  }
  if (['save', 'limited', 'fallback', 'outage'].includes(mode)) {
    checkpoint('save');
    sizes.forEach((_, i) => prepare(i));
    await Promise.all(sizes.map((_, i) => archive('save', i)));
    console.log('Concurrent GitHub saves passed: archives=2');
    // A `limited` save exceeds the object limit, so it is relayed without a copy.
    if (mode === 'limited') await uploads(before, 'skipped');
    else if (storing && mode === 'save') await uploads(before, 'stored');
  }
  if (['restore', 'mixed', 'limited', 'fallback', 'outage', 'interrupt'].includes(mode)) {
    checkpoint('restore');
    if (['limited', 'fallback', 'outage', 'interrupt'].includes(mode)) directories.forEach(d => fs.rmSync(d, {recursive: true}));
    const work = sizes.map((_, i) => archive('restore', i));
    if (mode === 'mixed') sizes.forEach((_, i) => {
      const directory = path.join(root, 'upload-' + i);
      prepare(i, directory);
      const suffix = '-mixed-' + process.env.GITHUB_RUN_ID + '-' + process.env.GITHUB_RUN_ATTEMPT;
      work.push(archive('save', i, suffix, directory));
    });
    await Promise.all(work);
    console.log('Concurrent GitHub restores and integrity passed: archives=2');
    if (storing && mode === 'mixed') await uploads(before, 'stored');
  }
  checkpoint('releases');
  await releases();
  checkpoint('counters');
  if (mode === 'outage' || mode === 'interrupt') {
    console.log('Cache outage preserved GitHub saves, restores, and release downloads');
    return;
  }
  const after = await metrics();
  // A fresh guest's first restore of a stored save is local. Without upload
  // storage, it fills from upstream instead.
  if (after && mode === 'restore') {
    const hits = after.archives.hits - before.archives.hits, misses = after.archives.misses - before.archives.misses;
    check(storing ? hits === 2 && misses === 0 : hits + misses === 2, 'first restores must be local hits after stored saves');
  }
  if (after && mode !== 'limited') check(after.release_proxy.hits > before.release_proxy.hits, 'release cache hit missing');
  console.log('Public release downloads and integrity passed: downloads=2');
  if (after) console.log('Numeric cache snapshot: ' + JSON.stringify(after));
}
main().catch(() => { console.error('Isolated cache validation failed: stage=' + stage); process.exitCode = 1; });
