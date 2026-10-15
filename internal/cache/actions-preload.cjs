// The official runner injects cache endpoints after job hooks. Observe only the
// authorized CacheService download response; metadata, uploads, and all other
// HTTPS traffic remain untouched. No runtime token enters Bivouac.
'use strict';
const fs = require('node:fs');
const https = require('node:https');
let config;
try { config = JSON.parse(fs.readFileSync(process.env.BIVOUAC_CACHE_CONFIG, 'utf8')); }
catch { return; }
const endpoint = new URL(config.url);
const original = https.request;

function lease(source) {
  return new Promise(resolve => {
    const body = JSON.stringify({url: source});
    const request = original.call(https, new URL('/lease', endpoint), {
      method: 'POST', ca: config.ca, agent: false,
      headers: {'Authorization': `Bearer ${config.token}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body)}
    }, response => {
      let data = '';
      response.on('data', chunk => { if (data.length < 16384) data += chunk; });
      response.on('error', () => resolve(source));
      response.on('end', () => {
        try { const parsed = JSON.parse(data); resolve(response.statusCode === 200 ? parsed.url : source); }
        catch { resolve(source); }
      });
    });
    request.setTimeout(2500, () => request.destroy());
    request.on('error', () => resolve(source));
    request.end(body);
  });
}

function inspect(response) {
  if (response.statusCode !== 200) return;
  const emit = response.emit;
  let chunks = [], size = 0, pending = false, closed;
  response.emit = function(event, ...args) {
    if (event === 'data') {
      size += args[0].length;
      if (size > 1024 * 1024) {
        response.emit = emit;
        for (const chunk of chunks) emit.call(response, 'data', chunk);
        return emit.call(response, event, ...args);
      }
      chunks.push(Buffer.from(args[0])); return true;
    }
    if (event === 'end') {
      pending = true;
      const body = Buffer.concat(chunks);
      (async () => {
        let output = body;
        try {
          const parsed = JSON.parse(body.toString('utf8'));
          const field = parsed.signed_download_url ? 'signed_download_url' : 'signedDownloadUrl';
          if (parsed[field]) {
            parsed[field] = await lease(parsed[field]);
            output = Buffer.from(JSON.stringify(parsed));
          }
        } catch { /* Cache is optional; retain the exact upstream response. */ }
        delete response.headers['content-length'];
        response.emit = emit;
        emit.call(response, 'data', output);
        emit.call(response, 'end');
        if (closed) emit.call(response, 'close', ...closed);
      })();
      return true;
    }
    if (event === 'close' && pending) { closed = args; return true; }
    return emit.call(response, event, ...args);
  };
}

https.request = function(input, options, callback) {
  let opts;
  if (typeof input === 'string' || input instanceof URL) {
    const u = new URL(input);
    opts = {protocol: u.protocol, hostname: u.hostname, port: u.port, path: u.pathname + u.search, ...(typeof options === 'object' ? options : {})};
  } else { opts = {...input}; }
  const cb = typeof options === 'function' ? options : callback;
  const host = opts.hostname || opts.host || '';
  if (host === endpoint.hostname && String(opts.port || 443) === endpoint.port) opts.ca = config.ca;
  const cacheLookup = host.endsWith('.actions.githubusercontent.com') &&
    (opts.path || '').split('?')[0] === '/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL';
  const request = original.call(https, opts, cb ? response => { if (cacheLookup) inspect(response); cb(response); } : undefined);
  if (!cb && cacheLookup) request.prependOnceListener('response', inspect);
  return request;
};
