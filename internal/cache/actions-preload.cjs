// The official runner injects cache endpoints after job hooks. Observe only the
// authorized CacheService responses that carry signed archive URLs: download
// lookups and, when the host stores uploads, cache creation. Metadata and all
// other HTTPS traffic remain untouched. No runtime token enters Bivouac.
'use strict';
const fs = require('node:fs');
const https = require('node:https');
let config;
try { config = JSON.parse(fs.readFileSync(process.env.BIVOUAC_CACHE_CONFIG, 'utf8')); }
catch { return; }
const endpoint = new URL(config.url);
const original = https.request;
const servicePath = '/twirp/github.actions.results.api.v1.CacheService/';
// Relayed upload IDs and their signed Azure URLs. Once a relay fails, the
// storage SDK's retries for that upload go straight to Azure.
const relays = new Map(), direct = new Set();

function claim(path, source) {
  return new Promise(resolve => {
    const body = JSON.stringify({url: source});
    const request = original.call(https, new URL(path, endpoint), {
      method: 'POST', ca: config.ca, agent: false,
      headers: {'Authorization': `Bearer ${config.token}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body)}
    }, response => {
      let data = '';
      response.on('data', chunk => { if (data.length < 16384) data += chunk; });
      response.on('error', () => resolve(source));
      response.on('end', () => {
        try { const parsed = JSON.parse(data); resolve(response.statusCode === 200 && typeof parsed.url === 'string' ? parsed.url : source); }
        catch { resolve(source); }
      });
    });
    request.setTimeout(2500, () => request.destroy());
    request.on('error', () => resolve(source));
    request.end(body);
  });
}

// Swap the signed URL in a small successful JSON response for the host's.
function inspect(response, names, path, claimed) {
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
          const field = names.find(name => typeof parsed[name] === 'string' && parsed[name]);
          if (field) {
            const local = await claim(path, parsed[field]);
            if (local !== parsed[field]) {
              if (claimed) claimed(parsed[field], local);
              parsed[field] = local;
              output = Buffer.from(JSON.stringify(parsed));
            }
          }
        } catch { /* Cache is optional; retain the exact upstream response. */ }
        if (output !== body) delete response.headers['content-length'];
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

// Send a relayed upload request to Azure with the same operation. With a proxy
// configured this connects directly: it is only the fallback path.
function toUpstream(opts, source) {
  const upstream = new URL(source);
  const query = (opts.path || '').split('?').slice(1).join('?');
  opts.protocol = 'https:';
  opts.hostname = opts.host = upstream.hostname;
  opts.port = upstream.port || 443;
  opts.path = upstream.pathname + upstream.search + (query ? '&' + query : '');
  delete opts.ca;
  delete opts.servername;
  opts.headers = {...opts.headers};
  for (const name of Object.keys(opts.headers)) if (name.toLowerCase() === 'host') delete opts.headers[name];
}

https.request = function(input, options, callback) {
  let opts;
  if (typeof input === 'string' || input instanceof URL) {
    const u = new URL(input);
    opts = {protocol: u.protocol, hostname: u.hostname, port: u.port, path: u.pathname + u.search, ...(typeof options === 'object' ? options : {})};
  } else { opts = {...input}; }
  const cb = typeof options === 'function' ? options : callback;
  const host = opts.hostname || opts.host || '';
  const local = host === endpoint.hostname && String(opts.port || 443) === endpoint.port;
  if (local) opts.ca = config.ca;
  const path = (opts.path || '').split('?')[0];
  const relay = local && path.startsWith('/upload/') && relays.has(path.slice(8)) ? path.slice(8) : '';
  if (relay && direct.has(relay)) toUpstream(opts, relays.get(relay));
  const relayed = relay && !direct.has(relay);
  const cacheService = host.endsWith('.actions.githubusercontent.com');
  const cacheLookup = cacheService && path === servicePath + 'GetCacheEntryDownloadURL';
  const cacheCreate = cacheService && config.store_uploads === true && path === servicePath + 'CreateCacheEntry';
  const observe = response => {
    if (cacheLookup) inspect(response, ['signed_download_url', 'signedDownloadUrl'], '/lease');
    if (cacheCreate) inspect(response, ['signed_upload_url', 'signedUploadUrl'], '/upload', (source, url) => relays.set(new URL(url).pathname.slice(8), source));
    if (relayed && response.statusCode === 503 && response.headers['x-bivouac-relay'] === 'unavailable') direct.add(relay);
  };
  const request = original.call(https, opts, cb ? response => { observe(response); cb(response); } : undefined);
  if (!cb && (cacheLookup || cacheCreate || relayed)) request.prependOnceListener('response', observe);
  if (relayed) request.prependListener('error', () => direct.add(relay));
  return request;
};
