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
// Every rewritten URL retains its public source for SDK retries, including
// responses cut off mid-body. At capacity, leave new URLs public instead of
// evicting a mapping that an in-flight reader could still need.
const relays = new Map(), downloads = new Map();
const maxMappings = 4096;
function remember(map, prefix, source, url) {
  const local = new URL(url);
  if (local.origin !== endpoint.origin || !local.pathname.startsWith(prefix) ||
      (!map.has(local.pathname) && map.size >= maxMappings)) return false;
  map.set(local.pathname, {source, direct: false});
  return true;
}

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
            if (local !== parsed[field] && (!claimed || claimed(parsed[field], local) !== false)) {
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
  delete opts.auth;
  const privateHeaders = new Set(['host', 'authorization', 'proxy-authorization']);
  if (Array.isArray(opts.headers)) {
    const pairs = [];
    for (let i = 0; i + 1 < opts.headers.length; i += 2) {
      if (!privateHeaders.has(String(opts.headers[i]).toLowerCase())) pairs.push(opts.headers[i], opts.headers[i + 1]);
    }
    opts.headers = pairs;
  } else {
    opts.headers = {...opts.headers};
    for (const name of Object.keys(opts.headers)) if (privateHeaders.has(name.toLowerCase())) delete opts.headers[name];
  }
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
  const relay = local && relays.get(path);
  const download = local && ['GET', 'HEAD'].includes(String(opts.method || 'GET').toUpperCase()) && downloads.get(path);
  const mapping = relay || download;
  if (mapping && mapping.direct) toUpstream(opts, mapping.source);
  const relayed = relay && !relay.direct;
  const cached = download && !download.direct;
  // The official action can log the relay ID in debug output, so the host also
  // requires this guest's token, which only the bootstrap settings hold.
  if (relayed) {
    const auth = `Bearer ${config.token}`;
    if (Array.isArray(opts.headers)) { // Node's raw [name, value, ...] form.
      const pairs = [];
      for (let i = 0; i + 1 < opts.headers.length; i += 2) {
        if (String(opts.headers[i]).toLowerCase() !== 'authorization') pairs.push(opts.headers[i], opts.headers[i + 1]);
      }
      opts.headers = [...pairs, 'Authorization', auth];
    } else {
      opts.headers = {...opts.headers};
      for (const name of Object.keys(opts.headers)) if (name.toLowerCase() === 'authorization') delete opts.headers[name];
      opts.headers.Authorization = auth;
    }
  }
  const cacheService = host.endsWith('.actions.githubusercontent.com');
  const cacheLookup = cacheService && path === servicePath + 'GetCacheEntryDownloadURL';
  const cacheCreate = cacheService && config.store_uploads === true && path === servicePath + 'CreateCacheEntry';
  const observe = response => {
    if (cacheLookup) inspect(response, ['signed_download_url', 'signedDownloadUrl'], '/lease', (source, url) => remember(downloads, '/object/', source, url));
    if (cacheCreate) inspect(response, ['signed_upload_url', 'signedUploadUrl'], '/upload', (source, url) => remember(relays, '/upload/', source, url));
    if (relayed && response.statusCode === 503 && response.headers['x-bivouac-relay'] === 'unavailable') relay.direct = true;
    if (cached) {
      const failed = () => { download.direct = true; };
      response.prependOnceListener('error', failed);
      response.prependOnceListener('aborted', failed);
      response.prependOnceListener('close', () => { if (!response.complete) failed(); });
      if (response.statusCode >= 400) {
        failed();
        // A private lease rejection must remain retryable by the storage SDK.
        // The retry receives the public source's own status and normal trust.
        response.statusCode = 503;
      }
    }
  };
  const request = original.call(https, opts, cb ? response => { observe(response); cb(response); } : undefined);
  if (!cb && (cacheLookup || cacheCreate || relayed || cached)) request.prependOnceListener('response', observe);
  if (relayed || cached) request.prependListener('error', () => { mapping.direct = true; });
  return request;
};
