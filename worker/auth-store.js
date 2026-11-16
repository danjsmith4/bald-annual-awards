const key = '_settings/auth-v1.json';
const encoder = new TextEncoder();
const hex = bytes => Array.from(new Uint8Array(bytes), x => x.toString(16).padStart(2, '0')).join('');
const bytes = value => Uint8Array.from(value.match(/../g), x => parseInt(x, 16));
const fields = ['ADMIN_PASSPHRASE', 'BOOSTER_PASSPHRASE', 'CUSTOMER_PASSPHRASE'];
const recoveryHash = '13bbf497afc16695c6b04ebdbc22b99bcb360f8d4a924debf9a32c2afbe63fe7';
const recoveryExpires = Date.parse('2026-11-18T23:59:59Z');
const reply = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });

async function derive(password, salt) {
  const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: bytes(salt), iterations: 100000, hash: 'SHA-256' }, material, 256));
}
function equal(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return difference === 0;
}
function validate(config) {
  if (config?.version !== 1 || !/^[a-f0-9]{64}$/.test(config.sessionSecret)) throw Error('Invalid stored authentication settings.');
  for (const field of fields) {
    const credential = config.credentials?.[field];
    if (!credential || !/^[a-f0-9]{32}$/.test(credential.salt) || !/^[a-f0-9]{64}$/.test(credential.hash)) throw Error('Invalid stored credentials.');
  }
}
export async function loadAuthSettings(env) {
  if (!env.BALLOTS || (env.SESSION_SECRET && fields.every(name => env[name]))) return env;
  const object = await env.BALLOTS.get(key);
  if (!object) return env;
  const config = await object.json();
  validate(config);
  const resolved = { ...env };
  const storedCredentials = {};
  for (const name of fields) if (!env[name]) {
    resolved[name] = config.credentials[name].hash;
    storedCredentials[name] = config.credentials[name];
  }
  resolved.SESSION_SECRET = env.SESSION_SECRET || config.sessionSecret;
  Object.defineProperty(resolved, '__storedCredentials', { value: storedCredentials });
  Object.defineProperty(resolved, '__bindingSources', { value: { ...env.__bindingSources, ...Object.fromEntries(Object.keys(storedCredentials).map(name => [name, 'private-storage'])), SESSION_SECRET: env.SESSION_SECRET ? (env.__bindingSources?.SESSION_SECRET || 'request') : 'private-storage' } });
  return resolved;
}
export async function verifyPassphrase(password, env, name) {
  if (typeof password !== 'string' || password.length > 200) return false;
  const credential = env.__storedCredentials?.[name];
  return credential ? equal(await derive(password, credential.salt), credential.hash) : equal(password, env[name]);
}

// One-time, expiring recovery. Only a token's SHA-256 digest is in the source.
// The token itself and password values are never committed or returned by APIs.
export async function provisionAuth(req, env, { tokenHash = recoveryHash, expires = recoveryExpires } = {}) {
  const url = new URL(req.url);
  if (req.method !== 'POST') return reply({ error: 'Not found.' }, 404);
  if (req.headers.get('origin') !== url.origin) return reply({ error: 'Request not allowed.' }, 403);
  const token = req.headers.get('authorization')?.replace(/^Bearer /, '') || '';
  if (Date.now() > expires || !equal(hex(await crypto.subtle.digest('SHA-256', encoder.encode(token))), tokenHash)) return reply({ error: 'Not authorized.' }, 401);
  if (!env.BALLOTS) return reply({ error: 'Private storage unavailable.' }, 503);
  if (await env.BALLOTS.get(key)) return reply({ error: 'Authentication is already configured. Recovery is disabled.' }, 409);
  const body = await req.json();
  if (fields.some(name => typeof body[name] !== 'string' || body[name].length < 12 || body[name].length > 200)) return reply({ error: 'Every password must be 12-200 characters.' }, 400);
  const credentials = {};
  for (const name of fields) {
    const salt = hex(crypto.getRandomValues(new Uint8Array(16)));
    credentials[name] = { salt, hash: await derive(body[name], salt) };
  }
  const config = { version: 1, credentials, sessionSecret: hex(crypto.getRandomValues(new Uint8Array(32))), createdAt: new Date().toISOString() };
  const result = await env.BALLOTS.put(key, JSON.stringify(config), { onlyIf: new Headers({ 'If-None-Match': '*' }), httpMetadata: { contentType: 'application/json', cacheControl: 'private, no-store' } });
  if (!result) return reply({ error: 'Authentication was configured by another request. Recovery is disabled.' }, 409);
  return reply({ ok: true });
}
