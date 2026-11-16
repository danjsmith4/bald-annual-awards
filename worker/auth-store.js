const key = '_settings/auth-v1.json';
const encoder = new TextEncoder();
const hex = bytes => Array.from(new Uint8Array(bytes), x => x.toString(16).padStart(2, '0')).join('');
const bytes = value => Uint8Array.from(value.match(/../g), x => parseInt(x, 16));
const fields = ['ADMIN_PASSPHRASE', 'BOOSTER_PASSPHRASE', 'CUSTOMER_PASSPHRASE'];

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

