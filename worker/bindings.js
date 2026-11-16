const names = ['ADMIN_PASSPHRASE', 'SESSION_SECRET', 'BOOSTER_PASSPHRASE', 'CUSTOMER_PASSPHRASE', 'BALLOTS'];
const cleanName = name => name.normalize('NFKC').replace(/[\u200B-\u200D\u2060\uFEFF]/g, '').trim().toUpperCase();

// Dashboard-created bindings may contain invisible whitespace in their names.
// Match only our known settings; never alter secret VALUES or invent defaults.
export function resolveBindings(source) {
  const env = source && typeof source === 'object' ? source : {};
  const resolved = Object.create(env);
  const keys = Object.getOwnPropertyNames(env);
  for (const name of names) {
    if (name in env) continue;
    const candidates = keys.filter(key => cleanName(key) === name);
    // An exact name wins. Ambiguous aliases fail closed rather than guessing.
    if (candidates.length === 1) resolved[name] = env[candidates[0]];
  }
  return resolved;
}

export function bindingStatus(env) {
  return Object.fromEntries(['ADMIN_PASSPHRASE', 'SESSION_SECRET'].map(name => [name,
    env[name] === undefined || env[name] === null ? 'missing'
      : typeof env[name] !== 'string' ? 'invalid-type'
      : env[name].length === 0 ? 'empty' : 'available',
  ]));
}
