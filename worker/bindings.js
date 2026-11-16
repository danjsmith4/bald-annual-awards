const names = ['ADMIN_PASSPHRASE', 'SESSION_SECRET', 'BOOSTER_PASSPHRASE', 'CUSTOMER_PASSPHRASE', 'BALLOTS'];
const cleanName = name => name.normalize('NFKC').replace(/[\u200B-\u200D\u2060\uFEFF]/g, '').trim().toUpperCase();

// Dashboard-created bindings may contain invisible whitespace in their names.
// Match only our known settings; never alter secret VALUES or invent defaults.
export function resolveBindings(source, nativeSource = {}) {
  const env = source && typeof source === 'object' ? source : {};
  const native = nativeSource && typeof nativeSource === 'object' ? nativeSource : {};
  const resolved = { ...env };
  const sources = {};
  for (const name of names) {
    for (const [label, object] of [['request', env], ['native', native]]) {
      // Read from the original receiver. Some runtime bindings are accessors.
      if (name in object && object[name] !== undefined) {
        resolved[name] = object[name]; sources[name] = label; break;
      }
      const candidates = Object.getOwnPropertyNames(object).filter(key => cleanName(key) === name);
      // Ambiguous aliases fail closed rather than choosing a credential.
      if (candidates.length > 1) break;
      if (candidates.length === 1 && object[candidates[0]] !== undefined) {
        resolved[name] = object[candidates[0]]; sources[name] = label + '-normalized'; break;
      }
    }
  }
  Object.defineProperty(resolved, '__bindingSources', { value: sources });
  return resolved;
}

export function bindingStatus(env) {
  return Object.fromEntries(['ADMIN_PASSPHRASE', 'SESSION_SECRET'].map(name => [name,
    env[name] === undefined || env[name] === null ? 'missing'
      : typeof env[name] !== 'string' ? 'invalid-type'
      : env[name].length === 0 ? 'empty' : 'available',
  ]));
}
