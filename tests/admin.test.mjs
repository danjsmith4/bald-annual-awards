import { test } from 'node:test';
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === 'cloudflare:workers') return { url: 'test:cloudflare-workers', shortCircuit: true };
    return nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    if (url === 'test:cloudflare-workers') return { format: 'module', source: `export const env = new Proxy({}, { get: (_, key) => globalThis.__nativeWorkerBindings?.[key], has: (_, key) => key in (globalThis.__nativeWorkerBindings || {}), ownKeys: () => Reflect.ownKeys(globalThis.__nativeWorkerBindings || {}), getOwnPropertyDescriptor: () => ({configurable:true,enumerable:true}) });`, shortCircuit: true };
    return nextLoad(url, context);
  },
});
const { default: worker } = await import('../worker/index.js');
import { tally } from '../worker/admin.js';
import vm from 'node:vm';
import { resolveBindings } from '../worker/bindings.js';
import { provisionAuth } from '../worker/auth-store.js';

function fixture() {
  const records = new Map();
  const env = {
    ADMIN_PASSPHRASE: 'test-admin', SESSION_SECRET: 'test-signing-secret',
    BOOSTER_PASSPHRASE: 'test-booster', CUSTOMER_PASSPHRASE: 'test-customer',
    BALLOTS: {
      async put(k, v, options = {}) {
        if (options.onlyIf?.get('If-None-Match') === '*' && records.has(k)) return null;
        records.set(k, JSON.parse(v));
        return { etag: 'test-etag' };
      },
      async list({ prefix, cursor, limit }) {
        const keys = [...records.keys()].filter(k => k.startsWith(prefix)).sort();
        const start = Number(cursor || 0);
        return { objects: keys.slice(start, start + limit).map(key => ({ key })), truncated: keys.length > start + limit, cursor: String(start + limit) };
      },
      async get(k) { return records.has(k) ? { json: async () => records.get(k) } : null; },
    },
  };
  async function call(path, body, cookie = '', origin = 'https://awards.test') {
    return worker.fetch(new Request('https://awards.test' + path, {
      method: body === undefined ? 'GET' : 'POST',
      headers: { cookie, origin, 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    }), env);
  }
  async function login() {
    const res = await call('/api/admin/login', { password: 'test-admin' });
    assert.equal(res.status, 200);
    assert.match(res.headers.get('set-cookie'), /HttpOnly; Secure; SameSite=Strict/);
    return res.headers.get('set-cookie').split(';')[0];
  }
  return { env, records, call, login };
}

test('admin authentication is separate from voter access and rejects forged, expired, rotated and cross-origin sessions', async () => {
  const { env, call, login } = fixture();
  assert.equal((await call('/api/admin/votes')).status, 401);
  assert.equal((await call('/api/admin/login', { password: 'test-booster' })).status, 401);
  assert.equal((await call('/api/admin/login', { password: 'test-admin' }, '', 'https://other.test')).status, 403);
  const voter = await call('/api/login', { role: 'booster', password: 'test-booster' });
  assert.equal((await call('/api/admin/votes', undefined, voter.headers.get('set-cookie').split(';')[0])).status, 401);
  const cookie = await login();
  assert.equal((await call('/api/admin/votes', undefined, cookie)).status, 200);
  assert.equal((await call('/api/admin/votes', undefined, cookie + '0')).status, 401);
  const expired = cookie.replace(/\.\d+\./, '.1.');
  assert.equal((await call('/api/admin/votes', undefined, expired)).status, 401);
  const logout = await call('/api/admin/logout', {}, cookie);
  assert.match(logout.headers.get('set-cookie'), /Max-Age=0/);
  env.ADMIN_PASSPHRASE = 'rotated';
  assert.equal((await call('/api/admin/votes', undefined, cookie)).status, 401);
});

test('missing admin configuration fails closed and empty storage returns zero standings', async () => {
  const { env, call, login } = fixture();
  const cookie = await login();
  const data = await (await call('/api/admin/votes', undefined, cookie)).json();
  assert.equal(data.ballots.length, 0);
  assert.equal(data.awards.length, 7);
  assert(tally(data.ballots).every(r => r.total === 0 && r.nominees.length === 0));
  delete env.ADMIN_PASSPHRASE;
  assert.equal((await call('/api/admin/login', { password: 'test-admin' })).status, 503);
  assert.equal((await call('/api/admin/votes', undefined, cookie)).status, 401);
});

test('configuration errors identify the exact missing secret without revealing values', async () => {
  const { env, call } = fixture();
  delete env.SESSION_SECRET;
  let status = await (await call('/api/admin/session')).json();
  assert.equal(status.configured, false);
  assert.deepEqual(status.missingSecrets, ['SESSION_SECRET']);
  let error = await (await call('/api/admin/login', { password: 'test-admin' })).json();
  assert.match(error.error, /Missing Worker secrets: SESSION_SECRET\./);
  assert(!error.error.includes('test-admin'));
  env.SESSION_SECRET = 'restored';
  delete env.ADMIN_PASSPHRASE;
  status = await (await call('/api/admin/session')).json();
  assert.deepEqual(status.missingSecrets, ['ADMIN_PASSPHRASE']);
  delete env.SESSION_SECRET;
  status = await (await call('/api/admin/session')).json();
  assert.deepEqual(status.missingSecrets, ['ADMIN_PASSPHRASE', 'SESSION_SECRET']);
});

test('dashboard secret names with spaces and invisible characters work through the actual Worker entrypoint', async () => {
  const { env, call } = fixture();
  env[' ADMIN_PASSPHRASE '] = env.ADMIN_PASSPHRASE;
  env['\u200BSESSION_SECRET\u00A0'] = env.SESSION_SECRET;
  delete env.ADMIN_PASSPHRASE;
  delete env.SESSION_SECRET;
  const status = await (await call('/api/admin/session')).json();
  assert.equal(status.configured, true);
  assert.deepEqual(status.secretStatus, { ADMIN_PASSPHRASE: 'available', SESSION_SECRET: 'available' });
  assert.equal(status.build, 'stored-auth-v4');
  assert.equal(status.voteStorageBound, true);
  const login = await call('/api/admin/login', { password: 'test-admin' });
  assert.equal(login.status, 200);
  const cookie = login.headers.get('set-cookie').split(';')[0];
  assert.equal((await call('/api/admin/votes', undefined, cookie)).status, 200);
  assert.equal((await call('/api/login', { role: 'booster', password: 'test-booster' })).status, 200);
});

test('binding resolution preserves exact names and secret values and rejects ambiguous aliases', async () => {
  assert.equal(resolveBindings({ ADMIN_PASSPHRASE: 'exact', ' ADMIN_PASSPHRASE ': 'alias' }).ADMIN_PASSPHRASE, 'exact');
  assert.equal(resolveBindings({ ' ADMIN_PASSPHRASE ': ' value with spaces ' }).ADMIN_PASSPHRASE, ' value with spaces ');
  assert.equal(resolveBindings({ ' ADMIN_PASSPHRASE': 'a', 'ADMIN_PASSPHRASE ': 'b' }).ADMIN_PASSPHRASE, undefined);
  const { env, call } = fixture();
  env.ADMIN_PASSPHRASE = '';
  const status = await (await call('/api/admin/session')).json();
  assert.equal(status.configured, false);
  assert.equal(status.secretStatus.ADMIN_PASSPHRASE, 'empty');
  assert.equal((await call('/api/admin/login', { password: '' })).status, 503);
});

test('native Cloudflare env recovers secrets absent from the request environment', async () => {
  const { env, call } = fixture();
  globalThis.__nativeWorkerBindings = { ADMIN_PASSPHRASE: env.ADMIN_PASSPHRASE, SESSION_SECRET: env.SESSION_SECRET };
  delete env.ADMIN_PASSPHRASE;
  delete env.SESSION_SECRET;
  try {
    const status = await (await call('/api/admin/session')).json();
    assert.equal(status.configured, true);
    assert.equal(status.bindingSources.ADMIN_PASSPHRASE, 'native');
    const login = await call('/api/admin/login', { password: 'test-admin' });
    assert.equal(login.status, 200);
    assert.equal((await call('/api/admin/votes', undefined, login.headers.get('set-cookie').split(';')[0])).status, 200);
  } finally { delete globalThis.__nativeWorkerBindings; }
});

test('binding accessors are read using the original runtime object', () => {
  const env = {};
  Object.defineProperty(env, 'ADMIN_PASSPHRASE', { get() { assert.equal(this, env); return 'test-admin'; } });
  assert.equal(resolveBindings(env).ADMIN_PASSPHRASE, 'test-admin');
});

test('private stored auth enables all logins without environment secrets; setup is authorized and one-time', async () => {
  const { env, records, call } = fixture();
  for (const name of ['ADMIN_PASSPHRASE', 'SESSION_SECRET', 'BOOSTER_PASSPHRASE', 'CUSTOMER_PASSPHRASE']) delete env[name];
  const token = 'disposable-test-only-bootstrap-token';
  const tokenHash = Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token))).toString('hex');
  const passwords = { ADMIN_PASSPHRASE: 'test-admin-password', BOOSTER_PASSPHRASE: 'test-booster-password', CUSTOMER_PASSPHRASE: 'test-customer-password' };
  const make = (auth = token, origin = 'https://awards.test') => new Request('https://awards.test/api/internal/provision-auth', { method: 'POST', headers: { origin, authorization: 'Bearer ' + auth, 'Content-Type': 'application/json' }, body: JSON.stringify(passwords) });
  const options = { tokenHash, expires: Date.now() + 60000 };
  assert.equal((await provisionAuth(make('wrong'), env, options)).status, 401);
  assert.equal((await provisionAuth(make(token, 'https://other.test'), env, options)).status, 403);
  assert.equal((await provisionAuth(make(), env, { tokenHash, expires: 1 })).status, 401);
  assert.equal((await provisionAuth(make(), env, options)).status, 200);
  assert.equal((await provisionAuth(make(), env, options)).status, 409);
  const stored = JSON.stringify([...records.values()]);
  for (const password of Object.values(passwords)) assert(!stored.includes(password));
  const status = await (await call('/api/admin/session')).json();
  assert.equal(status.configured, true);
  assert.equal(status.bindingSources.ADMIN_PASSPHRASE, 'private-storage');
  assert.equal((await call('/api/admin/login', { password: 'wrong' })).status, 401);
  const admin = await call('/api/admin/login', { password: passwords.ADMIN_PASSPHRASE });
  assert.equal(admin.status, 200);
  assert.equal((await call('/api/admin/votes', undefined, admin.headers.get('set-cookie').split(';')[0])).status, 200);
  for (const role of ['booster', 'customer']) {
    const login = await call('/api/login', { role, password: passwords[role === 'booster' ? 'BOOSTER_PASSPHRASE' : 'CUSTOMER_PASSPHRASE'] });
    assert.equal(login.status, 200);
    const data = await login.json();
    assert.equal((await call('/api/vote', { name: role, answers: data.categories.map(category => category.includes('Moment') ? data.momentOptions[0] : 'Nominee') }, login.headers.get('set-cookie').split(';')[0])).status, 200);
  }
  const publicPage = await (await call('/')).text();
  assert(!publicPage.includes(passwords.ADMIN_PASSPHRASE));
  assert.equal([...records.keys()].filter(k => k.startsWith('2026/')).length, 2);
  env.ADMIN_PASSPHRASE = 'native-admin';
  assert.equal((await call('/api/admin/login', { password: 'native-admin' })).status, 200);
});

test('pagination returns every stored ballot, tallies normalize case/spacing, detect ties, and separate voter groups', async () => {
  const { records, call, login } = fixture();
  for (let i = 0; i < 61; i++) records.set('2026/booster/' + i + '.json', {
    role: 'booster', name: 'Voter ' + i, submittedAt: new Date().toISOString(),
    votes: [{ category: 'Staff of the Year', nomination: i < 30 ? (i % 2 ? ' PIE ' : 'Pie') : i < 60 ? 'Hula' : 'Someone  Else' }],
  });
  records.set('2026/customer/test.json', { role: 'customer', name: 'Customer', votes: [{ category: 'Customers Staff of the Year', nomination: 'Pie' }] });
  records.set('2025/booster/old.json', { role: 'booster', name: 'Old', votes: [] });
  const cookie = await login();
  let cursor = null;
  const all = [];
  do {
    const res = await call('/api/admin/votes' + (cursor ? '?cursor=' + cursor : ''), undefined, cookie);
    assert.equal(res.status, 200);
    const data = await res.json();
    all.push(...data.ballots);
    cursor = data.nextCursor;
  } while (cursor);
  assert.equal(all.length, 62);
  const results = tally(all);
  const staff = results.find(r => r.category === 'Staff of the Year');
  assert.equal(staff.total, 61);
  assert.deepEqual(staff.nominees.map(n => n.count), [30, 30, 1]);
  assert.equal(staff.nominees[2].name, 'Someone Else');
  assert.equal(results.find(r => r.category === 'Customers Staff of the Year').total, 1);
});

test('real voter submissions are visible in admin results and updates count once', async () => {
  const { call, login } = fixture();
  const res = await call('/api/login', { role: 'booster', password: 'test-booster' });
  const voterCookie = res.headers.get('set-cookie').split(';')[0];
  const { momentOptions } = await res.json();
  const body = { name: '<img src=x onerror=alert(1)>', answers: ['Uzer', 'Pie', 'Hula', momentOptions[0], 'Lupin'] };
  assert.equal((await call('/api/vote', body, voterCookie)).status, 200);
  body.answers[1] = 'Other staff';
  assert.equal((await call('/api/vote', body, voterCookie)).status, 200);
  const data = await (await call('/api/admin/votes', undefined, await login())).json();
  assert.equal(data.ballots.length, 1);
  assert.equal(data.ballots[0].votes[1].nomination, 'Other staff');
  const adminPage = await call('/admin');
  assert.equal(adminPage.status, 200);
  assert.equal(adminPage.headers.get('cache-control'), 'no-store');
  const html = await adminPage.text();
  assert(!html.includes(body.name));
  assert(!html.includes('test-admin'));
  const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
  new Function(script);
  assert(!script.includes('innerHTML'));
  const home = await (await call('/')).text();
  assert(home.includes('href="/admin"'));
  new Function(home.match(/<script>([\s\S]*?)<\/script>/)[1]);
});

test('unreadable storage fails visibly rather than returning incomplete vote totals', async () => {
  const { records, call, login } = fixture();
  records.set('2026/booster/broken.json', { role: 'booster', name: 'Broken', votes: [{}] });
  assert.equal((await call('/api/admin/votes', undefined, await login())).status, 500);
});

test('dashboard renders leaders, every vote, search and table pagination without HTML injection', async () => {
  const { call } = fixture();
  const html = await (await call('/admin')).text();
  class Element {
    children = []; textContent = ''; value = ''; disabled = false;
    classList = { toggle() {} };
    append(...nodes) { this.children.push(...nodes); }
    replaceChildren(...nodes) { this.children = [...nodes]; }
  }
  const nodes = new Map();
  const document = { createElement: () => new Element(), getElementById: id => {
    if (!nodes.has(id)) nodes.set(id, new Element());
    return nodes.get(id);
  } };
  const context = vm.createContext({ document, fetch: async () => ({ ok: true, json: async () => ({ authenticated: false, configured: true }) }), console });
  vm.runInContext(html.match(/<script>([\s\S]*?)<\/script>/)[1], context);
  vm.runInContext(`awards=[['booster','Staff of the Year']];ballots=Array.from({length:61},(_,i)=>({name:i===0?'<img src=x onerror=alert(1)>':'Voter '+i,role:'booster',submittedAt:'2026-11-16T12:00:00Z',votes:[{category:'Staff of the Year',nomination:i<31?'Pie':'Hula'}]}));render();`, context);
  assert.equal(nodes.get('votes-body').children.length, 50);
  assert.equal(nodes.get('vote-caption').textContent, '61 individual votes across 61 ballots');
  assert.equal(nodes.get('votes-body').children[0].children[0].textContent, '<img src=x onerror=alert(1)>');
  const leader = nodes.get('leaders').children[0];
  assert.equal(leader.children[2].textContent, 'Pie');
  assert.equal(leader.children[3].textContent, 'Leading with 31 votes');
  nodes.get('next').onclick();
  assert.equal(nodes.get('votes-body').children.length, 11);
  assert.equal(nodes.get('page-label').textContent, 'Page 2 of 2');
  nodes.get('search').value = 'Hula';
  nodes.get('search').oninput();
  assert.equal(nodes.get('votes-body').children.length, 30);
  assert.equal(nodes.get('page-label').textContent, 'Page 1 of 1');
});
