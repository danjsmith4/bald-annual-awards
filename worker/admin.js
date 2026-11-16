import { bindingStatus } from './bindings.js';
import { verifyPassphrase } from './auth-store.js';
import { adminDiscord } from './discord.js';
const YEAR = 2026;
const AWARDS = [
  ['booster', 'Boosters Booster of the Year'],
  ['booster', 'Staff of the Year'],
  ['booster', 'Dev of the Year'],
  ['booster', 'Retard Moment of the Year'],
  ['booster', 'Boosters Customer of the Year'],
  ['customer', 'Customers Booster of the Year'],
  ['customer', 'Customers Staff of the Year'],
];
const encoder = new TextEncoder();
const cookieName = 'awards_admin';
const cookieFlags = '; HttpOnly; Secure; SameSite=Strict; Path=/api/admin/';
const reply = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), {
  status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers },
});
const missingSecrets = env => Object.entries(bindingStatus(env)).filter(([, status]) => status !== 'available').map(([name]) => name);
async function key(env) {
  return crypto.subtle.importKey('raw', encoder.encode(env.SESSION_SECRET + ':' + env.ADMIN_PASSPHRASE), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}
async function isAdmin(req, env) {
  if (missingSecrets(env).length) return false;
  const token = (req.headers.get('cookie') || '').split(';').map(x => x.trim()).find(x => x.startsWith(cookieName + '='))?.slice(cookieName.length + 1);
  if (!token) return false;
  const parts = token.split('.');
  if (parts.length !== 3 || !/^\d+$/.test(parts[1]) || Number(parts[1]) <= Date.now() || !/^[a-f0-9]{64}$/.test(parts[2])) return false;
  const bytes = Uint8Array.from(parts[2].match(/../g), x => parseInt(x, 16));
  return crypto.subtle.verify('HMAC', await key(env), bytes, encoder.encode(parts[0] + '.' + parts[1]));
}
export async function handleAdminRequest(req, env, publicPage) {
  const url = new URL(req.url);
  if (url.pathname === '/admin' || url.pathname === '/admin/') {
    return new Response(renderAdminPage(publicPage), { headers: {
      'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store',
      'X-Robots-Tag': 'noindex, nofollow', 'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'same-origin',
      'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'self' https://chatgpt.com",
    } });
  }
  if (req.method === 'POST' && req.headers.get('origin') !== url.origin) return reply({ error: 'Request not allowed.' }, 403);
  if (url.pathname === '/api/admin/session' && req.method === 'GET') return reply({ authenticated: await isAdmin(req, env), configured: missingSecrets(env).length === 0, missingSecrets: missingSecrets(env), secretStatus: bindingStatus(env), voteStorageBound: !!env.BALLOTS, bindingSources: env.__bindingSources || {}, build: 'stored-auth-v4' });
  if (url.pathname === '/api/admin/login' && req.method === 'POST') {
    if (missingSecrets(env).length) return reply({ error: 'Missing Worker secrets: ' + missingSecrets(env).join(', ') + '. Add them under Settings > Variables and Secrets, then deploy.' }, 503);
    const { password } = await req.json();
    if (!(await verifyPassphrase(password, env, 'ADMIN_PASSPHRASE'))) return reply({ error: 'Incorrect admin passphrase.' }, 401);
    const payload = crypto.randomUUID() + '.' + (Date.now() + 8 * 60 * 60 * 1000);
    const signature = Array.from(new Uint8Array(await crypto.subtle.sign('HMAC', await key(env), encoder.encode(payload)))).map(x => x.toString(16).padStart(2, '0')).join('');
    return reply({ ok: true }, 200, { 'Set-Cookie': cookieName + '=' + payload + '.' + signature + cookieFlags + '; Max-Age=28800' });
  }
  if (url.pathname === '/api/admin/logout' && req.method === 'POST') return reply({ ok: true }, 200, { 'Set-Cookie': cookieName + '=' + cookieFlags + '; Max-Age=0' });
  if (!(await isAdmin(req, env))) return reply({ error: 'Admin login required.' }, 401);
  if (url.pathname === '/api/admin/discord' || url.pathname === '/api/admin/discord/sync') return adminDiscord(req,env);
  if (url.pathname === '/api/admin/votes' && req.method === 'GET') {
    if (!env.BALLOTS) return reply({ error: 'Vote storage is unavailable.' }, 503);
    // Keep each request bounded; the dashboard follows every cursor before tallying.
    const listed = await env.BALLOTS.list({ prefix: YEAR + '/', limit: 25, cursor: url.searchParams.get('cursor') || undefined });
    const ballots = [];
    for (let offset = 0; offset < listed.objects.length; offset += 5) {
      const chunk = await Promise.all(listed.objects.slice(offset, offset + 5).map(async object => {
        const record = await env.BALLOTS.get(object.key);
        if (!record) throw Error('Ballot changed while loading. Refresh to try again.');
        const ballot = await record.json();
        if (!['booster', 'customer'].includes(ballot.role) || typeof ballot.name !== 'string' || !Array.isArray(ballot.votes) || ballot.votes.some(v => typeof v.category !== 'string' || typeof v.nomination !== 'string')) throw Error('An unreadable ballot was found.');
        return { id: object.key, name: ballot.name, role: ballot.role, submittedAt: ballot.submittedAt, votes: ballot.votes };
      }));
      ballots.push(...chunk);
    }
    return reply({ ballots, nextCursor: listed.truncated ? listed.cursor : null, awards: AWARDS });
  }
  return reply({ error: 'Not found.' }, 404);
}

export function tally(ballots, awards = AWARDS) {
  const results = awards.map(([role, category]) => ({ role, category, total: 0, nominees: new Map() }));
  for (const ballot of ballots) for (const vote of ballot.votes) {
    const result = results.find(r => r.role === ballot.role && r.category === vote.category);
    if (!result) continue;
    const display = vote.nomination.trim().replace(/\s+/g, ' ');
    if (!display) continue;
    const normalized = vote.nomineeId ? 'discord:' + vote.nomineeId : display.normalize('NFKC').toLowerCase();
    const nominee = result.nominees.get(normalized) || { name: display, count: 0 };
    nominee.count++;
    result.nominees.set(normalized, nominee);
    result.total++;
  }
  return results.map(r => ({ ...r, nominees: [...r.nominees.values()].sort((a, b) => b.count - a.count || a.name.localeCompare(b.name)) }));
}

function renderAdminPage(publicPage) {
  const sharedStyle = publicPage.match(/<style>([\s\S]*?)<\/style>/)?.[1] || '';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>Bald.gg - Awards Admin</title><style>${sharedStyle}
  .admin-title{font-size:clamp(38px,6vw,65px);letter-spacing:-2px;margin:20px 0}.toolbar{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin:26px 0}.toolbar button{width:auto}.outline{background:transparent!important;color:var(--gold)!important;border:1px solid var(--line)!important}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:25px 0 42px}.stat{background:var(--panel);border:1px solid var(--line);padding:20px;border-radius:10px}.stat strong{display:block;color:var(--gold);font-size:32px;margin-bottom:9px}.stat span{font-size:12px;color:var(--muted)}.leaders{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;margin:24px 0 50px}.leader{padding:24px;border:1px solid var(--line);border-radius:12px;background:linear-gradient(130deg,#211c10,#111);min-width:0}.leader h3{font-size:16px;line-height:1.6;margin:12px 0}.leader-name{color:var(--gold);font-size:22px;font-weight:bold;line-height:1.5;overflow-wrap:anywhere}.lead-count{color:var(--gold);font-size:14px;margin:12px 0}.standing{display:flex;justify-content:space-between;gap:18px;padding:10px 0;border-top:1px solid var(--line);font-size:13px;line-height:1.5}.standing span{overflow-wrap:anywhere}.standing b{white-space:nowrap}.leader summary{font-size:12px;color:var(--muted);cursor:pointer;margin:20px 0 14px}.tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:10px;margin:20px 0}table{border-collapse:collapse;width:100%;min-width:760px;font-size:13px;text-align:left}caption{text-align:left;padding:16px;color:var(--muted)}th,td{padding:15px;border-bottom:1px solid var(--line);vertical-align:top;line-height:1.6}th{background:#1b1810;color:var(--gold);font-size:11px;letter-spacing:1px}td{overflow-wrap:anywhere;max-width:350px}.pager{display:flex;gap:18px;align-items:center;justify-content:space-between;margin:22px 0 60px}.pager button{width:auto}button:disabled{opacity:.5;cursor:wait}.pager button:disabled{cursor:default}.admin-hint{max-width:600px}.notice{padding:14px;border:1px solid var(--line);border-radius:8px;color:var(--muted);line-height:1.7}.admin-search{max-width:530px}.adminhome{color:var(--muted);font-size:13px}.loading{color:var(--gold)}@media(max-width:650px){.stats{grid-template-columns:repeat(2,1fr)}.leaders{grid-template-columns:1fr}.toolbar{align-items:stretch}.pager{flex-wrap:wrap}.edition{letter-spacing:0}.stat{padding:16px}}
  </style></head><body><header><div class="brand">bald<span>.gg</span></div><div class="edition">AWARDS / ADMIN</div></header><main><a href="/" class="back" style="display:inline-block">&larr; Back to awards</a>
  <section id="admin-login" class="loginbox"><div class="eyebrow">STAFF ACCESS ONLY</div><h1 class="admin-title">Behind the<br><em>spotlight.</em></h1><p class="intro">Sign in to see the standings and every submitted vote.</p><form id="admin-form"><label for="admin-password">Admin passphrase</label><input type="password" id="admin-password" autocomplete="current-password" required maxlength="200"><p class="error" id="login-error" role="alert"></p><button class="primary" id="login-button">Open admin panel <span>&rarr;</span></button></form></section>
  <section id="dashboard" class="hidden"><div class="eyebrow">ANNUAL AWARDS / 2026</div><h1 class="admin-title">Every vote.<br><em>The full picture.</em></h1><div class="toolbar"><button class="primary" id="refresh">Refresh votes</button><button class="primary outline" id="admin-logout">Sign out</button><span id="updated" class="small" aria-live="polite"></span></div><p id="data-error" class="error" role="alert"></p><p class="notice admin-hint">Counts include all currently saved ballots. Updated ballots replace the previous ballot from that session. Nominee capitalization and extra spaces are grouped together; other spelling differences remain separate.</p>
  <div class="stats" id="stats"></div><h2>Who's winning</h2><p class="small">Leaders and ties in every category. Expand a card to see all nominees.</p><div id="leaders" class="leaders"></div>
  <section style="margin-bottom:48px;padding:24px;border:1px solid var(--line);border-radius:12px" aria-labelledby="discord-title"><div class="eyebrow">NOMINEES FROM YOUR SERVER</div><h2 id="discord-title">Discord connection</h2><p class="small">Use a bot already in your server with Server Members Intent enabled. This connection reads members and roles; it does not send messages or change Discord roles. After syncing, every person award requires selecting an eligible Discord member.</p><form id="discord-form"><label for="discord-guild">Discord server ID</label><input id="discord-guild" inputmode="numeric" required pattern="[0-9]{17,20}" placeholder="Right-click your Discord server > Copy Server ID"><label for="discord-token">Bot token</label><input id="discord-token" type="password" autocomplete="off" placeholder="Required for first setup; leave blank to keep the saved token"><p class="small">Entered only here; encrypted in private storage and never returned to your browser.</p><label for="discord-role-booster">Booster role IDs</label><input id="discord-role-booster" required placeholder="Role ID, or multiple role IDs separated by commas"><label for="discord-role-staff">Staff role IDs</label><input id="discord-role-staff" required placeholder="Role ID, or multiple role IDs separated by commas"><label for="discord-role-developer">Developer role IDs</label><input id="discord-role-developer" required placeholder="Role ID, or multiple role IDs separated by commas"><label for="discord-role-customer">Customer role IDs</label><input id="discord-role-customer" required placeholder="Role ID, or multiple role IDs separated by commas"><p class="small">Members with any listed role qualify. For customers, use a Customer role; to include everyone, use the server ID as the role ID. Bots are excluded.</p><p id="discord-error" class="error" role="alert"></p><p id="discord-status" class="small" aria-live="polite">Loading Discord settings...</p><div class="toolbar"><button id="discord-save" class="primary">Save and sync members</button><button id="discord-sync" class="primary outline" type="button">Refresh Discord members</button></div></form></section><h2>Every vote</h2><p class="small">Each nomination is listed separately, with the voter, ballot group, and submission time.</p><label for="search">Search votes</label><input type="search" id="search" class="admin-search" placeholder="Voter, nominee, category or ballot group"><div class="tablewrap"><table><caption id="vote-caption">No votes loaded yet</caption><thead><tr><th scope="col">VOTER</th><th scope="col">BALLOT</th><th scope="col">CATEGORY</th><th scope="col">VOTE</th><th scope="col">SUBMITTED</th></tr></thead><tbody id="votes-body"></tbody></table></div><div class="pager"><button class="primary outline" id="previous">&larr; Previous</button><span class="small" id="page-label"></span><button class="primary outline" id="next">Next &rarr;</button></div></section></main><footer><b>Bald.gg community awards</b><span>ADMIN ACCESS ONLY</span></footer><script>
  const tally = ${tally.toString()};
  const $ = id => document.getElementById(id);
  let ballots = [], awards = [], rows = [], currentPage = 0, generation = 0, busy = false;
  const pageSize = 50;
  function el(tag, text, cls) { const n = document.createElement(tag); if(text !== undefined)n.textContent = text; if(cls)n.className=cls; return n; }
  async function api(path, body) { const res = await fetch('/api/admin/' + path, {method: body === undefined ? 'GET' : 'POST', headers: body === undefined ? {} : {'Content-Type':'application/json'}, body: body === undefined ? undefined : JSON.stringify(body)}); const data = await res.json(); if(!res.ok){const e=new Error(data.error || 'Unable to load votes. Please retry.');e.status=res.status;throw e;}return data; }
  function showDashboard(show) {if(show)loadDiscord(); $('admin-login').classList.toggle('hidden',show);$('dashboard').classList.toggle('hidden',!show); }
  function clearData(){generation++;ballots=[];rows=[];$('leaders').replaceChildren();$('stats').replaceChildren();$('votes-body').replaceChildren();$('search').value='';$('updated').textContent='';}
  function renderTable(){ const query=$('search').value.trim().toLowerCase(); const filtered=rows.filter(r=>!query||[r.name,r.group,r.category,r.nomination,r.date].some(s=>s.toLowerCase().includes(query))); const pages=Math.max(1,Math.ceil(filtered.length/pageSize));currentPage=Math.min(currentPage,pages-1);$('votes-body').replaceChildren(); for(const row of filtered.slice(currentPage*pageSize,(currentPage+1)*pageSize)){const tr=el('tr');for(const value of [row.name,row.group,row.category,row.nomination,row.date])tr.append(el('td',value));$('votes-body').append(tr);} if(!filtered.length){const tr=el('tr');const td=el('td',rows.length?'No matching votes.':'No votes have been submitted yet.');td.colSpan=5;tr.append(td);$('votes-body').append(tr);}$('vote-caption').textContent=filtered.length+' individual votes'+(query?' matching your search':' across '+ballots.length+' ballots');$('page-label').textContent='Page '+(currentPage+1)+' of '+pages;$('previous').disabled=currentPage===0;$('next').disabled=currentPage+1>=pages; }
  function render(){ const summaries=tally(ballots,awards); rows=ballots.flatMap(b=>b.votes.map(v=>({name:b.name,group:b.role==='booster'?'Booster':'Customer',category:v.category,nomination:v.nomination+(v.nomineeUsername?' (@'+v.nomineeUsername+')':''),date:b.submittedAt&&!Number.isNaN(Date.parse(b.submittedAt))?new Date(b.submittedAt).toLocaleString():'Unknown'})));$('stats').replaceChildren(); for(const [value,label] of [[ballots.length,'Total ballots'],[rows.length,'Individual votes'],[ballots.filter(b=>b.role==='booster').length,'Booster ballots'],[ballots.filter(b=>b.role==='customer').length,'Customer ballots']]){const box=el('div',undefined,'stat');box.append(el('strong',String(value)),el('span',label));$('stats').append(box);} $('leaders').replaceChildren();for(const result of summaries){const card=el('article',undefined,'leader');card.append(el('span',result.role.toUpperCase()+' BALLOT','tag'),el('h3',result.category));if(!result.nominees.length){card.append(el('p','No votes yet','leader-name'),el('p','0 votes','small'));}else{const high=result.nominees[0].count;const leaders=result.nominees.filter(n=>n.count===high);card.append(el('p',leaders.map(n=>n.name).join(' / '),'leader-name'),el('p',(leaders.length>1?'Tied at ':'Leading with ')+high+(high===1?' vote':' votes')+' each'.repeat(leaders.length>1?1:0),'lead-count'),el('p',result.total+' total votes in this category','small'));const details=el('details');details.append(el('summary','All nominees ('+result.nominees.length+')'));for(const nominee of result.nominees){const line=el('div',undefined,'standing');line.append(el('span',nominee.name),el('b',nominee.count+(nominee.count===1?' vote':' votes')));details.append(line);}card.append(details);}$('leaders').append(card);}renderTable(); }
  async function loadVotes(){if(busy)return;busy=true;const run=++generation;$('refresh').disabled=true;$('data-error').textContent='';$('updated').textContent='Loading all ballots...';try{const collected=new Map();let cursor=null;const seen=new Set();do{const data=await api('votes'+(cursor?'?cursor='+encodeURIComponent(cursor):''));if(run!==generation)return;awards=data.awards;for(const ballot of data.ballots)collected.set(ballot.id,ballot);cursor=data.nextCursor;if(cursor&&seen.has(cursor))throw Error('Vote loading stopped unexpectedly. Please refresh.');if(cursor)seen.add(cursor);$('updated').textContent='Loading all ballots... '+collected.size+' loaded';}while(cursor);ballots=[...collected.values()].sort((a,b)=>String(b.submittedAt).localeCompare(String(a.submittedAt)));render();$('updated').textContent='Updated '+new Date().toLocaleTimeString();}catch(e){if(run!==generation)return;if(e.status===401){clearData();showDashboard(false);$('login-error').textContent='Your admin session expired. Please sign in again.';}else{$('data-error').textContent=e.message;$('updated').textContent=ballots.length?'Refresh failed; showing previous results.':'Results unavailable. Click Refresh votes to retry.';}}finally{busy=false;$('refresh').disabled=false;} }

  let syncingDiscord=false;
  function discordSummary(data){return !data.configured?'Not connected yet.':!data.ready?'Settings saved. Finish syncing to enable member selections.':'Last synced '+new Date(data.syncedAt).toLocaleString()+' | '+Object.entries(data.counts).map(([group,count])=>group+': '+count).join(' | ');}
  async function loadDiscord(){try{const data=await api('discord');$('discord-guild').value=data.guildId||'';for(const group of ['booster','staff','developer','customer'])$('discord-role-'+group).value=(data.roleIds?.[group]||[]).join(', ');$('discord-status').textContent=discordSummary(data);}catch(e){$('discord-error').textContent=e.message;}}
  async function syncDiscord(){if(syncingDiscord)return;syncingDiscord=true;$('discord-save').disabled=true;$('discord-sync').disabled=true;$('discord-error').textContent='';try{let first=true,data;do{data=await api('discord/sync',{restart:first});first=false;$('discord-status').textContent='Scanning server members... '+data.scanned+' checked';}while(!data.done);$('discord-status').textContent=discordSummary(data);}catch(e){$('discord-error').textContent=e.message;}finally{syncingDiscord=false;$('discord-save').disabled=false;$('discord-sync').disabled=false;}}
  $('discord-form').onsubmit=async e=>{e.preventDefault();if(syncingDiscord)return;$('discord-error').textContent='';$('discord-save').disabled=true;try{const roleIds={};for(const group of ['booster','staff','developer','customer'])roleIds[group]=$('discord-role-'+group).value.split(',').map(s=>s.trim()).filter(Boolean);await api('discord',{guildId:$('discord-guild').value.trim(),token:$('discord-token').value,roleIds});$('discord-token').value='';await syncDiscord();}catch(e){$('discord-error').textContent=e.message;}finally{$('discord-save').disabled=false;}};
  $('discord-sync').onclick=syncDiscord;

  $('admin-form').onsubmit=async e=>{e.preventDefault();$('login-button').disabled=true;$('login-error').textContent='';try{await api('login',{password:$('admin-password').value});$('admin-password').value='';showDashboard(true);await loadVotes();}catch(e){$('login-error').textContent=e.message;}finally{$('login-button').disabled=false;}};
  $('refresh').onclick=loadVotes;$('search').oninput=()=>{currentPage=0;renderTable();};$('previous').onclick=()=>{currentPage--;renderTable();};$('next').onclick=()=>{currentPage++;renderTable();};$('admin-logout').onclick=async()=>{try{await api('logout',{});clearData();showDashboard(false);}catch(e){$('data-error').textContent=e.message;}};
  api('session').then(s=>{if(s.authenticated){showDashboard(true);loadVotes();}else if(!s.configured){$('login-error').textContent='Missing Worker secrets: '+(s.missingSecrets || ['ADMIN_PASSPHRASE', 'SESSION_SECRET']).join(', ')+'. Add them under Settings > Variables and Secrets, then deploy.';}}).catch(e=>{$('login-error').textContent=e.message;});
  </script></body></html>`;
}
