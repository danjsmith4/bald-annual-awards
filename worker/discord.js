const CONFIG = '_settings/discord-v1.json';
const ROSTER = '_settings/discord-roster-v1.json';
const DRAFT = '_settings/discord-sync-v1.json';
const groups = ['booster', 'staff', 'developer', 'customer'];
const snowflake = value => typeof value === 'string' && /^\d{17,20}$/.test(value);
const encode = new TextEncoder();
const hex = value => Array.from(new Uint8Array(value), b => b.toString(16).padStart(2, '0')).join('');
const unhex = value => Uint8Array.from(value.match(/../g), pair => parseInt(pair, 16));
const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: {'Content-Type':'application/json','Cache-Control':'no-store'} });
export const nomineeGroup = category => category.includes('Moment') ? null : category.includes('Customer of') ? 'customer' : category.includes('Dev of') ? 'developer' : category.toLowerCase().includes('staff of') ? 'staff' : 'booster';
async function read(env, key) { return (await env.BALLOTS.get(key))?.json() || null; }
async function cipherKey(env) { return crypto.subtle.importKey('raw', await crypto.subtle.digest('SHA-256', encode.encode(env.SESSION_SECRET)), 'AES-GCM', false, ['encrypt','decrypt']); }
async function seal(token, env) { const iv = crypto.getRandomValues(new Uint8Array(12)); return {iv:hex(iv),data:hex(await crypto.subtle.encrypt({name:'AES-GCM',iv},await cipherKey(env),encode.encode(token)))}; }
async function open(config, env) { return new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:unhex(config.token.iv)},await cipherKey(env),unhex(config.token.data))); }
async function discord(path, token, fetcher) {
  const response = await fetcher('https://discord.com/api/v10' + path, {headers:{Authorization:'Bot ' + token,'User-Agent':'BaldAwards/1.0'}});
  if (!response.ok) {
    const error = new Error(response.status === 401 ? 'Discord rejected the bot token.' : response.status === 403 ? 'The bot cannot read server members. Check server access and Server Members Intent.' : response.status === 429 ? 'Discord rate limit reached. Wait a moment, then retry syncing.' : 'Discord request failed (' + response.status + '). Check the server ID and bot membership.');
    error.status = response.status === 429 ? 429 : 400;
    throw error;
  }
  return response.json();
}
function safeStatus(config, roster) { return { configured:!!config,ready:!!config && roster?.revision === config.revision,guildId:config?.guildId || '',roleIds:config?.roleIds || {},syncedAt:roster?.syncedAt || null,counts:Object.fromEntries(groups.map(group=>[group,roster?.groups?.[group]?.length || 0])),hasToken:!!config?.token }; }
export async function adminDiscord(req, env, fetcher = fetch) {
  if (!env.BALLOTS || !env.SESSION_SECRET) return json({error:'Private storage is unavailable.'},503);
  const path = new URL(req.url).pathname;
  try {
    const config = await read(env,CONFIG);
    if(path === '/api/admin/discord' && req.method === 'GET') return json(safeStatus(config,await read(env,ROSTER)));
    if(path === '/api/admin/discord' && req.method === 'POST') {
      const body = await req.json();
      if(!snowflake(body.guildId)) return json({error:'Enter a valid Discord server ID.'},400);
      const roleIds = {};
      for(const group of groups) {
        const ids = Array.isArray(body.roleIds?.[group]) ? [...new Set(body.roleIds[group])] : [];
        if(!ids.length || ids.length > 10 || ids.some(id=>!snowflake(id))) return json({error:'Enter at least one valid role ID for ' + group + '.'},400);
        roleIds[group] = ids;
      }
      const token = typeof body.token === 'string' && body.token.trim() ? body.token.trim().replace(/^Bot /,'') : config ? await open(config,env) : '';
      if(!token || token.length > 300) return json({error:'Enter the Discord bot token in this private form.'},400);
      const roles = await discord('/guilds/' + body.guildId + '/roles',token,fetcher);
      const allowed = new Set(roles.map(role=>role.id));
      if(groups.some(group=>roleIds[group].some(id=>!allowed.has(id)))) return json({error:'One or more role IDs do not belong to this server.'},400);
      const next = {version:1,guildId:body.guildId,roleIds,token:await seal(token,env),revision:crypto.randomUUID()};
      await env.BALLOTS.put(CONFIG,JSON.stringify(next));
      return json(safeStatus(next,null));
    }
    if(path === '/api/admin/discord/sync' && req.method === 'POST') {
      if(!config) return json({error:'Save the Discord settings first.'},400);
      const body = await req.json();
      let draft = body.restart ? null : await read(env,DRAFT);
      if(!draft || draft.revision !== config.revision) draft = {revision:config.revision,after:'0',scanned:0,groups:Object.fromEntries(groups.map(group=>[group,[]]))};
      const members = await discord('/guilds/' + config.guildId + '/members?limit=1000&after=' + draft.after,await open(config,env),fetcher);
      if(!Array.isArray(members)) throw Error('Discord returned an invalid member list.');
      for(const member of members) {
        if(!member.user || member.user.bot) continue;
        const person = {id:member.user.id,name:member.nick || member.user.global_name || member.user.username,username:member.user.username};
        for(const group of groups) if(config.roleIds[group].some(id=>id === config.guildId || member.roles?.includes(id))) draft.groups[group].push(person);
      }
      draft.scanned += members.length;
      if(members.length === 1000) {
        const next = members[members.length-1].user.id;
        if(next === draft.after) throw Error('Discord member pagination did not advance.');
        draft.after = next;
        await env.BALLOTS.put(DRAFT,JSON.stringify(draft));
        return json({done:false,scanned:draft.scanned});
      }
      for(const group of groups) draft.groups[group] = [...new Map(draft.groups[group].map(person=>[person.id,person])).values()].sort((a,b)=>a.name.localeCompare(b.name));
      const roster = {revision:config.revision,groups:draft.groups,syncedAt:new Date().toISOString()};
      await env.BALLOTS.put(ROSTER,JSON.stringify(roster));
      return json({done:true,scanned:draft.scanned,...safeStatus(config,roster)});
    }
    return json({error:'Not found.'},404);
  } catch(error) { return json({error:error.status ? error.message : 'Discord sync failed. Verify the bot settings and try again.'},error.status || 503); }
}
export async function nomineeLists(env, role) {
  const config = await read(env,CONFIG);
  if(!config) return {enabled:false};
  const roster = await read(env,ROSTER);
  if(roster?.revision !== config.revision) throw Error('Discord nominees are not ready. Please ask an admin to finish syncing the server.');
  const permitted = role === 'customer' ? ['booster','staff'] : groups;
  return {enabled:true,syncedAt:roster.syncedAt,groups:Object.fromEntries(permitted.map(group=>[group,roster.groups[group]]))};
}
export async function resolveNominees(env, role, categories, answers, fetcher = fetch) {
  const lists = await nomineeLists(env,role);
  if(!lists.enabled) return categories.map((category,i)=>({category,nomination:answers[i].trim()}));
  const config = await read(env,CONFIG);
  const token = await open(config,env);
  const checked = new Map();
  const votes = [];
  for(let i=0;i<categories.length;i++) {
    const category = categories[i], group = nomineeGroup(category);
    if(!group) { votes.push({category,nomination:answers[i]}); continue; }
    const person = lists.groups[group]?.find(person=>person.id === answers[i]);
    if(!person) throw Error('Choose an eligible Discord member for ' + category + '.');
    if(!checked.has(person.id)) checked.set(person.id,await discord('/guilds/' + config.guildId + '/members/' + person.id,token,fetcher));
    const member = checked.get(person.id);
    if(member.user?.bot || !config.roleIds[group].some(id=>id === config.guildId || member.roles?.includes(id))) throw Error('That member no longer has the required role. Refresh the nominees and choose again.');
    votes.push({category,nomination:member.nick || member.user.global_name || member.user.username,nomineeId:person.id,nomineeUsername:member.user.username});
  }
  return votes;
}
