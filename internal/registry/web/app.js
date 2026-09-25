'use strict';
const $ = s => document.querySelector(s);
let config, registration = true, namespaces = [], current, user, offset = 0, roleCatalog = {}, usersOffset = 0, selectedUser = null, updateTarget = null;
function notify(text, error = false) { const box = $('#message'); box.textContent = text; box.className = error ? 'error' : ''; box.hidden = false; }
async function api(path, options = {}) {
 const response = await fetch(path, { ...options, headers: { 'X-Registry-CSRF': '1', ...options.headers } });
 if (!response.ok) { let body; try { body = await response.json(); } catch { body = {}; } if (response.status === 401 && !path.startsWith('/auth/')) showAuth(); throw new Error(body.error || `Request failed (${response.status})`); }
 if (response.status === 204) return null;
 return response.json();
}
const json = (method, value) => ({ method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(value) });
const base = () => `/v1/namespaces/${encodeURIComponent(current.name)}`;
function el(tag, text, className) { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (className) e.className = className; return e; }
function action(label, fn) { const b = el('button', label); b.onclick = () => run(b, fn); return b; }
async function run(button, fn) { button.disabled = true; try { await fn(); } catch (e) { notify(e.message, true); } finally { button.disabled = button.id === "previous" ? offset === 0 : button.id === "next" ? $("#skills").querySelectorAll("article").length < 12 : button.id === "users-previous" ? usersOffset === 0 : button.id === "users-next" ? $("#users-list").querySelectorAll("tbody tr").length < 25 : false; } }
function form(id, fn) { $(id).onsubmit = e => { e.preventDefault(); const f = e.currentTarget; run(f.querySelector('button'), () => fn(Object.fromEntries(new FormData(f)), f)); }; }
function showAuth() {
 $('#workspace').hidden = true; $('#auth').hidden = false; $('#logout').hidden = true; $('#identity').textContent = ''; $('#users-panel').hidden = true; selectedUser = null;
 $('#auth-form').hidden = !config.local; $('#sso').hidden = !config.oidc; $('#auth-toggle').hidden = !config.local || !config.registration;
 registration = registration && config.registration; renderAuth();
}
function renderAuth() {
 $('#auth-title').textContent = !config.local ? 'Sign in with SSO' : registration ? 'Create your account' : 'Welcome back';
 $('#auth-description').textContent = !config.local ? 'Continue with your organization’s identity provider.' : registration ? 'Start with your email, username, and password.' : 'Sign in to your private skill registry.';
 for (const name of ['email', 'username']) { $(`#${name}-field`).hidden = !registration; $(`[name=${name}]`).required = registration; }
 $('#login-field').hidden = registration; $('[name=login]').required = !registration;
 $('[name=password]').minLength = registration ? 12 : 1; $('[name=password]').autocomplete = registration ? 'new-password' : 'current-password';
 $('#auth-submit').textContent = registration ? 'Create account' : 'Sign in'; $('#auth-toggle').textContent = registration ? 'Already registered? Sign in' : 'New here? Create account';
}
$('#auth-toggle').onclick = () => { registration = !registration; renderAuth(); };
form('#auth-form', async (data, f) => { await api(registration ? '/auth/register' : '/auth/login', json('POST', data)); f.reset(); $('#message').hidden = true; await load(); });
$('#logout').onclick = () => run($('#logout'), async () => { await api('/auth/logout', { method: 'POST' }); showAuth(); });
async function load() {
 user = await api('/auth/me'); roleCatalog = await api('/v1/roles'); populateRoles(); $('#manage-users').hidden = user.system_role !== 'super-admin'; $('#namespace-form').hidden = !user.can_create_namespace; $('#registry-view').hidden = false; $('#users-panel').hidden = true; $('#back-registry').hidden = true; $('#identity').textContent = `${user.username || 'SSO user'} · ${user.subject}`; $('#logout').hidden = false; $('#auth').hidden = true; $('#workspace').hidden = false;
 namespaces = await api('/v1/namespaces'); const previous = current?.name; $('#namespace').replaceChildren();
 for (const ns of namespaces) { const option = el('option', ns.name); option.value = ns.name; $('#namespace').append(option); }
 current = namespaces.find(n => n.name === previous) || namespaces[0]; if (current) $('#namespace').value = current.name;
 $('#empty').hidden = !!current; $('#namespace-content').hidden = !current; if (current) await selectNamespace();
}
async function selectNamespace() {
 current = namespaces.find(n => n.name === $('#namespace').value); offset = 0; $('#role').textContent = current.role;
 document.querySelectorAll('[data-permission]').forEach(e => e.hidden = !can(e.dataset.permission)); $('#upload-card').hidden = !can('write'); $('#record-usage').hidden = !can('usage-write'); await tab('skills');
}
$('#namespace').onchange = () => selectNamespace().catch(e => notify(e.message, true));
form('#namespace-form', async (data, f) => { await api('/v1/namespaces', json('POST', data)); current = { name: data.name }; f.reset(); await load(); notify('Namespace created.'); });
form('#upload-form', async (data, f) => {
 if (!data.bundle.size || data.bundle.size > 10 * 1024 * 1024) throw new Error('Choose a ZIP no larger than 10 MiB.');
 await api(`${base()}/skills/${encodeURIComponent(data.skill)}/versions/${encodeURIComponent(data.version)}`, { method: 'POST', headers: { 'Content-Type': 'application/zip' }, body: data.bundle }); f.reset(); offset = 0; await skills(); notify('Uploaded and scanned. Review findings before approval.');
});
form('#search-form', async () => { offset = 0; await skills(); });
$('#previous').onclick = () => run($('#previous'), async () => { offset = Math.max(0, offset - 12); await skills(); });
$('#next').onclick = () => run($('#next'), async () => { offset += 12; await skills(); });
const can = permission => !!current?.permissions?.includes(permission);
async function skills() {
 $('#search-form').hidden = !can('list'); $('#previous').parentElement.hidden = !can('list');
 if (!can('list')) { $('#skills').replaceChildren(el('p', 'Your roles permit uploads but do not permit browsing or downloading skills.')); return; }

 const params = new URLSearchParams(new FormData($('#search-form'))); params.set('limit', '12'); params.set('offset', offset);
 const items = await api(`${base()}/skills?${params}`); $('#skills').replaceChildren();
 if (!items.length) $('#skills').append(el('p', 'No skills found. Upload a bundle or change your search.'));
 for (const skill of items) {
  const card = el('article', undefined, 'card'); const top = el('div', undefined, 'skill-top'); top.append(el('h3', skill.name), el('span', skill.status, `status ${skill.status}`)); card.append(top, el('small', `v${skill.version} · revision ${skill.revision} · ${new Date(skill.updated_at).toLocaleDateString()}`));
  const score = el('div', `${skill.scan.score}`, 'score'); score.append(el('small', ' / 100 trust score')); card.append(score);
  const details = el('details'); details.append(el('summary', `${skill.scan.findings.length} findings · Scan details`), el('pre', JSON.stringify({ ...skill.scan, sha256: skill.sha256 }, null, 2))); card.append(details);
  const actions = el('div', undefined, 'actions'); const path = `${base()}/skills/${encodeURIComponent(skill.name)}/versions/${encodeURIComponent(skill.version)}`;
  if (skill.status === 'published' && can('read')) { const link = el('a', 'Download ZIP', 'button'); link.href = path; actions.append(link); }
  if (can('review')) {
   if (skill.status === 'quarantined' && skill.scan.score === 100 && skill.scan.findings.length === 0) actions.append(action('Approve', async () => { await api(`${path}/approve`, { method: 'POST' }); await skills(); notify('Version published.'); }));
   if (skill.status !== 'rejected') actions.append(action('Reject', async () => { const reason = prompt('Reason for rejection (at least 3 characters):'); if (!reason) return; await api(`${path}/reject`, json('POST', { reason })); await skills(); notify('Version rejected.'); }));
   actions.append(action('Rescan', async () => { await api(`${path}/rescan`, { method: 'POST' }); await skills(); notify('Rescanned. A new approval is required.'); }));
  }
  if (can('update')) actions.append(action('Update ZIP', async () => { updateTarget = { path, sha256: skill.sha256 }; $('#update-target').textContent = `${skill.name}@${skill.version}`; $('#update-form').reset(); $('#update-dialog').showModal(); }));
  if (can('delete')) actions.append(action('Delete version', async () => { if (!confirm(`Permanently delete ${skill.name}@${skill.version}? Audit and usage history will remain.`)) return; await api(path, { method: 'DELETE', headers: { 'If-Match': skill.sha256 } }); await skills(); notify('Version deleted.'); }));
  card.append(actions); $('#skills').append(card);
 }
 $('#page').textContent = `Page ${offset / 12 + 1}`; $('#previous').disabled = offset === 0; $('#next').disabled = items.length < 12;
}
function table(target, headings, rows) {
 const container = $(target); container.replaceChildren(); if (!rows.length) { container.append(el('p', 'No records yet.')); return; }
 const wrap = el('div', undefined, 'table-wrap'), t = el('table'), head = el('tr'); headings.forEach(h => head.append(el('th', h))); const thead = el('thead'); thead.append(head); t.append(thead); const body = el('tbody');
 rows.forEach(row => { const tr = el('tr'); row.forEach(value => { const td = el('td'); if (value instanceof Node) td.append(value); else td.textContent = String(value); tr.append(td); }); body.append(tr); }); t.append(body); wrap.append(t); container.append(wrap);
}
async function analytics() { const data = await api(`${base()}/usage`); table('#usage', ['Skill', 'Calls', 'Avg ms', 'Success', 'Tokens saved (est.)', 'USD saved (est.)'], data.items.map(x => [`${x.skill}@${x.version}`, x.calls, x.avg_latency_ms, `${x.success_pct}%`, x.estimated_tokens_saved, x.estimated_cost_usd])); }
async function audit() { const items = await api(`${base()}/audit`); table('#audit', ['Time', 'Actor', 'Action', 'Skill', 'Details'], items.map(x => [new Date(x.at).toLocaleString(), x.subject, x.action, x.skill, JSON.stringify(x.detail)])); }
async function members() { const items = await api(`${base()}/members`); table('#members', ['User', 'Subject ID', 'Role', ''], items.map(x => [x.username || 'External user', x.subject, x.role, x.subject === user.subject ? 'You' : action('Remove', async () => { if (!confirm(`Remove access for ${x.username || x.subject}?`)) return; await api(`${base()}/members/${encodeURIComponent(x.subject)}`, { method: 'DELETE' }); await members(); })])); }
form('#member-form', async (data, f) => { await api(`${base()}/members/${encodeURIComponent(data.subject)}`, json('PUT', { roles: [...f.elements.roles.selectedOptions].map(o => o.value) })); f.reset(); await members(); notify('Member role updated.'); });
form('#usage-form', async data => { for (const key of ['latency_ms', 'estimated_tokens_saved', 'estimated_cost_usd']) data[key] = Number(data[key]); data.success = data.success === 'true'; await api(`${base()}/usage`, json('POST', data)); await analytics(); notify('Usage recorded.'); });
async function tab(name) { document.querySelectorAll('[data-tab]').forEach(b => b.classList.toggle('active', b.dataset.tab === name)); for (const id of ['skills', 'usage', 'audit', 'members']) $(`#${id}-panel`).hidden = id !== name; await ({ skills, usage: analytics, audit, members })[name](); }
document.querySelectorAll('[data-tab]').forEach(b => b.onclick = () => run(b, () => tab(b.dataset.tab)));
(async () => { try { config = await api('/auth/config'); try { await load(); } catch (e) { if (e.message === 'login required' || e.message === 'session expired') showAuth(); else throw e; } } catch (e) { notify(e.message, true); } })();

function populateRoles() {
 const names = Object.keys(roleCatalog).filter(n => !['reader', 'publisher'].includes(n)).sort();
 for (const selector of ['#member-form [name=roles]', '#grant-form [name=roles]']) { const select = $(selector); select.replaceChildren(); for (const name of names) { const option = el('option', name); option.value = name; select.append(option); } }
 table('#role-help', ['Role', 'Permissions'], names.map(n => [n, roleCatalog[n].join(', ')]));
}
$('#cancel-update').onclick = () => $('#update-dialog').close();
form('#update-form', async (data, f) => {
 if (!data.bundle.size || data.bundle.size > 10 * 1024 * 1024) throw new Error('Choose a ZIP no larger than 10 MiB.');
 await api(updateTarget.path, { method: 'PUT', headers: { 'Content-Type': 'application/zip', 'If-Match': updateTarget.sha256 }, body: data.bundle }); $('#update-dialog').close(); f.reset(); await skills(); notify('Updated and quarantined. Review and approve the new content.');
});
$('#manage-users').onclick = () => run($('#manage-users'), async () => {
 $('#registry-view').hidden = true; $('#users-panel').hidden = false; $('#back-registry').hidden = false; $('#create-user-card').hidden = !config.local;
 const scope = $('#grant-form [name=namespace]'); scope.replaceChildren(); for (const ns of [{ name: '*' }, ...namespaces]) { const option = el('option', ns.name === '*' ? 'All namespaces (including future)' : ns.name); option.value = ns.name; scope.append(option); }
 usersOffset = 0; await users();
});
$('#back-registry').onclick = () => run($('#back-registry'), async () => { await load(); });
form('#create-user-form', async (data, f) => { await api('/v1/admin/users', json('POST', data)); f.reset(); usersOffset = 0; await users(); notify('User created. Select Manage to assign namespace access.'); });
form('#user-search', async () => { usersOffset = 0; await users(); });
$('#users-previous').onclick = () => run($('#users-previous'), async () => { usersOffset = Math.max(0, usersOffset - 25); await users(); });
$('#users-next').onclick = () => run($('#users-next'), async () => { usersOffset += 25; await users(); });
async function users() {
 const q = new URLSearchParams(new FormData($('#user-search'))); q.set('limit', '25'); q.set('offset', usersOffset);
 const items = await api(`/v1/admin/users?${q}`);
 table('#users-list', ['User', 'Email / subject', 'Registry role', 'Status', ''], items.map(u => [u.username || 'External user', u.email || u.subject, u.system_role, u.disabled ? 'Disabled' : 'Active', action('Manage', async () => { selectedUser = u; editUser(); })]));
 $('#users-page').textContent = `Page ${usersOffset / 25 + 1}`; $('#users-previous').disabled = usersOffset === 0; $('#users-next').disabled = items.length < 25;
 if (selectedUser) { selectedUser = items.find(u => u.subject === selectedUser.subject) || null; if (selectedUser) editUser(); else $('#user-editor').hidden = true; }
}
function editUser() {
 $('#user-editor').hidden = false; $('#editing-user').textContent = selectedUser.username || selectedUser.subject;
 const f = $('#account-form'); f.elements.system_role.value = selectedUser.system_role; f.elements.disabled.value = String(selectedUser.disabled); f.elements.password.value = ''; f.elements.password.disabled = !selectedUser.local;
 f.elements.system_role.disabled = selectedUser.subject === user.subject; f.elements.disabled.disabled = selectedUser.subject === user.subject;
 table('#user-grants', ['Scope', 'Roles', ''], selectedUser.grants.map(g => [g.namespace === '*' ? 'All namespaces' : g.namespace, g.roles.join(', '), action('Remove grant', async () => { if (!confirm('Remove this namespace grant?')) return; await saveGrants(selectedUser.grants.filter(x => x.namespace !== g.namespace)); })]));
}
async function saveGrants(grants) { await api(`/v1/admin/users/${encodeURIComponent(selectedUser.subject)}/grants`, json('PUT', { grants })); await users(); notify('Namespace grants updated.'); }
form('#grant-form', async (data, f) => { const grant = { namespace: data.namespace, roles: [...f.elements.roles.selectedOptions].map(o => o.value) }; await saveGrants([...selectedUser.grants.filter(g => g.namespace !== grant.namespace), grant]); });
form('#account-form', async data => { if (data.disabled !== undefined) data.disabled = data.disabled === 'true'; if (!data.password) delete data.password; await api(`/v1/admin/users/${encodeURIComponent(selectedUser.subject)}`, json('PATCH', data)); await users(); notify('Account updated. Password resets and disabling revoke existing sessions.'); });
$('#load-admin-audit').onclick = () => run($('#load-admin-audit'), async () => { const items = await api('/v1/admin/audit'); table('#admin-audit', ['Time', 'Actor', 'Action', 'Details'], items.map(x => [new Date(x.at).toLocaleString(), x.subject, x.action, JSON.stringify(x.detail)])); });
