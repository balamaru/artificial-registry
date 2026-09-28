'use strict';
let tokenOptions = {}, tokenGrants = [], tokenList = [], tokenOptionsSequence = 0;
function clearTokenSecret() { $('#token-secret').value = ''; $('#token-secret-card').hidden = true; }
function clearAccount() { tokenOptionsSequence++; clearTokenSecret(); $('#password-form').reset(); $('#token-form').reset(); $('#account-panel').hidden = true; tokenGrants = []; tokenList = []; $('#token-list').replaceChildren(); }
function userActions(account) {
 const box = el('div', undefined, 'actions');
 if (user.can_admin_users) box.append(action('Manage', async () => { selectedUser = account; editUser(); }));
 if (account.subject !== user.subject && user.can_delete_users && (user.can_admin_users || account.system_role === 'user')) box.append(action('Delete user', async () => {
  if (!confirm(`Delete user ${account.username || account.subject}? Their sessions, tokens, and access will be revoked. Skills and audit history will remain.`)) return;
  await api(`/v1/admin/users/${encodeURIComponent(account.subject)}`, { method: 'DELETE' }); await users(); notify('User deleted. Sessions and tokens revoked.');
 }));
 return box;
}
$('#my-account').onclick = () => run($('#my-account'), async () => {
 $('#registry-view').hidden = true; $('#users-panel').hidden = true; $('#account-panel').hidden = false; $('#back-registry').hidden = false;
 activateNav('nav-security', 'Account & tokens', 'Change your password and manage scoped CLI credentials.');
 $('#password-form').hidden = !user.local; $('#external-password').hidden = !!user.local; clearTokenSecret(); await refreshTokens(); await refreshTokenOptions();
});
$('#nav-security').onclick = () => $('#my-account').click();
$('#hide-token').onclick = clearTokenSecret;
form('#password-form', async (data, f) => {
 if (data.new_password !== data.confirmation) throw new Error('New passwords do not match.');
 await api('/auth/password', json('POST', { current_password: data.current_password, new_password: data.new_password }));
 f.reset(); showAuth(); notify('Password changed. Sign in again with your new password. All previous sessions and tokens have been revoked.');
});
function checks(target, names) {
 const container = $(target); container.querySelectorAll('label').forEach(e => e.remove());
 for (const name of names) { const label = el('label', undefined, 'token-check'), input = el('input'); input.type = 'checkbox'; input.value = name; label.append(input, el('span', name)); container.append(label); }
}
function tokenPermissions(ns) { return new Set((tokenOptions.grants || []).filter(g => g.namespace === '*' || g.namespace === ns).flatMap(g => g.roles.flatMap(r => roleCatalog[r] || []))); }
function renderTokenRoles() {
 const perms = tokenPermissions($('#token-scope').value);
 checks('#token-roles', Object.keys(roleCatalog).filter(r => !['reader','publisher'].includes(r) && roleCatalog[r].every(p => perms.has(p))).sort());
}
async function refreshTokenOptions() {
 const sequence = ++tokenOptionsSequence; const parent = $('#token-parent').value;
 $('#create-token').disabled = true; $('#add-token-grant').disabled = true;
 const options = await api(`/auth/token-options${parent ? '?parent_id=' + encodeURIComponent(parent) : ''}`);
 if (sequence !== tokenOptionsSequence) return;
 tokenOptions = options; tokenGrants = []; renderTokenGrants();
 const scopes = new Set((options.grants || []).map(g => g.namespace));
 if (scopes.has('*')) namespaces.forEach(ns => scopes.add(ns.name));
 const select = $('#token-scope'); select.replaceChildren();
 for (const scope of scopes) { const option = el('option', scope === '*' ? 'All namespaces (including future)' : scope); option.value = scope; select.append(option); }
 renderTokenRoles();
 const systems = new Set(options.system_roles || []); if (systems.has('super-admin')) systems.add('user-delete');
 checks('#token-system', [...systems]);
 $('#parent-expiry').textContent = options.expires_at ? `Lifetime is capped at parent expiry: ${new Date(options.expires_at).toLocaleString()}.` : 'Maximum lifetime: 365 days.';
 $('#create-token').disabled = false; $('#add-token-grant').disabled = !scopes.size;
}
$('#token-parent').onchange = () => refreshTokenOptions().catch(e => notify(e.message, true));
$('#token-scope').onchange = renderTokenRoles;
function renderTokenGrants() {
 table('#token-grants', ['Namespace', 'Roles', ''], tokenGrants.map(g => [g.namespace, g.roles.join(', '), action('Remove', async () => { tokenGrants = tokenGrants.filter(x => x.namespace !== g.namespace); renderTokenGrants(); })]));
}
$('#add-token-grant').onclick = () => {
 const namespace = $('#token-scope').value, roles = [...document.querySelectorAll('#token-roles input:checked')].map(e => e.value);
 if (!namespace || !roles.length) { notify('Choose a namespace and at least one role, then add the grant.', true); return; }
 tokenGrants = [...tokenGrants.filter(g => g.namespace !== namespace), { namespace, roles }]; renderTokenGrants();
};
form('#token-form', async data => {
 const system_roles = [...document.querySelectorAll('#token-system input:checked')].map(e => e.value);
 if (!tokenGrants.length && !system_roles.length) throw new Error('Add a namespace grant or select a registry administration role.');
 clearTokenSecret();
 const result = await api('/auth/tokens', json('POST', { name: data.name, parent_id: data.parent_id, expires_in_days: Number(data.expires_in_days), grants: tokenGrants, system_roles }));
 $('#token-secret').value = result.token; $('#token-secret-card').hidden = false;
 $('#token-secret-card').scrollIntoView({ block: 'nearest' });
 await refreshTokens(); notify('Token created. Copy the secret now; it cannot be displayed again.');
});
async function refreshTokens() {
 tokenList = await api('/auth/tokens');
 const selected = $('#token-parent').value, select = $('#token-parent'); select.replaceChildren();
 const root = el('option', 'New root token (account permissions)'); root.value = ''; select.append(root);
 for (const token of tokenList.filter(t => !t.revoked_at && new Date(t.expires_at) > new Date())) { const option = el('option', `${token.name} · ${token.prefix}…`); option.value = token.id; select.append(option); }
 if ([...select.options].some(o => o.value === selected)) select.value = selected;
 table('#token-list', ['Name / prefix', 'Parent', 'Permissions', 'Expires', 'Status', ''], tokenList.map(token => {
  const inactive = token.revoked_at || new Date(token.expires_at) <= new Date();
  const parent = tokenList.find(t => t.id === token.parent_id);
  return [`${token.name} · ${token.prefix}…`, token.parent_id ? parent?.name || token.parent_id : 'Root',
   [...token.grants.map(g => `${g.namespace}: ${g.roles.join(', ')}`), ...token.system_roles].join('; '),
   new Date(token.expires_at).toLocaleString(), token.revoked_at ? 'Revoked' : inactive ? 'Expired' : 'Active',
   inactive ? '' : action('Revoke', async () => { if (!confirm(`Revoke ${token.name} and all its descendants?`)) return; await api(`/auth/tokens/${encodeURIComponent(token.id)}`, { method: 'DELETE' }); clearTokenSecret(); await refreshTokens(); await refreshTokenOptions(); notify('Token and descendants revoked.'); })];
 }));
}
