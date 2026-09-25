'use strict';
const memberLookup = { generation: 0, controller: null, timer: null, items: [], active: -1 };

function cancelMemberLookup() {
 clearTimeout(memberLookup.timer);
 memberLookup.controller?.abort();
 memberLookup.generation++;
}
function closeMemberSearch() {
 cancelMemberLookup();
 $('#member-user-popup').hidden = true;
 $('#member-user-search').setAttribute('aria-expanded', 'false');
 $('#member-user-search').removeAttribute('aria-activedescendant');
}
function closeMemberRoles() {
 $('#member-role-options').hidden = true;
 $('#member-role-toggle').setAttribute('aria-expanded', 'false');
}
function selectedMemberRoles() {
 return [...document.querySelectorAll('#member-role-options input:checked')].map(input => input.value);
}
function updateMemberRoleLabel() {
 const roles = selectedMemberRoles();
 $('#member-role-label').textContent = roles.length === 0 ? 'Choose roles' : roles.length === 1 ? roles[0] : `${roles.length} roles selected`;
 $('#member-role-toggle').title = roles.join(', ') || 'Choose one or more roles';
}
function populateMemberRoles(names) {
 const options = $('#member-role-options');
 options.replaceChildren();
 for (const name of names) {
  const label = el('label', undefined, 'member-role-option');
  const checkbox = document.createElement('input');
  checkbox.type = 'checkbox'; checkbox.name = 'roles'; checkbox.value = name;
  checkbox.onchange = updateMemberRoleLabel;
  label.append(checkbox, el('span', name)); options.append(label);
 }
 updateMemberRoleLabel();
}
function resetMemberPicker() {
 closeMemberSearch(); closeMemberRoles();
 $('#member-form').reset(); memberLookup.items = []; memberLookup.active = -1;
 $('#member-user-options').replaceChildren(); updateMemberRoleLabel();
}
function chooseMember(candidate) {
 const input = $('#member-user-search');
 input.focus();
 input.value = candidate.username || candidate.email || candidate.subject;
 $('#member-subject').value = candidate.subject;
 closeMemberSearch();
}
function highlightMember(index) {
 memberLookup.active = index;
 const options = [...$('#member-user-options').children];
 options.forEach((option, i) => option.setAttribute('aria-selected', String(i === index)));
 if (options[index]) {
  $('#member-user-search').setAttribute('aria-activedescendant', options[index].id);
  options[index].scrollIntoView({ block: 'nearest' });
 }
}
function renderMemberCandidates() {
 const list = $('#member-user-options'); list.replaceChildren();
 memberLookup.items.forEach((candidate, index) => {
  const option = el('button', undefined, 'member-user-option');
  option.type = 'button'; option.tabIndex = -1; option.id = `member-user-option-${index}`;
  option.setAttribute('role', 'option'); option.setAttribute('aria-selected', 'false');
  option.append(el('strong', candidate.username || 'External user'));
  if (candidate.email) option.append(el('span', candidate.email));
  option.append(el('small', candidate.subject));
  option.onmousedown = event => event.preventDefault();
  option.onclick = () => chooseMember(candidate);
  list.append(option);
 });
}
async function fetchMemberCandidates(append = false) {
 cancelMemberLookup();
 const generation = memberLookup.generation, namespace = current?.name;
 if (!namespace || !can('members')) return;
 const input = $('#member-user-search'), popup = $('#member-user-popup');
 popup.hidden = false; input.setAttribute('aria-expanded', 'true');
 memberLookup.active = -1; input.removeAttribute('aria-activedescendant');
 if (!append) { memberLookup.items = []; renderMemberCandidates(); }
 $('#member-user-status').textContent = 'Loading users…'; $('#member-user-more').hidden = true;
 const controller = new AbortController(); memberLookup.controller = controller;
 const params = new URLSearchParams({ q: input.value, limit: '50', offset: String(memberLookup.items.length) });
 try {
  const result = await api(`/v1/namespaces/${encodeURIComponent(namespace)}/member-candidates?${params}`, { signal: controller.signal });
  if (generation !== memberLookup.generation || namespace !== current?.name) return;
  memberLookup.items.push(...result.items); renderMemberCandidates();
  $('#member-user-status').textContent = memberLookup.items.length ? `${memberLookup.items.length} users found${result.has_more ? ' · more available' : ''}` : 'No matching users.';
  $('#member-user-more').hidden = !result.has_more;
 } catch (error) {
  if (error.name !== 'AbortError' && generation === memberLookup.generation) $('#member-user-status').textContent = `Unable to search: ${error.message}`;
 }
}
function initMemberPicker() {
 const input = $('#member-user-search');
 const open = () => { if ($('#member-user-popup').hidden) fetchMemberCandidates(); };
 input.addEventListener('focus', open); input.addEventListener('click', open);
 input.addEventListener('input', () => {
  $('#member-subject').value = ''; cancelMemberLookup(); memberLookup.items = []; memberLookup.active = -1;
  input.removeAttribute('aria-activedescendant'); $('#member-user-options').replaceChildren();
  $('#member-user-popup').hidden = false; input.setAttribute('aria-expanded', 'true');
  $('#member-user-status').textContent = 'Searching…'; $('#member-user-more').hidden = true;
  memberLookup.timer = setTimeout(() => fetchMemberCandidates(), 150);
 });
 input.addEventListener('keydown', event => {
  if (event.key === 'Escape') { event.preventDefault(); closeMemberSearch(); }
  if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
   event.preventDefault(); if ($('#member-user-popup').hidden) { fetchMemberCandidates(); return; }
   const length = memberLookup.items.length; if (length) highlightMember(memberLookup.active < 0 ? (event.key === 'ArrowDown' ? 0 : length - 1) : (memberLookup.active + (event.key === 'ArrowDown' ? 1 : -1) + length) % length);
  }
  if (event.key === 'Enter' && !$('#member-user-popup').hidden) { event.preventDefault(); if (memberLookup.active >= 0) chooseMember(memberLookup.items[memberLookup.active]); }
 });
 $('#member-user-more').onclick = () => fetchMemberCandidates(true);
 $('#member-role-toggle').onclick = () => {
  const options = $('#member-role-options'); options.hidden = !options.hidden;
  $('#member-role-toggle').setAttribute('aria-expanded', String(!options.hidden));
 };
 $('#member-role-picker').addEventListener('keydown', event => {
  if (event.key === 'Escape') { event.preventDefault(); closeMemberRoles(); $('#member-role-toggle').focus(); }
 });
 for (const eventName of ['pointerdown', 'focusin']) document.addEventListener(eventName, event => {
  if (!$('#member-user-picker').contains(event.target)) closeMemberSearch();
  if (!$('#member-role-picker').contains(event.target)) closeMemberRoles();
 });
}
