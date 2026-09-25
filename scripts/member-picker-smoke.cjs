// Run against an empty, disposable registry database with Playwright installed.
const { chromium, expect } = require('playwright/test');
(async () => {
 const browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
 try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const errors = []; page.on('pageerror', e => errors.push(e.message));
  const base = process.env.BASE_URL || 'http://localhost:8080';
  const headers = { 'X-Registry-CSRF': '1' };
  const register = await page.request.post(`${base}/auth/register`, { data: { username: 'owner', email: 'owner@example.test', password: 'member-picker-password' }, headers });
  if (register.status() !== 201) throw new Error(await register.text());
  const ns = await page.request.post(`${base}/v1/namespaces`, { data: { name: 'team' }, headers });
  if (ns.status() !== 201) throw new Error(await ns.text());
  const subjects = {};
  for (const name of ['aaaa', 'bbb', 'ccc', 'jhoen']) {
   const response = await page.request.post(`${base}/v1/admin/users`, { data: { username: name, email: `${name}@example.test`, password: 'member-picker-password' }, headers });
   if (response.status() !== 201) throw new Error(await response.text()); subjects[name] = (await response.json()).subject;
  }
  await page.goto(base);
  await page.getByRole('button', { name: 'Members', exact: true }).click();
  const input = page.getByRole('combobox', { name: 'Search users to add' });
  const options = page.locator('#member-user-options [role=option]');
  await input.click(); await expect(options).toHaveCount(5);
  await expect(page.locator('#member-user-options')).toContainText('aaaa');
  await expect(page.locator('#member-user-options')).toContainText('jhoen');
  await input.fill('J'); await expect(options).toHaveCount(1); await expect(options.first()).toContainText('jhoen');
  await input.fill('BBB@'); await expect(options).toHaveCount(1); await expect(options.first()).toContainText('bbb');
  await input.fill(subjects.ccc.slice(-16)); await expect(options).toHaveCount(1); await expect(options.first()).toContainText('ccc');
  await input.fill('no-matches'); await expect(page.locator('#member-user-status')).toHaveText('No matching users.');
  await input.fill(''); await expect(options).toHaveCount(5);
  // A delayed old query must never overwrite results for the newer input.
  let releaseOld;
  const oldBlocked = new Promise(resolve => releaseOld = resolve);
  let markStarted;
  const started = new Promise(resolve => markStarted = resolve);
  await page.route('**/member-candidates?*', async route => {
   if (new URL(route.request().url()).searchParams.get('q') === 'aaaa') {
    markStarted(); await oldBlocked;
    try { await route.fulfill({ json: { items: [{ subject: subjects.aaaa, username: 'aaaa', email: 'aaaa@example.test' }], has_more: false } }); } catch { /* request was aborted */ }
   } else await route.continue();
  });
  await input.fill('aaaa'); await started;
  await input.fill('jhoen'); await expect(options).toHaveCount(1); await expect(options.first()).toContainText('jhoen');
  releaseOld(); await page.unrouteAll({ behavior: 'wait' });
  await expect(options.first()).toContainText('jhoen');
  await input.press('ArrowDown'); await input.press('Enter');
  await expect(page.locator('#member-subject')).toHaveValue(subjects.jhoen);
  await expect(page.locator('#member-user-popup')).toBeHidden();
  const roleButton = page.getByRole('button', { name: 'Choose namespace roles' });
  await roleButton.click();
  await page.locator('#member-role-options').getByLabel('read-only', { exact: true }).check();
  await page.locator('#member-role-options').getByLabel('update', { exact: true }).check();
  await expect(page.locator('#member-role-label')).toHaveText('2 roles selected');
  await roleButton.press('Escape');
  const heights = await Promise.all([input, roleButton, page.getByRole('button', { name: 'Set role', exact: true })].map(async locator => (await locator.boundingBox()).height));
  if (Math.max(...heights) - Math.min(...heights) > 1) throw new Error(`Unequal control heights: ${heights}`);
  await page.getByRole('button', { name: 'Set role', exact: true }).click();
  const member = page.locator('#members tr').filter({ hasText: 'jhoen' });
  await expect(member).toContainText('read-only'); await expect(member).toContainText('update');
  await expect(input).toHaveValue(''); await expect(page.locator('#member-role-label')).toHaveText('Choose roles');
  // Namespace admin (not a registry super-admin) must also be able to search.
  const assigned = await page.request.put(`${base}/v1/namespaces/team/members/${subjects.aaaa}`, { data: { roles: ['admin'] }, headers });
  if (assigned.status() !== 204) throw new Error(await assigned.text());
  const adminPage = await browser.newPage();
  await adminPage.request.post(`${base}/auth/login`, { data: { login: 'aaaa', password: 'member-picker-password' }, headers });
  await adminPage.goto(base); await adminPage.getByRole('button', { name: 'Members', exact: true }).click();
  await adminPage.getByRole('combobox', { name: 'Search users to add' }).click();
  await expect(adminPage.locator('#member-user-options [role=option]')).toHaveCount(5);
  await expect(adminPage.locator('#manage-users')).toBeHidden(); await adminPage.close();
  await input.click(); await expect(options).toHaveCount(5);
  if (process.env.SCREENSHOT_DIR) await page.screenshot({ path: `${process.env.SCREENSHOT_DIR}/members-desktop.png`, fullPage: true });
  await input.press('Escape'); await page.setViewportSize({ width: 390, height: 844 });
  await roleButton.click(); await expect(page.locator('#member-role-options')).toBeVisible();
  if (await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)) throw new Error('Mobile layout overflow');
  if (process.env.SCREENSHOT_DIR) await page.screenshot({ path: `${process.env.SCREENSHOT_DIR}/members-mobile.png`, fullPage: true });
  if (errors.length) throw new Error(errors.join('; '));
  console.log('PASS: initial list, live username/email/subject filtering, empty results, stale-query cancellation, keyboard selection, multiple roles, assignment, namespace-admin access, equal control heights, mobile layout.');
 } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exit(1); });
