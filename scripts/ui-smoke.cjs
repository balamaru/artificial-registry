// npm install playwright@1.58.2, install Chromium, and set ZIP_FIXTURE to a ZIP
// containing a safe root SKILL.md. Use a disposable database, not production.
const { chromium, expect } = require('playwright/test');
const fs = require('node:fs');

(async () => {
  if (!process.env.ZIP_FIXTURE) throw new Error('ZIP_FIXTURE is required');
  const browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    const suffix = Date.now().toString(36);
    const username = `browser-${suffix}`, namespace = `ui-${suffix}`;
    await page.goto(process.env.BASE_URL || 'http://localhost:8080');
    await expect(page.getByRole('heading', { name: 'Create your account' })).toBeVisible();
    await page.locator('#auth-form [name=email]').fill(`${username}@example.test`);
    await page.locator('#auth-form [name=username]').fill(username);
    await page.locator('#auth-form [name=password]').fill('browser-test-password');
    await page.getByRole('button', { name: 'Create account', exact: true }).click();
    await expect(page.locator('#workspace')).toBeVisible();
    await page.getByRole('textbox', { name: 'New namespace' }).fill(namespace);
    await page.getByRole('button', { name: 'Create namespace', exact: true }).click();
    await expect(page.locator('#role')).toHaveText('admin');
    await page.getByRole('textbox', { name: 'Skill name', exact: true }).fill('example');
    await page.getByRole('textbox', { name: 'Version', exact: true }).fill('1.0.0');
    await page.getByLabel('Skill ZIP', { exact: true }).setInputFiles(process.env.ZIP_FIXTURE);
    await page.getByRole('button', { name: 'Upload & scan', exact: true }).click();
    await expect(page.locator('.status')).toHaveText('quarantined');
    await page.getByRole('button', { name: 'Approve', exact: true }).click();
    await expect(page.locator('.status')).toHaveText('published');
    const download = page.waitForEvent('download');
    await page.getByRole('link', { name: 'Download ZIP' }).click();
    const file = await download;
    const downloaded = fs.readFileSync(await file.path());
    if (!downloaded.equals(fs.readFileSync(process.env.ZIP_FIXTURE))) throw new Error('Downloaded ZIP differs');
    if (process.env.SCREENSHOT_DIR) await page.screenshot({ path: `${process.env.SCREENSHOT_DIR}/registry-desktop.png`, fullPage: true });
    await page.getByRole('button', { name: 'Analytics', exact: true }).click();
    await page.getByText('Record a usage event', { exact: true }).click();
    await page.locator('#usage-form [name=skill]').fill('example');
    await page.locator('#usage-form [name=version]').fill('1.0.0');
    await page.locator('#usage-form [name=latency_ms]').fill('125');
    await page.getByRole('button', { name: 'Record event', exact: true }).click();
    await expect(page.locator('#usage')).toContainText('example@1.0.0');
    await page.getByRole('button', { name: 'Audit log', exact: true }).click();
    await expect(page.locator('#audit')).toContainText('skill.approve');
    await page.getByRole('button', { name: 'Members', exact: true }).click();
    await expect(page.locator('#members')).toContainText(username);
    await page.getByRole('button', { name: 'Skills', exact: true }).click();
    await page.setViewportSize({ width: 390, height: 844 });
    await expect(page.getByRole('link', { name: 'Download ZIP' })).toBeVisible();
    if (await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)) throw new Error('Mobile layout overflows viewport');
    if (process.env.SCREENSHOT_DIR) await page.screenshot({ path: `${process.env.SCREENSHOT_DIR}/registry-mobile.png`, fullPage: true });
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await expect(page.locator('#auth')).toBeVisible();
    await page.getByRole('button', { name: 'Already registered? Sign in', exact: true }).click();
    await page.locator('#auth-form [name=login]').fill(username);
    await page.locator('#auth-form [name=password]').fill('browser-test-password');
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    await expect(page.locator('#workspace')).toBeVisible();
    await expect(page.locator('.status')).toHaveText('published');
    if (errors.length) throw new Error(`Browser errors: ${errors.join('; ')}`);
    console.log('PASS: registration, namespace, upload, approval, download integrity, analytics, audit, members, mobile layout, logout, login; no browser errors.');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exit(1); });
