const { expect } = require('playwright/test');
module.exports = async function bootstrapLogin(page, base, password, email = '') {
 const temporary = process.env.BOOTSTRAP_PASSWORD;
 if (!temporary) throw new Error('BOOTSTRAP_PASSWORD must contain the temporary admin password from disposable application logs.');
 await page.goto(base);
 await expect(page.locator('#auth')).toBeVisible();
 await expect(page.getByRole('button', {name:'Create account',exact:true})).toHaveCount(0);
 const denied = await page.request.post(base+'/auth/register', {data:{username:'intruder',password:'test-intruder-password'}});
 if (denied.status() !== 403) throw new Error('Public registration remains enabled');
 await page.locator('#auth-form [name=login]').fill('admin');
 await page.locator('#auth-form [name=password]').fill(temporary);
 await page.locator('#auth-submit').click();
 await expect(page.locator('#first-login')).toBeVisible();
 await expect(page.locator('#workspace')).toBeHidden();
 for (const path of ['/v1/admin/users','/v1/namespaces','/auth/tokens']) {
  if ((await page.request.get(base+path)).status()!==403) throw new Error('Initial password bypass at '+path);
 }
 await page.reload();
 await expect(page.locator('#first-login')).toBeVisible();
 await page.locator('#first-login-form [name=current_password]').fill(temporary);
 await page.locator('#first-login-form [name=new_password]').fill(password);
 await page.locator('#first-login-form [name=confirmation]').fill(password);
 await page.locator('#first-login-form [name=email]').fill(email);
 await page.locator('#first-login-form button').click();
 await expect(page.locator('#auth')).toBeVisible();
 await page.locator('#auth-form [name=login]').fill('admin');
 await page.locator('#auth-form [name=password]').fill(password);
 await page.locator('#auth-submit').click();
 await expect(page.locator('#workspace')).toBeVisible();
};
