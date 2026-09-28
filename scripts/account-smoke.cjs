// Disposable EMPTY database only. Requires playwright@1.58.2 and Chromium.
const { chromium, expect } = require('playwright/test');
(async () => {
 const browser = await chromium.launch({headless:true,args:['--no-sandbox']});
 try {
  const page = await browser.newPage({viewport:{width:1440,height:1000}}), errors=[];
  page.on('pageerror',e=>errors.push(e.message));page.on('dialog',d=>d.accept());
  const base=process.env.BASE_URL||'http://localhost:8080';
  const req=async(method,path,data,token)=>{
   const response=await page.request.fetch(base+path,{method,data,headers:token?{Authorization:'Bearer '+token}:{'X-Registry-CSRF':'1'}});
   return response;
  };
  await page.goto(base);
  await page.locator('#auth-form [name=email]').fill('owner@example.test');
  await page.locator('#auth-form [name=username]').fill('owner');
  await page.locator('#auth-form [name=password]').fill('browser-original-password');
  await page.locator('#auth-submit').click();await expect(page.locator('#workspace')).toBeVisible();
  await page.locator('#namespace-form [name=name]').fill('alpha');await page.locator('#namespace-form button').click();await expect(page.locator('#role')).toHaveText('admin');
  await page.locator('#my-account').click();await expect(page.locator('#account-panel')).toBeVisible();
  await page.locator('#token-form [name=name]').fill('parent');
  await page.locator('#token-scope').selectOption('alpha');
  await page.locator('#token-roles input[value=read-write]').check();
  await page.locator('#add-token-grant').click();await page.locator('#create-token').click();
  await expect(page.locator('#token-secret-card')).toBeVisible();
  const parentSecret=await page.locator('#token-secret').inputValue();
  if(!parentSecret.startsWith('ar_pat_'))throw Error('Missing parent token');
  await expect(page.locator('#token-list')).toContainText('parent');
  let tokens=await(await req('GET','/auth/tokens')).json(), parent=tokens.find(t=>t.name==='parent');
  await page.locator('#hide-token').click();await expect(page.locator('#token-secret')).toHaveValue('');
  await page.locator('#token-parent').selectOption(parent.id);
  await expect(page.locator('#parent-expiry')).toContainText('parent expiry');
  await expect(page.locator('#token-roles input[value=admin]')).toHaveCount(0);
  await expect(page.locator('#token-system input[value=super-admin]')).toHaveCount(0);
  await page.locator('#token-form [name=name]').fill('child');
  await page.locator('#token-roles input[value=read-only]').check();await page.locator('#add-token-grant').click();
  await page.locator('#create-token').click();await expect(page.locator('#token-secret-card')).toBeVisible();
  const childSecret=await page.locator('#token-secret').inputValue();
  if(childSecret===parentSecret)throw Error('Child secret reused');
  await expect(page.locator('#token-list')).toContainText('child');
  if((await req('GET','/v1/namespaces/alpha/skills',undefined,childSecret)).status()!==200)throw Error('Child read failed');
  if((await req('GET','/v1/admin/users',undefined,childSecret)).status()!==403)throw Error('Child elevated privileges');
  await page.setViewportSize({width:390,height:844});
  if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth))throw Error('Mobile overflow');
  if(process.env.SCREENSHOT_DIR)await page.screenshot({path:process.env.SCREENSHOT_DIR+'/account-mobile.png',fullPage:true});
  await page.setViewportSize({width:1440,height:1000});
  await page.locator('#token-list tbody tr').filter({has:page.locator('td:first-child',{hasText:'parent'})}).getByRole('button',{name:'Revoke',exact:true}).click();
  await expect(page.locator('#token-list')).not.toContainText('Active');
  if((await req('GET','/auth/me',undefined,childSecret)).status()!==401)throw Error('Revoked descendant still works');
  // User-delete operator has a delete-only UI and cannot administer privileged users.
  await page.locator('#manage-users').click();
  for(const [name,role] of [['operator','user-delete'],['victim','user']]){
   await page.locator('#create-user-form [name=email]').fill(name+'@example.test');
   await page.locator('#create-user-form [name=username]').fill(name);
   await page.locator('#create-user-form [name=password]').fill('browser-original-password');
   await page.locator('#create-user-form [name=system_role]').selectOption(role);
   await page.locator('#create-user-form button').click();await expect(page.locator('#users-list')).toContainText(name);
  }
  const operator=await browser.newPage();operator.on('dialog',d=>d.accept());
  await operator.goto(base);await operator.locator('#auth-toggle').click();
  await operator.locator('#auth-form [name=login]').fill('operator');await operator.locator('#auth-form [name=password]').fill('browser-original-password');
  await operator.locator('#auth-submit').click();await expect(operator.locator('#workspace')).toBeVisible();
  await operator.locator('#manage-users').click();await expect(operator.locator('#create-user-card')).toBeHidden();
  await expect(operator.locator('#users-list button',{hasText:'Manage'})).toHaveCount(0);
  const victimRow=operator.locator('#users-list tr').filter({hasText:'victim@example.test'});
  await victimRow.getByRole('button',{name:'Delete user',exact:true}).click();await expect(victimRow).toHaveCount(0);
  await expect(operator.locator('#users-list button')).toHaveCount(0);
  await operator.close();
  await page.locator('#my-account').click();
  await page.locator('#password-form [name=current_password]').fill('browser-original-password');
  await page.locator('#password-form [name=new_password]').fill('browser-replacement-password');
  await page.locator('#password-form [name=confirmation]').fill('browser-replacement-password');
  await page.locator('#password-form button').click();await expect(page.locator('#auth')).toBeVisible();
  await expect(page.locator('#token-secret')).toHaveValue('');
  await page.locator('#auth-form [name=login]').fill('owner');await page.locator('#auth-form [name=password]').fill('browser-replacement-password');
  await page.locator('#auth-submit').click();await expect(page.locator('#workspace')).toBeVisible();
  if(errors.length)throw Error(errors.join('\n'));
  console.log('Account UI passed: root/child tokens, reduced roles, cascade revoke, user-delete, password, mobile.');
 } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exit(1)});
