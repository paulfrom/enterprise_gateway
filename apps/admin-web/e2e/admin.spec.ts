import { test, expect, type Page } from '@playwright/test';
const password = 'admin@123'; // Fixed credential of this newly isolated synthetic runtime only.
async function login(page: Page) {
  await page.goto('/login');
  await page.getByLabel('用户名', { exact: true }).fill('admin');
  await page.getByLabel('密码', { exact: true }).fill(password);
  await page.getByRole('button', { name: /登\s*录/ }).click();
  await expect(page).toHaveURL(/\/admin$/);
}
async function history(page: Page) {
  await login(page); await page.getByRole('link', { name: '请求历史', exact: true }).click();
  await expect(page.getByRole('button', { name: '查看详情' })).toHaveCount(4);
}
test('anonymous redirect, wrong credentials, actual login and refresh restore', async ({ page }) => {
  await page.goto('/admin/requests'); await expect(page).toHaveURL(/\/login$/);
  await page.getByLabel('用户名', { exact: true }).fill('admin');
  await page.getByLabel('密码', { exact: true }).fill('synthetic-wrong');
  await page.getByRole('button', { name: /登\s*录/ }).click();
  await expect(page.getByText('用户名或密码错误')).toBeVisible();
  await page.getByLabel('密码', { exact: true }).fill(password);
  await page.getByRole('button', { name: /登\s*录/ }).click();
  await expect(page).toHaveURL(/\/admin$/); await page.reload();
  await expect(page.getByText('管理 API 已连接，会话有效')).toBeVisible();
  const cookies = await page.context().cookies();
  expect(cookies.some(c => c.httpOnly && c.sameSite === 'Strict')).toBeTruthy();
  expect(await page.evaluate(() => localStorage.length + sessionStorage.length)).toBe(0);
});
test('filter and cursor pagination use the real history store', async ({ page }) => {
  await history(page); await page.getByLabel('每页', { exact: true }).fill('1');
  await page.getByRole('button', { name: /筛\s*选/, exact: true }).click();
  await expect(page.getByRole('button', { name: '查看详情' })).toHaveCount(1);
  await page.getByRole('button', { name: '下一页' }).click();
  await expect(page.getByText('第 2 页')).toBeVisible();
  await page.getByRole('button', { name: '上一页' }).click();
  await expect(page.getByText('第 1 页')).toBeVisible();
  await page.getByLabel('模型', { exact: true }).fill('nonexistent-synthetic-model');
  await page.getByRole('button', { name: /筛\s*选/, exact: true }).click();
  await expect(page.getByText('没有请求记录')).toBeVisible();
});
test('four-stage detail and copy preserve plaintext as text, including malicious HTML', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']); await history(page);
  const count = await page.getByRole('button', { name: '查看详情' }).count();
  let found = false;
  for (let i = 0; i < count; i++) {
    await page.getByRole('button', { name: '查看详情' }).nth(i).click();
    await expect(page.getByRole('tab', { name: '输入' })).toBeVisible();
    for (const name of ['输入', '脱敏', '上游', '还原']) await page.getByRole('tab', { name, exact: true }).click();
    const text = await page.locator('.ant-modal .ant-tabs-tabpane-active pre').textContent();
    if (text?.includes('HTML_RENDER_PROBE') || text?.includes('<img')) {
      found = true;
      expect(await page.locator('.ant-modal img').count()).toBe(0);
      await page.locator('.ant-modal .ant-tabs-tabpane-active').getByRole('button', { name: '复制正文' }).click();
      await expect(page.locator('.ant-modal .ant-tabs-tabpane-active').getByText('已复制原始正文')).toBeVisible();
      expect(await page.evaluate(() => navigator.clipboard.readText())).toContain('<');
    }
    await page.getByRole('button', { name: 'Close' }).click();
  }
  expect(found).toBeTruthy();
});
test('same-origin and CSRF checks remain effective; logout blocks cookie replay', async ({ page, request }) => {
  await login(page);
  const denied = await page.request.post('/api/admin/logout', { headers: { Origin: new URL(page.url()).origin } });
  expect(denied.status()).toBe(403);
  const cross = await request.post('/api/admin/login', { headers: { Origin: 'http://foreign.test' }, data: { username: 'admin', password } });
  expect(cross.status()).toBe(403);
  const cookie = (await page.context().cookies()).map(c => c.name + '=' + c.value).join('; ');
  await page.getByRole('button', { name: /退\s*出/, exact: true }).click();
  await expect(page).toHaveURL(/\/login$/);
  expect((await request.get('/api/admin/requests', { headers: { Cookie: cookie } })).status()).toBe(401);
  await page.goto('/admin/requests'); await expect(page).toHaveURL(/\/login$/);
});
test('server revocation clears detail and cannot render a delayed history response', async ({ page }) => {
  await history(page);
  let release!: () => void;
  let entered!: () => void;
  const arrived = new Promise<void>(resolve => { entered = resolve; });
  const gate = new Promise<void>(resolve => { release = resolve; });
  await page.route('**/api/admin/requests/*', async route => {
    const response = await route.fetch(); entered(); await gate;
    await route.fulfill({ response }).catch(() => {});
  });
  await page.getByRole('button', { name: '查看详情' }).first().click(); await arrived;
  const session = await (await page.request.get('/api/admin/session')).json();
  expect((await page.request.post('/api/admin/logout', { headers: { Origin: new URL(page.url()).origin, 'X-Admin-CSRF': session.csrf_token } })).status()).toBe(200);
  await expect(page).toHaveURL(/\/login$/, { timeout: 35000 }); release();
  await expect(page.locator('.ant-modal pre')).toHaveCount(0);
  await expect(page.getByRole('button', { name: '查看详情' })).toHaveCount(0);
});

test('dependency failure is visible and retry restores real history', async ({ page }) => {
  await login(page);
  await page.route('**/api/admin/requests?*', route => route.fulfill({
    status: 503, contentType: 'application/json', body: JSON.stringify({ error: { code: 'HISTORY_UNAVAILABLE' } }),
  }));
  await page.getByRole('link', { name: '请求历史', exact: true }).click();
  await expect(page.getByText('请求历史暂不可用，请检查数据库与密钥配置')).toBeVisible();
  await expect(page.getByRole('button', { name: '查看详情' })).toHaveCount(0);
  await page.unroute('**/api/admin/requests?*');
  await page.getByRole('button', { name: /重\s*试/, exact: true }).click();
  await expect(page.getByRole('button', { name: '查看详情' })).toHaveCount(4);
});

test('unavailable session store exposes the actual failure', async ({ page }) => {
  await page.route('**/api/admin/session', route => route.fulfill({
    status: 503, contentType: 'application/json', body: JSON.stringify({ error: { code: 'ADMIN_STORAGE_UNAVAILABLE' } }),
  }));
  await page.goto('/admin');
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByText('管理员状态存储不可用')).toBeVisible();
  await expect(page.getByText('管理 API 已连接，会话有效')).toHaveCount(0);
});

test('logout cancels a pending detail and drops previously loaded bodies', async ({ page }) => {
  await history(page);
  await page.getByRole('button', { name: '查看详情' }).first().click();
  await expect(page.locator('.ant-modal pre').first()).toBeVisible();
  await page.getByRole('button', { name: 'Close' }).click();
  let release!: () => void;
  let entered!: () => void;
  const arrived = new Promise<void>(resolve => { entered = resolve; });
  const gate = new Promise<void>(resolve => { release = resolve; });
  await page.route('**/api/admin/requests/*', async route => {
    const response = await route.fetch(); entered(); await gate;
    await route.fulfill({ response }).catch(() => {});
  });
  await page.getByRole('button', { name: '查看详情' }).last().click();
  await arrived;
  // The pending detail modal has no body yet; close it to reach the real logout control.
  await page.getByRole('button', { name: 'Close' }).click();
  await page.getByRole('button', { name: /退\s*出/, exact: true }).click();
  await expect(page).toHaveURL(/\/login$/);
  release();
  await expect(page.locator('.ant-modal pre')).toHaveCount(0);
  await expect(page.getByRole('button', { name: '查看详情' })).toHaveCount(0);
  await login(page);
  await expect(page.locator('.ant-modal pre')).toHaveCount(0);
});

test('failed logout still removes protected content and reports unconfirmed revocation', async ({ page }) => {
  await history(page);
  await page.getByRole('button', { name: '查看详情' }).first().click();
  await expect(page.locator('.ant-modal pre').first()).toBeVisible();
  await page.getByRole('button', { name: 'Close' }).click();
  await page.route('**/api/admin/logout', route => route.fulfill({
    status: 503, contentType: 'application/json',
    body: JSON.stringify({ error: { code: 'ADMIN_STORAGE_UNAVAILABLE' } }),
  }));
  await page.getByRole('button', { name: /退\s*出/, exact: true }).click();
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByText('服务端退出未确认：管理员状态存储不可用')).toBeVisible();
  await expect(page.locator('.ant-modal pre')).toHaveCount(0);
  await expect(page.getByRole('button', { name: '查看详情' })).toHaveCount(0);
});
