import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';

test('real file upload, safe preview, download, refresh and logout', async ({ page }) => {
  await page.goto('/admin/documents');
  await expect(page).toHaveURL(/\/login$/);
  await page.getByLabel('用户名', { exact: true }).fill('admin');
  await page.getByLabel('密码', { exact: true }).fill('admin@123');
  await page.getByRole('button', { name: /登\s*录/ }).click();
  await expect(page).toHaveURL(/\/admin$/);
  await page.goto('/admin/documents');
  await expect(page.getByRole('heading', { name: '文件脱敏' })).toBeVisible();
  const original = '甲公司和乙公司。张三的电话：13800138000。\n<img src=x onerror="window.fileExecuted=true">';
  await page.getByLabel('文件（最大 10 MiB）').setInputFiles({ name: 'private-synthetic.txt',
    mimeType: 'text/plain', buffer: Buffer.from(original) });
  const response = page.waitForResponse(r => r.url().includes('/api/admin/documents/redact'));
  await page.getByRole('button', { name: /开始脱敏/ }).click();
  const completed = await response;
  expect(completed.status()).toBe(200);
  expect(completed.request().url()).toMatch(/\?format=txt$/);
  expect(completed.request().headers()['content-type']).toBe('application/octet-stream');
  expect(completed.request().url()).not.toContain('private-synthetic');
  const preview = page.getByLabel('脱敏文本');
  await expect(preview).toContainText('<ORG_');
  for (const value of ['甲公司', '乙公司', '张三', '13800138000']) {
    await expect(preview).not.toContainText(value);
  }
  expect(await preview.locator('img').count()).toBe(0);
  expect(await page.evaluate(() => 'fileExecuted' in window)).toBe(false);
  const waiting = page.waitForEvent('download');
  await page.getByRole('button', { name: /下载 Markdown/ }).click();
  const download = await waiting;
  expect(download.suggestedFilename()).toBe('redacted.md');
  const exported = await readFile((await download.path())!, 'utf8');
  expect(exported).toBe(await preview.textContent());
  expect(exported).not.toContain('13800138000');
  await page.reload();
  await expect(page.getByRole('heading', { name: '文件脱敏' })).toBeVisible();
  await expect(page.getByLabel('脱敏文本')).toHaveCount(0);
  expect(await page.evaluate(() => localStorage.length + sessionStorage.length)).toBe(0);
  await page.getByRole('button', { name: /退\s*出/, exact: true }).click();
  await expect(page).toHaveURL(/\/login$/);
});

test('unsupported files and high-sensitivity secrets produce no download', async ({ page }) => {
  await page.goto('/login');
  await page.getByLabel('用户名', { exact: true }).fill('admin');
  await page.getByLabel('密码', { exact: true }).fill('admin@123');
  await page.getByRole('button', { name: /登\s*录/ }).click();
  await expect(page).toHaveURL(/\/admin$/);
  await page.goto('/admin/documents');
  await page.getByLabel('文件（最大 10 MiB）').setInputFiles({ name: 'old.doc', mimeType: 'application/msword', buffer: Buffer.from('synthetic') });
  await expect(page.getByText('不支持此格式；旧版 DOC 请先转换为 DOCX。')).toBeVisible();
  await expect(page.getByRole('button', { name: /开始脱敏/ })).toBeDisabled();
  await page.getByLabel('文件（最大 10 MiB）').setInputFiles({ name: 'secret.txt', mimeType: 'text/plain', buffer: Buffer.from('sk-ABCDEFGH123456789') });
  await page.getByRole('button', { name: /开始脱敏/ }).click();
  await expect(page.getByText('检测到高敏秘密，文件处理已阻断')).toBeVisible();
  await expect(page.getByRole('button', { name: /下载 Markdown/ })).toHaveCount(0);
});
