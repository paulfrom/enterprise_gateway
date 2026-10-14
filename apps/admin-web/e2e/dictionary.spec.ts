import { test, expect } from '@playwright/test';

test('dictionary drafts persist, publication updates file detection, and logout clears terms', async ({ page }) => {
  await page.goto('/login');
  await page.getByLabel('用户名', { exact: true }).fill('admin');
  await page.getByLabel('密码', { exact: true }).fill('admin@123');
  await page.getByRole('button', { name: /登\s*录/ }).click();
  await expect(page).toHaveURL(/\/admin$/);
  await page.goto('/admin/dictionary');
  const term = 'DICTIONARY_BROWSER_ENTITY_88317';
  await expect(page.getByText('本地脱敏词典', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: '新增词条', exact: true }).click();
  const drawer = page.getByRole('dialog');
  await drawer.getByLabel('实体文本', { exact: true }).fill(term);
  await drawer.getByLabel('实体类型', { exact: true }).fill('PROJECT');
  await drawer.getByLabel('实体类型', { exact: true }).press('Enter');
  const saved = page.waitForResponse(response => response.url().endsWith('/api/admin/dictionary/entries') &&
    response.request().method() === 'POST');
  await drawer.getByRole('button', { name: '保存草稿', exact: true }).click();
  expect((await saved).status()).toBe(200);
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await page.reload();
  await expect(page.getByRole('row').filter({ hasText: term })).toBeVisible();
  await expect(page.getByText('草稿有未发布修改', { exact: true })).toBeVisible();
  const published = page.waitForResponse(response => response.url().endsWith('/api/admin/dictionary/publish'));
  await page.getByRole('button', { name: '发布词典', exact: true }).click();
  expect((await published).status()).toBe(200);
  await expect(page.getByText('草稿与发布版本一致', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: '发布记录', exact: true }).click();
  await expect(page.getByText('词典发布记录', { exact: true })).toBeVisible();
  await page.goto('/admin/documents');
  await page.getByLabel('文件（最大 10 MiB）').setInputFiles({
    name: 'synthetic-dictionary.txt', mimeType: 'text/plain', buffer: Buffer.from(term),
  });
  await page.getByRole('button', { name: /开始脱敏/ }).click();
  const preview = page.getByLabel('脱敏文本');
  await expect(preview).toBeVisible();
  await expect(preview).not.toContainText(term);
  await expect(preview).toContainText(/<[A-Z][A-Z0-9_]*_\d{3,}>/);
  await page.goto('/admin/dictionary');
  const row = page.getByRole('row').filter({ hasText: term });
  await row.getByRole('button', { name: '编辑', exact: true }).click();
  await page.getByRole('dialog').getByRole('switch').uncheck();
  await page.getByRole('dialog').getByRole('button', { name: '保存草稿', exact: true }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await expect(row.getByText('停用', { exact: true })).toBeVisible();
  await row.getByRole('button', { name: /删\s*除/, exact: true }).click();
  await page.getByRole('button', { name: /删\s*除/, exact: true }).last().click();
  await expect(page.getByRole('row').filter({ hasText: term })).toHaveCount(0);
  await page.getByRole('button', { name: '发布词典', exact: true }).click();
  await expect(page.getByText('草稿与发布版本一致', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: /退\s*出/, exact: true }).click();
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByText(term, { exact: true })).toHaveCount(0);
});
