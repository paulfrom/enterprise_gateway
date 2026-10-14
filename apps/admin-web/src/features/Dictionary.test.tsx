import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ConfigProvider } from 'antd';
import { api, ApiError, type DictionaryPage } from '../api/client';
import { Dictionary } from './Dictionary';

const page: DictionaryPage = {
  dictionary_id: 'synthetic', revision: 2, published_revision: 1,
  published_sha256: 'ab'.repeat(32), published_entries: 1,
  updated_at: '2026-10-13T00:00:00Z', total: 1, offset: 0, limit: 50,
  items: [{ entry_id: '00000000-0000-0000-0000-000000000001', text: '合成企业甲',
    entity_type: 'ORG', enabled: true, updated_at: '2026-10-13T00:00:00Z' }],
};
afterEach(() => vi.restoreAllMocks());

function show() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<ConfigProvider theme={{ token: { motion: false } }}>
    <QueryClientProvider client={client}><Dictionary /></QueryClientProvider>
  </ConfigProvider>);
}

describe('dictionary editing', { timeout: 15000 }, () => {
  it('saves an exact draft with the revision captured when editing starts', async () => {
    vi.spyOn(api, 'dictionary').mockResolvedValue(page);
    const save = vi.spyOn(api, 'saveDictionaryEntry').mockResolvedValue(page);
    show();
    await screen.findByText('合成企业甲');
    fireEvent.click(screen.getByRole('button', { name: /编\s*辑/ }));
    const drawer = screen.getByRole('dialog');
    fireEvent.change(within(drawer).getByLabelText('实体文本'), { target: { value: '合成企业乙' } });
    fireEvent.click(within(drawer).getByRole('button', { name: '保存草稿' }));
    await waitFor(() => expect(save).toHaveBeenCalledWith({
      text: '合成企业乙', entity_type: 'ORG', enabled: true, expected_revision: 2,
    }, page.items[0].entry_id));
    await screen.findByText('词条已保存到草稿。发布后用于脱敏。');
  });

  it('publishes the displayed revision and disables publication without draft changes', async () => {
    const listing = vi.spyOn(api, 'dictionary').mockResolvedValue(page);
    const publish = vi.spyOn(api, 'publishDictionary').mockResolvedValue({ ...page, published_revision: 2 });
    show();
    await screen.findByText('合成企业甲');
    listing.mockResolvedValue({ ...page, published_revision: 2 });
    fireEvent.click(screen.getByRole('button', { name: /发布词典/ }));
    await waitFor(() => expect(publish).toHaveBeenCalledWith(2));
    await screen.findByText('草稿与发布版本一致');
    expect(screen.getByRole('button', { name: /发布词典/ })).toBeDisabled();
  });

  it('keeps the typed draft and requires reopening after a revision conflict', async () => {
    vi.spyOn(api, 'dictionary').mockResolvedValue(page);
    const save = vi.spyOn(api, 'saveDictionaryEntry').mockRejectedValue(new ApiError(409, 'DICTIONARY_REVISION_CONFLICT'));
    show();
    await screen.findByText('合成企业甲');
    fireEvent.click(screen.getByRole('button', { name: /编\s*辑/ }));
    const drawer = screen.getByRole('dialog');
    const input = within(drawer).getByLabelText('实体文本');
    fireEvent.change(input, { target: { value: '合成修改' } });
    fireEvent.click(within(drawer).getByRole('button', { name: '保存草稿' }));
    await screen.findByText('词典已发生修改，请关闭编辑并重新打开后核对。');
    expect(input).toHaveValue('合成修改');
    expect(within(drawer).getByRole('button', { name: '保存草稿' })).toBeDisabled();
    expect(save).toHaveBeenCalledTimes(1);
  });

  it('provides an unavailable state without editable data', async () => {
    vi.spyOn(api, 'dictionary').mockRejectedValue(new ApiError(503, 'DICTIONARY_UNAVAILABLE'));
    show();
    await screen.findByText('词典服务暂不可用，请检查数据库表和服务配置');
    expect(screen.getByRole('button', { name: /新增词条/ })).toBeDisabled();
    expect(screen.getByRole('button', { name: /发布词典/ })).toBeDisabled();
  });
});
