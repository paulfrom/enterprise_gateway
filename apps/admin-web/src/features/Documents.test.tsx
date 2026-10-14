import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { api, ApiError, type DocumentRedaction } from '../api/client';
import { Documents } from './Documents';

const result: DocumentRedaction = {
  format: 'txt', output_format: 'markdown', redacted_text: '联系电话 <<ENT_file-v1_abc>>',
  characters: 16, block_count: 1, entity_count: 1, replacement_count: 1,
  entity_types: { PHONE_NUMBER: 1 }, warnings: [], package_hash: 'ab'.repeat(32),
};
afterEach(() => vi.restoreAllMocks());

function choose(file: File) {
  fireEvent.change(screen.getByLabelText('文件（最大 10 MiB）'), { target: { files: [file] } });
}

describe('file redaction', () => {
  it('uploads only after an explicit action, shows plain text and downloads the returned artifact', async () => {
    const redact = vi.spyOn(api, 'redactDocument').mockResolvedValue({ ...result,
      redacted_text: '<img src=x onerror="window.bad=true"> <<ENT_file-v1_abc>>' });
    const create = vi.fn(() => 'blob:synthetic-file');
    Object.defineProperty(URL, 'createObjectURL', { value: create, configurable: true });
    Object.defineProperty(URL, 'revokeObjectURL', { value: vi.fn(), configurable: true });
    let downloadName = '';
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) { downloadName = this.download; });
    render(<Documents />);
    const file = new File(['原始合成文本'], 'private-name.TXT');
    choose(file);
    expect(redact).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: /开始脱敏/ }));
    await screen.findByLabelText('脱敏文本');
    expect(redact).toHaveBeenCalledWith(file, 'txt', expect.any(AbortSignal));
    expect(screen.getByLabelText('脱敏文本').querySelector('img')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: /下载 Markdown/ }));
    expect(create).toHaveBeenCalledWith(expect.any(Blob));
    expect(downloadName).toBe('redacted.md');
    fireEvent.click(screen.getByRole('button', { name: /清\s*除/ }));
    expect(screen.queryByLabelText('脱敏文本')).not.toBeInTheDocument();
  });

  it('clears old results when another file is selected and shows static parser warnings', async () => {
    vi.spyOn(api, 'redactDocument').mockResolvedValue({ ...result, warnings: ['SPREADSHEET_HIDDEN_CONTENT_INCLUDED'] });
    render(<Documents />);
    choose(new File(['a'], 'sample.txt'));
    fireEvent.click(screen.getByRole('button', { name: /开始脱敏/ }));
    await screen.findByLabelText('脱敏文本');
    expect(screen.getByText('已包含隐藏工作表、行或列中的文字。')).toBeInTheDocument();
    choose(new File(['b'], 'next.txt'));
    expect(screen.queryByLabelText('脱敏文本')).not.toBeInTheDocument();
  });

  it('blocks unsupported and oversized files before uploading', () => {
    const redact = vi.spyOn(api, 'redactDocument');
    render(<Documents />);
    choose(new File(['a'], 'old.doc'));
    expect(screen.getByText(/不支持此格式；旧版 DOC/)).toBeInTheDocument();
    choose(new File([new Uint8Array(10 * 1024 * 1024 + 1)], 'large.txt'));
    expect(screen.getByText(/文件最大为 10 MiB，请缩小/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /开始脱敏/ })).toBeDisabled();
    expect(redact).not.toHaveBeenCalled();
  });

  it('shows detection errors without an export button', async () => {
    vi.spyOn(api, 'redactDocument').mockRejectedValue(new ApiError(503, 'DOCUMENT_DETECTION_UNAVAILABLE'));
    render(<Documents />);
    choose(new File(['a'], 'sample.txt'));
    fireEvent.click(screen.getByRole('button', { name: /开始脱敏/ }));
    await screen.findByText('必需检测器或版本校验失败，未生成脱敏文件');
    expect(screen.queryByRole('button', { name: /下载 Markdown/ })).not.toBeInTheDocument();
  });

  it('aborts an active upload on navigation or logout', async () => {
    const redact = vi.spyOn(api, 'redactDocument').mockImplementation(() => new Promise(() => {}));
    const { unmount } = render(<Documents />);
    choose(new File(['a'], 'sample.txt'));
    fireEvent.click(screen.getByRole('button', { name: /开始脱敏/ }));
    await waitFor(() => expect(redact).toHaveBeenCalled());
    const signal = redact.mock.calls[0][2];
    unmount();
    expect(signal?.aborted).toBe(true);
  });
});
