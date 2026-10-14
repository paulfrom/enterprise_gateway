import { useEffect, useRef, useState } from 'react';
import { Alert, Button, Card, Descriptions, Space, Tag, Typography } from 'antd';
import { DownloadOutlined, FileProtectOutlined } from '@ant-design/icons';
import { api, errorText, type DocumentFormat, type DocumentRedaction } from '../api/client';

const formats: DocumentFormat[] = ['txt', 'md', 'csv', 'json', 'yaml', 'yml', 'docx', 'xlsx', 'xlsm', 'xls', 'pdf'];
const warnings: Record<string, string> = {
  DOCX_REVISIONS_INCLUDED: '已读取修订内容，请核对文本顺序。',
  DOCX_ANCILLARY_INCLUDED: '已读取页眉、页脚、批注或脚注。',
  SPREADSHEET_MACROS_OMITTED: '宏不会执行，也不会进入下载文件。',
  SPREADSHEET_HIDDEN_CONTENT_INCLUDED: '已包含隐藏工作表、行或列中的文字。',
  SPREADSHEET_FORMULAS_AS_TEXT: '公式按文字处理，不重新计算。',
  SPREADSHEET_COMMENTS_INCLUDED: '已包含单元格批注。',
  XLS_CACHED_VALUES_ONLY: '旧版 XLS 仅能读取缓存值，无法审查公式和其他对象；请核对，或先转换为 XLSX。',
  PDF_LAYOUT_NOT_PRESERVED: 'PDF 输出按读取顺序组织，不保留原始版式。',
};

export function Documents() {
  const [file, setFile] = useState<File>();
  const [result, setResult] = useState<DocumentRedaction>();
  const [failure, setFailure] = useState<string>();
  const [busy, setBusy] = useState(false);
  const controller = useRef<AbortController>();
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => () => controller.current?.abort(), []);

  function selectFile(selected?: File) {
    controller.current?.abort();
    setResult(undefined);
    setFailure(undefined);
    setFile(undefined);
    if (!selected) return;
    const extension = selected.name.split('.').pop()?.toLowerCase();
    if (!formats.includes(extension as DocumentFormat)) {
      setFailure('不支持此格式；旧版 DOC 请先转换为 DOCX。');
    } else if (selected.size > 10 * 1024 * 1024) {
      setFailure('文件最大为 10 MiB，请缩小文件后重试。');
    } else if (!selected.size) {
      setFailure('文件为空，请选择包含文字的文件。');
    } else {
      setFile(selected);
    }
  }

  async function redact() {
    if (!file) return;
    const active = new AbortController();
    controller.current = active;
    setBusy(true);
    setFailure(undefined);
    setResult(undefined);
    try {
      const value = await api.redactDocument(file, file.name.split('.').pop()!.toLowerCase() as DocumentFormat, active.signal);
      if (!active.signal.aborted) setResult(value);
    } catch (error) {
      if (!active.signal.aborted && !(error instanceof DOMException && error.name === 'AbortError')) {
        setFailure(errorText(error));
      }
    } finally {
      if (!active.signal.aborted) setBusy(false);
    }
  }

  function download() {
    if (!result) return;
    const url = URL.createObjectURL(new Blob([result.redacted_text], { type: 'text/markdown;charset=utf-8' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = 'redacted.md';
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  return (
    <Space direction="vertical" size="large" style={{ width: '100%' }}>
      <div>
        <Typography.Title level={2}>文件脱敏</Typography.Title>
        <Typography.Paragraph type="secondary">
          读取文件文字，通过本地规则、词典与 NER 检测，生成脱敏 Markdown。原文件保持不变。
        </Typography.Paragraph>
      </div>
      <Alert type="info" showIcon message="下载内容为提取后的文字，不保留原文件版式"
        description="支持 UTF-8 文本、DOCX、Excel 和文字型 PDF。图片、扫描 PDF 与嵌入对象会阻断处理。结果需人工核对，检测通过不代表所有敏感信息都已识别。" />
      <Card title="选择文件">
        <Space direction="vertical" size="middle" style={{ width: '100%' }}>
          <label htmlFor="redaction-file">文件（最大 10 MiB）</label>
          <input id="redaction-file" ref={input} type="file" disabled={busy}
            accept={formats.map(value => '.' + value).join(',')}
            onChange={event => selectFile(event.target.files?.[0])} />
          <Typography.Text type="secondary">TXT · MD · CSV · JSON · YAML · DOCX · XLSX · XLSM · XLS · PDF</Typography.Text>
          <Space wrap>
            <Button type="primary" icon={<FileProtectOutlined />} loading={busy} disabled={!file}
              onClick={() => void redact()}>{busy ? '正在解析与脱敏' : '开始脱敏'}</Button>
            <Button disabled={busy || (!file && !result && !failure)} onClick={() => {
              selectFile();
              if (input.current) input.current.value = '';
            }}>清除</Button>
          </Space>
          {failure && <Alert type="error" showIcon message={failure} />}
        </Space>
      </Card>
      {result && <Card title="脱敏结果" extra={<Button icon={<DownloadOutlined />} onClick={download}>下载 Markdown</Button>}>
        <Space direction="vertical" size="middle" style={{ width: '100%' }}>
          <Descriptions size="small" column={{ xs: 1, sm: 3 }} items={[
            { key: 'characters', label: '提取字符', children: result.characters.toLocaleString() },
            { key: 'entities', label: '不同敏感项', children: result.entity_count },
            { key: 'replacements', label: '替换次数', children: result.replacement_count },
          ]} />
          <Space wrap>{Object.entries(result.entity_types).map(([type, count]) => <Tag key={type}>{type} · {count}</Tag>)}</Space>
          {result.warnings.length > 0 && <Alert type="warning" showIcon message="解析提示，请核对结果"
            description={<ul>{result.warnings.map(code => <li key={code}>{warnings[code] ?? '文件包含需要人工核对的内容。'}</li>)}</ul>} />}
          <Typography.Paragraph type="secondary">仅保存本页处理结果；离开页面或退出登录后清除。下载文件不包含原值映射，无法自动回填。</Typography.Paragraph>
          <pre aria-label="脱敏文本" style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', maxHeight: 560, overflow: 'auto',
            padding: 20, margin: 0, background: '#fafafa', border: '1px solid #f0f0f0', borderRadius: 8 }}>{result.redacted_text}</pre>
        </Space>
      </Card>}
    </Space>
  );
}
