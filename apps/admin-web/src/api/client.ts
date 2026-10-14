import type { components, paths } from './schema';

export type Session = components['schemas']['AdminSession'];
export type HistoryPage = components['schemas']['HistoryPage'];
export type HistoryDetail = components['schemas']['HistoryDetail'];
export type HistoryFilters = NonNullable<paths['/api/admin/requests']['get']['parameters']['query']>;
export type Login = paths['/api/admin/login']['post']['requestBody']['content']['application/json'];

export type ObjectPage = components['schemas']['ObjectPage'];
export type ObjectDetail = components['schemas']['ObjectDetail'];
export type Governance = components['schemas']['Governance'];
export type GovernanceResult = components['schemas']['GovernanceResult'];
export type Withdraw = components['schemas']['Withdraw'];
export type WithdrawResult = components['schemas']['WithdrawResult'];
export type Publish = components['schemas']['Publish'];
export type PublishResult = components['schemas']['PublishResult'];
export type RejectResult = components['schemas']['RejectResult'];
export type Revise = components['schemas']['Revise'];
export type ReviseResult = components['schemas']['ReviseResult'];
export type Basis = components['schemas']['Basis'];
export type Revocation = components['schemas']['Revocation'];
export type DocumentRedaction = components['schemas']['DocumentRedaction'];
export type DocumentFormat = NonNullable<paths['/api/admin/documents/redact']['post']['parameters']['query']>['format'];
export type DictionaryPage = components['schemas']['DictionaryPage'];
export type DictionaryEntry = components['schemas']['DictionaryEntryView'];
export type DictionaryState = components['schemas']['DictionaryState'];
export type DictionaryVersions = components['schemas']['DictionaryVersions'];
export type DictionaryFilters = NonNullable<paths['/api/admin/dictionary']['get']['parameters']['query']>;
export type DictionaryEdit = paths['/api/admin/dictionary/entries']['post']['requestBody']['content']['application/json'];
export type AuditPage = components['schemas']['AuditPage'];
export type AuditDetail = components['schemas']['AuditDetail'];
export type CatalogEntry = components['schemas']['CatalogEntry'];

export type GraphQueryRequest = components['schemas']['GraphQueryRequest'];
export type GraphQueryResponse = components['schemas']['GraphQueryResponse'];
export type GraphRebuildResponse = components['schemas']['GraphRebuildResponse'];
export type GraphNodeDTO = components['schemas']['GraphNodeDTO'];
export type GraphEdgeDTO = components['schemas']['GraphEdgeDTO'];

export type SourceFilters = NonNullable<paths['/api/admin/sources']['get']['parameters']['query']>;
export type CandidateFilters = NonNullable<paths['/api/admin/candidates']['get']['parameters']['query']>;
export type PublicationFilters = NonNullable<paths['/api/admin/publications']['get']['parameters']['query']>;
export type ObservationFilters = NonNullable<paths['/api/admin/observations']['get']['parameters']['query']>;
export type AuditFilters = NonNullable<paths['/api/admin/audit/records']['get']['parameters']['query']>;
export type AuditEventsFilters = NonNullable<paths['/api/admin/audit/events']['get']['parameters']['query']>;

export class ApiError extends Error {
  constructor(public status: number, public code: string) { super(code); }
}

let csrf: string | undefined;
let generation = 0;
let expired: (() => void) | undefined;
const pending = new Set<AbortController>();

export function setSession(session: Session | null) { csrf = session?.csrf_token; }
export function onExpired(callback: () => void) { expired = callback; return () => { expired = undefined; }; }
export function clearSession() {
  generation++;
  csrf = undefined;
  for (const req of pending) req.abort();
  pending.clear();
}

function buildParams(filters: Record<string, unknown>): string {
  const params = new URLSearchParams();
  Object.entries(filters).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      params.set(key, String(value));
    }
  });
  const queryString = params.toString();
  return queryString ? '?' + queryString : '';
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const version = generation;
  const controller = new AbortController();
  const abort = () => controller.abort();
  options.signal?.addEventListener('abort', abort, { once: true });
  if (options.signal?.aborted) controller.abort();
  pending.add(controller);
  try {
    const response = await fetch(path, {
      ...options,
      signal: controller.signal,
      credentials: 'same-origin',
      headers: {
        ...(options.body ? { 'Content-Type': 'application/json' } : {}),
        ...(options.method === 'POST' && csrf ? { 'X-Admin-CSRF': csrf } : {}),
        ...options.headers,
      },
    });
    const payload = await response.json().catch(() => null);
    if (version !== generation || controller.signal.aborted) {
      throw new DOMException('Session changed', 'AbortError');
    }
    if (!response.ok) {
      if (response.status === 401 && path !== '/api/admin/login') expired?.();
      throw new ApiError(response.status, payload?.error?.code ?? 'INVALID_RESPONSE');
    }
    if (payload === null) throw new ApiError(502, 'INVALID_RESPONSE');
    return payload as T;
  } finally {
    pending.delete(controller);
    options.signal?.removeEventListener('abort', abort);
  }
}

export const api = {
  session: (signal?: AbortSignal) => request<Session>('/api/admin/session', { signal }),
  login: (body: Login) => request<Session>('/api/admin/login', { method: 'POST', body: JSON.stringify(body) }),
  logout: () => request<Revocation>('/api/admin/logout', { method: 'POST' }),

  dictionary: (filters: DictionaryFilters, signal?: AbortSignal) =>
    request<DictionaryPage>('/api/admin/dictionary' + buildParams(filters), { signal }),
  dictionaryVersions: (signal?: AbortSignal) =>
    request<DictionaryVersions>('/api/admin/dictionary/versions', { signal }),
  saveDictionaryEntry: (body: DictionaryEdit, entryId?: string) =>
    request<DictionaryState>('/api/admin/dictionary/entries' + (entryId ? '/' + encodeURIComponent(entryId) : ''), {
      method: 'POST', body: JSON.stringify(body),
    }),
  deleteDictionaryEntry: (entryId: string, revision: number) =>
    request<DictionaryState>('/api/admin/dictionary/entries/' + encodeURIComponent(entryId) + '/delete', {
      method: 'POST', body: JSON.stringify({ expected_revision: revision }),
    }),
  publishDictionary: (revision: number) =>
    request<DictionaryState>('/api/admin/dictionary/publish', {
      method: 'POST', body: JSON.stringify({ expected_revision: revision }),
    }),

  redactDocument: (file: File, format: DocumentFormat, signal?: AbortSignal) =>
    request<DocumentRedaction>('/api/admin/documents/redact?format=' + encodeURIComponent(format), {
      method: 'POST', body: file, headers: { 'Content-Type': 'application/octet-stream' }, signal,
    }),

  history: (filters: HistoryFilters, signal?: AbortSignal) =>
    request<HistoryPage>('/api/admin/requests' + buildParams(filters as Record<string, unknown>), { signal }),
  detail: (id: string, signal?: AbortSignal) =>
    request<HistoryDetail>('/api/admin/requests/' + encodeURIComponent(id), { signal }),

  sources: (filters: SourceFilters, signal?: AbortSignal) =>
    request<ObjectPage>('/api/admin/sources' + buildParams(filters as Record<string, unknown>), { signal }),
  sourceDetail: (id: string, version?: string, signal?: AbortSignal) =>
    request<ObjectDetail>(
      '/api/admin/sources/' + encodeURIComponent(id) + (version ? `?version=${encodeURIComponent(version)}` : ''),
      { signal }
    ),
  governSource: (id: string, body: Governance) =>
    request<GovernanceResult>('/api/admin/sources/' + encodeURIComponent(id) + '/governance', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  withdrawSource: (id: string, body: Withdraw) =>
    request<WithdrawResult>('/api/admin/sources/' + encodeURIComponent(id) + '/withdraw', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  candidates: (filters: CandidateFilters, signal?: AbortSignal) =>
    request<ObjectPage>('/api/admin/candidates' + buildParams(filters as Record<string, unknown>), { signal }),
  candidateDetail: (id: string, consumer?: string, use?: string, signal?: AbortSignal) =>
    request<ObjectDetail>(
      '/api/admin/candidates/' + encodeURIComponent(id) + buildParams({ consumer, use }),
      { signal }
    ),
  publishCandidate: (id: string, body: Publish) =>
    request<PublishResult>('/api/admin/candidates/' + encodeURIComponent(id) + '/publish', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  rejectCandidate: (id: string, body: Basis) =>
    request<RejectResult>('/api/admin/candidates/' + encodeURIComponent(id) + '/reject', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  reviseCandidate: (id: string, body: Revise) =>
    request<ReviseResult>('/api/admin/candidates/' + encodeURIComponent(id) + '/revise', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  publications: (filters: PublicationFilters, signal?: AbortSignal) =>
    request<ObjectPage>('/api/admin/publications' + buildParams(filters as Record<string, unknown>), { signal }),
  publicationDetail: (id: string, consumer?: string, use?: string, signal?: AbortSignal) =>
    request<ObjectDetail>(
      '/api/admin/publications/' + encodeURIComponent(id) + buildParams({ consumer, use }),
      { signal }
    ),
  revokePublication: (id: string, body: Basis) =>
    request<Revocation>('/api/admin/publications/' + encodeURIComponent(id) + '/revoke', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  observations: (filters: ObservationFilters, signal?: AbortSignal) =>
    request<ObjectPage>('/api/admin/observations' + buildParams(filters as Record<string, unknown>), { signal }),
  observationDetail: (id: string, signal?: AbortSignal) =>
    request<ObjectDetail>('/api/admin/observations/' + encodeURIComponent(id), { signal }),

  auditRecords: (filters: AuditFilters, signal?: AbortSignal) =>
    request<AuditPage>('/api/admin/audit/records' + buildParams(filters as Record<string, unknown>), { signal }),
  auditRecordDetail: (id: string, signal?: AbortSignal) =>
    request<AuditDetail>('/api/admin/audit/records/' + encodeURIComponent(id), { signal }),
  auditEvents: (filters: AuditEventsFilters, signal?: AbortSignal) =>
    request<ObjectPage>('/api/admin/audit/events' + buildParams(filters as Record<string, unknown>), { signal }),

  graphQuery: (body: GraphQueryRequest, signal?: AbortSignal) =>
    request<GraphQueryResponse>('/api/admin/graph/query', {
      method: 'POST',
      body: JSON.stringify(body),
      signal,
    }),
  graphRebuild: (signal?: AbortSignal) =>
    request<GraphRebuildResponse>('/api/admin/graph/rebuild', {
      method: 'POST',
      signal,
    }),
};

export function errorText(error: unknown): string {
  if (error instanceof ApiError) {
    const errorMap: Record<string, string> = {
        DICTIONARY_UNAVAILABLE: '词典服务暂不可用，请检查数据库表和服务配置',
        DICTIONARY_SCOPE_REJECTED: '当前会话不能管理此词典',
        DICTIONARY_ENTRY_NOT_FOUND: '词条已不存在，请刷新列表',
        DICTIONARY_ENTRY_CONFLICT: '同一实体文本已存在，请编辑已有词条',
        DICTIONARY_REVISION_CONFLICT: '词典已被其他页面修改，请刷新后重新核对',
        DICTIONARY_EMPTY_PUBLICATION: '至少保留一个启用词条后才能发布',
        DICTIONARY_LIMIT_EXCEEDED: '词典已达到词条数量上限',
      ADMIN_LOGIN_FAILED: '用户名或密码错误',
      ADMIN_LOGIN_THROTTLED: '登录尝试过多，请稍后重试',
      ADMIN_SESSION_INVALID: '会话已过期，请重新登录',
      ADMIN_STORAGE_UNAVAILABLE: '管理员状态存储不可用',
      HISTORY_UNAVAILABLE: '请求历史暂不可用，请检查数据库与密钥配置',
      INVALID_HISTORY_QUERY: '筛选条件无效',
      HISTORY_NOT_FOUND: '记录不存在或已过期',
      ADMIN_ORIGIN_REJECTED: '登录来源校验失败',
      ADMIN_CSRF_INVALID: '会话校验失败，请刷新后重试',
      ADMIN_REQUEST_INVALID: '请求参数或格式不合法',
        DOCUMENT_FORMAT_UNSUPPORTED: '不支持此格式，请使用页面列出的文件类型；旧版 DOC 请先转换为 DOCX',
        DOCUMENT_INVALID: '文件损坏、内容格式不符或不是有效 UTF-8 文本',
        DOCUMENT_NO_TEXT: '文件中没有可读取文本；扫描件请先进行 OCR',
        DOCUMENT_ENCRYPTED: '暂不支持加密文件，请先在本地解密',
        DOCUMENT_UNSUPPORTED_CONTENT: '文件包含图片、嵌入对象或其他无法完整解析的内容，请先整理为纯文本文件',
        DOCUMENT_LIMIT_EXCEEDED: '文件或解析内容超出限制（文件最大 10 MiB，文本最多 20 万字符）',
        DOCUMENT_SECRET_DETECTED: '检测到高敏秘密，文件处理已阻断',
        DOCUMENT_RESERVED_TOKEN: '文件包含保留的脱敏占位符，请使用原始文件',
        DOCUMENT_TIMEOUT: '文件解析或检测超时，请缩小文件后重试',
        DOCUMENT_BUSY: '已有文件正在处理，请稍后重试',
        DOCUMENT_SCOPE_REJECTED: '当前管理员的处理范围与文件服务不一致',
        DOCUMENT_DETECTION_UNAVAILABLE: '必需检测器或版本校验失败，未生成脱敏文件',
        DOCUMENT_SERVICE_UNAVAILABLE: '文件脱敏服务暂不可用，请检查本地运行配置',
        REQUEST_TOO_LARGE: '文件超出上传限制',
      KNOWLEDGE_SCHEMA_INCOMPATIBLE: '知识库数据库结构不匹配或未初始化',
      KNOWLEDGE_SOURCE_NOT_FOUND: '知识来源不存在',
      KNOWLEDGE_SOURCE_WITHDRAWN: '知识来源已被撤回',
      KNOWLEDGE_SOURCE_EXPIRED: '知识来源有效期已过',
      KNOWLEDGE_GOVERNANCE_VERSION_CONFLICT: '治理版本冲突，数据已被并发修改',
      KNOWLEDGE_GOVERNANCE_VERSION_INVALID: '治理版本不符合预期',
      KNOWLEDGE_CANDIDATE_NOT_FOUND: '知识候选不存在',
      KNOWLEDGE_CANDIDATE_VERSION_CONFLICT: '候选版本冲突',
      KNOWLEDGE_PUBLICATION_NOT_FOUND: '发布资产不存在',
      KNOWLEDGE_PUBLICATION_AUDIENCE_DENIED: '受众未被授权使用该资产',
      KNOWLEDGE_PUBLICATION_PURPOSE_DENIED: '用途未被授权使用该资产',
      KNOWLEDGE_PUBLISH_REJECTED: '知识发布被拒绝（未满足发布合规条件）',
      KNOWLEDGE_VALIDITY_EXCEEDS_SOURCE: '发布有效期超过了来源有效期限',
      KNOWLEDGE_ADMIN_UNAVAILABLE: '知识治理服务或数据库连接暂不可用',
      AUDIT_RECORD_NOT_FOUND: '审计记录不存在',
      AUDIT_RECORD_UNAVAILABLE: '审计记录已过期或当前不可调阅',
      AUDIT_EVIDENCE_CORRUPTED: '审计留证校验失败（指纹或密文异常）',
      AUDIT_ACCESS_REJECTED: '审计调阅被拒绝（未满足权限或预算超时）',
      AUDIT_WRITE_FAILED: '审计安全写入失败',
      ADMIN_AUDIT_UNAVAILABLE: '审计调阅服务暂不可用',
      BAD_GATEWAY: '后端服务不可用',
      GATEWAY_TIMEOUT: '后端服务响应超时',
      INVALID_RESPONSE: '后端未返回有效 JSON',
    };
    return errorMap[error.code] ?? `操作失败（${error.code}）`;
  }
  return '连接失败，请检查后端服务';
}
