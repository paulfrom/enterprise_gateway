import type { components, paths } from './schema';
export type Session = components['schemas']['AdminSession'];
export type HistoryPage = components['schemas']['HistoryPage'];
export type HistoryDetail = components['schemas']['HistoryDetail'];
export type HistoryFilters = NonNullable<paths['/api/admin/requests']['get']['parameters']['query']>;
export type Login = paths['/api/admin/login']['post']['requestBody']['content']['application/json'];
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
  for (const request of pending) request.abort();
  pending.clear();
}
async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const version = generation;
  const controller = new AbortController();
  const abort = () => controller.abort();
  options.signal?.addEventListener('abort', abort, { once: true });
  if (options.signal?.aborted) controller.abort();
  pending.add(controller);
  try {
    const response = await fetch(path, { ...options, signal: controller.signal, credentials: 'same-origin',
      headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}),
        ...(options.method === 'POST' && csrf ? { 'X-Admin-CSRF': csrf } : {}), ...options.headers } });
    const payload = await response.json().catch(() => null);
    if (version !== generation || controller.signal.aborted) throw new DOMException('Session changed', 'AbortError');
    if (!response.ok) {
      if (response.status === 401 && path !== '/api/admin/login') expired?.();
      throw new ApiError(response.status, payload?.error?.code ?? 'INVALID_RESPONSE');
    }
    if (payload === null) throw new ApiError(502, 'INVALID_RESPONSE');
    return payload as T;
  } finally { pending.delete(controller); options.signal?.removeEventListener('abort', abort); }
}
export const api = {
  session: (signal?: AbortSignal) => request<Session>('/api/admin/session', { signal }),
  login: (body: Login) => request<Session>('/api/admin/login', { method: 'POST', body: JSON.stringify(body) }),
  logout: () => request<components['schemas']['Revocation']>('/api/admin/logout', { method: 'POST' }),
  history: (filters: HistoryFilters, signal?: AbortSignal) => {
    const params = new URLSearchParams();
    Object.entries(filters).forEach(([key, value]) => { if (value !== undefined && value !== '') params.set(key, String(value)); });
    return request<HistoryPage>('/api/admin/requests?' + params, { signal });
  },
  detail: (id: string, signal?: AbortSignal) => request<HistoryDetail>('/api/admin/requests/' + encodeURIComponent(id), { signal }),
};
export function errorText(error: unknown): string {
  if (error instanceof ApiError) return ({
    ADMIN_LOGIN_FAILED: '用户名或密码错误', ADMIN_LOGIN_THROTTLED: '登录尝试过多，请稍后重试',
    ADMIN_SESSION_INVALID: '会话已过期，请重新登录', ADMIN_STORAGE_UNAVAILABLE: '管理员状态存储不可用',
    HISTORY_UNAVAILABLE: '请求历史暂不可用，请检查数据库与密钥配置',
    INVALID_HISTORY_QUERY: '筛选条件无效', HISTORY_NOT_FOUND: '记录不存在或已过期',
    ADMIN_ORIGIN_REJECTED: '登录来源校验失败', ADMIN_CSRF_INVALID: '会话校验失败，请刷新后重试',
    BAD_GATEWAY: '后端服务不可用', GATEWAY_TIMEOUT: '后端服务响应超时', INVALID_RESPONSE: '后端未返回有效 JSON',
  } as Record<string, string>)[error.code] ?? `请求失败（${error.code}）`;
  return '连接失败，请检查后端服务';
}
