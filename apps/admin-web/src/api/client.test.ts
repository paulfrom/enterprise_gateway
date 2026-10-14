import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, clearSession, setSession, type Session } from './client';
afterEach(() => { clearSession(); vi.unstubAllGlobals(); });
describe('session boundary', () => {
  it('sends file bytes with CSRF and no filename, and refuses a late file result after logout', async () => {
    setSession({ csrf_token: 'synthetic-csrf' } as Session);
    let resolve!: (response: Response) => void;
    const fetch = vi.fn((_path: string, _options: RequestInit) => new Promise<Response>(done => { resolve = done; }));
    vi.stubGlobal('fetch', fetch);
    const file = new File(['synthetic-sensitive-data'], 'private-name.txt');
    const pending = api.redactDocument(file, 'txt');
    expect(fetch.mock.calls[0][0]).toBe('/api/admin/documents/redact?format=txt');
    expect(fetch.mock.calls[0][1].body).toBe(file);
    expect(fetch.mock.calls[0][1].headers).toMatchObject({
      'Content-Type': 'application/octet-stream', 'X-Admin-CSRF': 'synthetic-csrf',
    });
    clearSession();
    resolve(new Response(JSON.stringify({ redacted_text: 'late-result' })));
    await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
  });
  it('rejects a response that arrives after the session is cleared', async () => {
    let resolve!: (response: Response) => void;
    vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>(done => { resolve = done; })));
    const pending = api.history({});
    clearSession();
    resolve(new Response(JSON.stringify({ items: [{ request_id: 'late-secret' }], next_cursor: null })));
    await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
  });
});
