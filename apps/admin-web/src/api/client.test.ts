import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, clearSession } from './client';
afterEach(() => { clearSession(); vi.unstubAllGlobals(); });
describe('session boundary', () => {
  it('rejects a response that arrives after the session is cleared', async () => {
    let resolve!: (response: Response) => void;
    vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>(done => { resolve = done; })));
    const pending = api.history({});
    clearSession();
    resolve(new Response(JSON.stringify({ items: [{ request_id: 'late-secret' }], next_cursor: null })));
    await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
  });
});
