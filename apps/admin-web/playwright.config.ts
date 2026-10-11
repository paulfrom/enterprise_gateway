import { defineConfig } from '@playwright/test';
import path from 'node:path';
import { existsSync } from 'node:fs';
const root = path.resolve(import.meta.dirname, '../..');
const backend = path.join(root, 'apps/backend');
const pg = process.env.GATEWAY_HISTORY_PG_CONFIG;
const external = process.env.GATEWAY_BROWSER_BASE_URL;
const backendPort = Number(process.env.GATEWAY_E2E_BACKEND_PORT ?? 18876);
const frontendPort = Number(process.env.GATEWAY_E2E_FRONTEND_PORT ?? 14174);
if (!pg) throw new Error('GATEWAY_HISTORY_PG_CONFIG must identify a private local PG 5433 test configuration');
export default defineConfig({
  testDir: './e2e', workers: 1, timeout: 45000,
  outputDir: process.env.PLAYWRIGHT_OUTPUT_DIR ?? '/tmp/enterprise-gateway-browser-results',
  use: { baseURL: external ?? `http://127.0.0.1:${frontendPort}`, headless: true,
    launchOptions: { executablePath: process.env.CHROME_PATH ?? (existsSync('/opt/google/chrome/chrome') ? '/opt/google/chrome/chrome' : undefined) } },
  webServer: [
    { command: '"' + path.join(backend, '.venv/bin/python') + '" scripts/serve_history_preview.py --pg-config "' + pg + '" --port ' + backendPort,
      cwd: backend, url: `http://127.0.0.1:${backendPort}/healthz`, timeout: 180000,
      gracefulShutdown: { signal: 'SIGTERM', timeout: 15000 }, reuseExistingServer: process.env.GATEWAY_E2E_REUSE_BACKEND === '1', stdout: 'pipe' },
    ...(external ? [] : [{ command: `npm run dev -- --host 127.0.0.1 --port ${frontendPort} --strictPort`,
      url: `http://127.0.0.1:${frontendPort}`, timeout: 30000,
      env: { GATEWAY_ADMIN_PROXY_TARGET: `http://127.0.0.1:${backendPort}` }, reuseExistingServer: false }]),
  ],
});
