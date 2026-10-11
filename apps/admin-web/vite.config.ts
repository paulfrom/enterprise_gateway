import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 3000,
    proxy: {
      '/api/admin': {
        target: process.env.GATEWAY_ADMIN_PROXY_TARGET ?? 'http://127.0.0.1:8080',
        changeOrigin: false,
      },
      '/v1': {
        target: process.env.GATEWAY_ADMIN_PROXY_TARGET ?? 'http://127.0.0.1:8080',
        changeOrigin: false,
      },
    },
  },
  test: {
    include: ['src/**/*.test.{ts,tsx}'],
    globals: true,
    environment: 'jsdom',
    setupFiles: './src/test/setup.ts',
    css: false,
  },
});
