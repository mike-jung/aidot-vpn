// AidotVpn console — Vite build configuration.
//
// We do NOT use TypeScript per project policy. Plain JS + Vue SFC (`<script
// setup>`) is the supported style. ESLint enforces the no-TS rule via its
// `*.ts` glob being absent from the lint script.
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import path from 'node:path'

import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

// The project's VERSION, baked in. 노드 compares it with what each
// gateway agent reports, so a container left on an old image shows up
// as a mismatch rather than as a fix that has no effect.
const APP_VERSION = readFileSync(resolve(__dirname, '../VERSION'), 'utf8').trim()

export default defineConfig({
  define: { __APP_VERSION__: JSON.stringify(APP_VERSION) },
  plugins: [vue()],
  resolve: {
    alias: {
      '@': path.resolve(import.meta.dirname, './src'),
    },
  },
  server: {
    // File watching.
    //
    // Vite watches with inotify, which does not fire for files on a
    // Windows drive seen through WSL2, on a network share, or in some
    // container mounts. When it does not fire, the dev server keeps
    // serving the module it read at startup — so an edit lands on disk,
    // the page looks unchanged, and nothing reports an error. That is
    // exactly the shape of "I overwrote the files and the console did
    // not change".
    //
    // Polling is slower and always works. AIDOT_POLL=1 turns it on;
    // it is not the default because on a native filesystem inotify is
    // both instant and free.
    watch: process.env.AIDOT_POLL === '1'
      ? { usePolling: true, interval: 300 }
      : undefined,

    port: 6203,
    // Dev-only: proxy controller calls so we don't deal with CORS during
    // SPA development. In production server.js handles this.
    //
    // Why the rewrite: the controller mounts its REST routes at the
    // bare paths (/devices, /policies, /audit). The SPA addresses them
    // with the /api prefix purely so this proxy + the prod Express
    // server can intercept them. Without `rewrite` Vite would forward
    // /api/devices to the controller verbatim — and the controller has
    // no /api/devices route, so every API call would 404.
    proxy: {
      '/api': {
        // The controller's port from .env, so moving it moves this too.
        // start.mjs passes it through as an environment variable; a
        // bare `vite` run outside npm start falls back to the default.
        target: `http://localhost:${(process.env.CONTROLLER_HTTP_LISTEN || '10030').replace(/^.*:/, '')}`,
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api/, ''),
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    rollupOptions: {
      output: {
        // Split vendor + app for better caching.
        manualChunks: {
          vue: ['vue', 'vue-router'],
          bootstrap: ['bootstrap'],
        },
      },
    },
  },
})
