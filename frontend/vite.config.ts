import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The adapter runs on :8000 (see soc_copilot/api/app.py); proxying keeps the
// browser on one origin, so no CORS and no URL baked into the bundle.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { '/api': { target: 'http://127.0.0.1:8000', rewrite: (p) => p.replace(/^\/api/, '') } },
  },
});
