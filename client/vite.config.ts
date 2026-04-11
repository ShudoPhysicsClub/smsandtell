import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Viteの設定ファイル
// ゲートウェイへのAPIリクエストをプロキシする
export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      // ゲートウェイAPIへのプロキシ設定
      '/auth': 'http://localhost:1919',
      '/sms': 'http://localhost:1919',
      '/ice': 'http://localhost:1919',
    },
  },
})
