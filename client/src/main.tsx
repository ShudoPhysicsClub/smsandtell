// アプリケーションのエントリーポイント
import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'

// グローバルスタイルをリセット
const style = document.createElement('style')
style.textContent = `
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
`
document.head.appendChild(style)

// Reactアプリをマウント
ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
)
