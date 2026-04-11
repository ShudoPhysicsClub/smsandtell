import React, { useState } from 'react'
import Login from './components/Login'
import SMS from './components/SMS'
import Voice from './components/Voice'
import { NodeConnection } from './websocket'

// アクティブなタブの型
type Tab = 'sms' | 'voice'

// アプリケーションのルートコンポーネント
const App: React.FC = () => {
  // 認証状態
  const [authenticated, setAuthenticated] = useState(false)
  // ログイン中の電話番号
  const [phone, setPhone] = useState('')
  // セッショントークン
  const [token, setToken] = useState('')
  // 接続可能なノードリスト
  const [nodes, setNodes] = useState<string[]>([])
  // 秘密鍵（BigInt）
  const [privateKey, setPrivateKey] = useState<bigint | null>(null)
  // ノードのWebSocket接続
  const [nodeConn, setNodeConn] = useState<NodeConnection | null>(null)
  // 現在表示中のタブ
  const [activeTab, setActiveTab] = useState<Tab>('sms')

  // ログイン成功時のコールバック
  const handleLogin = (
    loginPhone: string,
    loginToken: string,
    loginNodes: string[],
    privKey: bigint,
    conn: NodeConnection
  ) => {
    setPhone(loginPhone)
    setToken(loginToken)
    setNodes(loginNodes)
    setPrivateKey(privKey)
    setNodeConn(conn)
    setAuthenticated(true)
  }

  // ログアウト処理
  const handleLogout = () => {
    nodeConn?.disconnect()
    setAuthenticated(false)
    setPhone('')
    setToken('')
    setNodes([])
    setPrivateKey(null)
    setNodeConn(null)
  }

  // 未認証時はログイン画面を表示
  if (!authenticated || !nodeConn) {
    return <Login onLogin={handleLogin} />
  }

  return (
    <div style={styles.appContainer}>
      {/* ヘッダーバー */}
      <header style={styles.header}>
        <span style={styles.headerTitle}>SMSandTell</span>
        <div style={styles.headerRight}>
          <span style={styles.phoneLabel}>{phone}</span>
          {nodes.length > 0 && (
            <span style={styles.nodeLabel}>ノード: {nodes.length}件</span>
          )}
          {/* privateKeyは署名時に使用済み（表示不要） */}
          {privateKey !== null && null}
          <button onClick={handleLogout} style={styles.logoutButton}>
            ログアウト
          </button>
        </div>
      </header>

      {/* タブナビゲーション */}
      <nav style={styles.tabs}>
        <button
          onClick={() => setActiveTab('sms')}
          style={{ ...styles.tab, ...(activeTab === 'sms' ? styles.tabActive : {}) }}
        >
          💬 SMS
        </button>
        <button
          onClick={() => setActiveTab('voice')}
          style={{ ...styles.tab, ...(activeTab === 'voice' ? styles.tabActive : {}) }}
        >
          📞 音声通話
        </button>
      </nav>

      {/* タブコンテンツ */}
      <main style={styles.main}>
        {activeTab === 'sms' && (
          <SMS phone={phone} token={token} conn={nodeConn} />
        )}
        {activeTab === 'voice' && (
          <Voice phone={phone} token={token} conn={nodeConn} />
        )}
      </main>
    </div>
  )
}

// スタイル定義
const styles: Record<string, React.CSSProperties> = {
  appContainer: {
    display: 'flex',
    flexDirection: 'column',
    height: '100vh',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '0 20px',
    height: '56px',
    backgroundColor: '#1a1a2e',
    color: '#fff',
    flexShrink: 0,
  },
  headerTitle: {
    fontSize: '18px',
    fontWeight: 'bold',
  },
  headerRight: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
  },
  phoneLabel: {
    fontSize: '14px',
    color: '#ccc',
  },
  nodeLabel: {
    fontSize: '12px',
    color: '#aaa',
    backgroundColor: '#333',
    padding: '2px 8px',
    borderRadius: '12px',
  },
  logoutButton: {
    padding: '6px 14px',
    backgroundColor: 'transparent',
    color: '#fff',
    border: '1px solid #555',
    borderRadius: '4px',
    fontSize: '13px',
    cursor: 'pointer',
  },
  tabs: {
    display: 'flex',
    borderBottom: '1px solid #e0e0e0',
    backgroundColor: '#fff',
    flexShrink: 0,
  },
  tab: {
    padding: '12px 24px',
    border: 'none',
    backgroundColor: 'transparent',
    fontSize: '15px',
    cursor: 'pointer',
    color: '#666',
    borderBottom: '2px solid transparent',
  },
  tabActive: {
    color: '#1a1a2e',
    borderBottom: '2px solid #1a1a2e',
    fontWeight: '600',
  },
  main: {
    flex: 1,
    overflow: 'hidden',
    display: 'flex',
    flexDirection: 'column',
  },
}

export default App
