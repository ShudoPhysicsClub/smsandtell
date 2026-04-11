import React, { useState } from 'react'
import {
  deriveKeyFromPassword,
  getPublicKey,
  buildSignMessage,
  schnorrSign,
  bigIntToHex32,
} from '../ecdsa'
import { getChallenge, verifySignature } from '../api'
import { NodeConnection } from '../websocket'

// ログイン成功時に呼ばれるコールバックの型
interface LoginProps {
  onLogin: (phone: string, token: string, nodes: string[], privKey: bigint, conn: NodeConnection) => void
}

// ログイン画面コンポーネント
const Login: React.FC<LoginProps> = ({ onLogin }) => {
  // 電話番号の入力状態
  const [phone, setPhone] = useState('')
  // パスワードの入力状態（鍵導出に使用）
  const [password, setPassword] = useState('')
  // 認証処理中フラグ
  const [loading, setLoading] = useState(false)
  // エラーメッセージ
  const [error, setError] = useState('')

  // ログインボタン押下時の認証フロー
  const handleLogin = async () => {
    if (!phone || !password) {
      setError('電話番号とパスワードを入力してください')
      return
    }

    setLoading(true)
    setError('')

    try {
      // ステップ1: PBKDF2でパスワードから秘密鍵を生成
      const privKey = await deriveKeyFromPassword(password, phone)

      // ステップ2: 秘密鍵から公開鍵を生成
      const pubKey = getPublicKey(privKey)

      // ステップ3: サーバーからチャレンジを取得
      const challengeResp = await getChallenge(phone)

      // ステップ4: 署名対象メッセージを組み立てる
      // タイムスタンプは有効期限からTTL(300秒)を引いた発行時刻
      const issuedAt = challengeResp.expires - 300
      const message = buildSignMessage(challengeResp.challenge, issuedAt, phone)

      // ステップ5: Schnorr署名を生成
      const sig = await schnorrSign(privKey, message)

      // ステップ6: 署名を検証してセッショントークンを取得
      const verifyResp = await verifySignature(
        phone,
        { x: bigIntToHex32(pubKey.x), y: bigIntToHex32(pubKey.y) },
        sig,
        challengeResp.challenge
      )

      // ステップ7: ノードにWebSocket接続
      const conn = new NodeConnection()
      if (verifyResp.nodes.length > 0) {
        // 最初のノードに接続（実際は複数ノードへの接続も可）
        const nodeUrl = `http://${verifyResp.nodes[0]}`
        conn.connect(nodeUrl, phone, verifyResp.token, [])
      }

      // 認証成功時の処理
      onLogin(phone, verifyResp.token, verifyResp.nodes, privKey, conn)
    } catch (err) {
      setError(err instanceof Error ? err.message : '認証に失敗しました')
    } finally {
      setLoading(false)
    }
  }

  // Enterキーでもログインできるようにする
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') void handleLogin()
  }

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <h1 style={styles.title}>SMSandTell</h1>
        <p style={styles.subtitle}>tell.com 分散通信ネットワーク</p>

        <div style={styles.form}>
          <label style={styles.label}>電話番号</label>
          <input
            type="tel"
            placeholder="例: 02-12345678"
            value={phone}
            onChange={(e) => setPhone(e.target.value)}
            onKeyDown={handleKeyDown}
            style={styles.input}
            disabled={loading}
          />

          <label style={styles.label}>パスワード</label>
          <input
            type="password"
            placeholder="パスワードを入力"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onKeyDown={handleKeyDown}
            style={styles.input}
            disabled={loading}
          />

          {error && <p style={styles.error}>{error}</p>}

          <button
            onClick={() => void handleLogin()}
            disabled={loading}
            style={{ ...styles.button, ...(loading ? styles.buttonDisabled : {}) }}
          >
            {loading ? '認証中...' : 'ログイン'}
          </button>
        </div>
      </div>
    </div>
  )
}

// スタイル定義
const styles: Record<string, React.CSSProperties> = {
  container: {
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    minHeight: '100vh',
    backgroundColor: '#f0f2f5',
  },
  card: {
    backgroundColor: '#fff',
    borderRadius: '8px',
    padding: '40px',
    width: '360px',
    boxShadow: '0 2px 8px rgba(0,0,0,0.15)',
  },
  title: {
    textAlign: 'center',
    fontSize: '28px',
    fontWeight: 'bold',
    color: '#1a1a2e',
    margin: '0 0 8px',
  },
  subtitle: {
    textAlign: 'center',
    color: '#666',
    fontSize: '14px',
    marginBottom: '32px',
  },
  form: {
    display: 'flex',
    flexDirection: 'column',
    gap: '12px',
  },
  label: {
    fontSize: '14px',
    fontWeight: '600',
    color: '#333',
    marginBottom: '-8px',
  },
  input: {
    padding: '10px 12px',
    border: '1px solid #ccc',
    borderRadius: '4px',
    fontSize: '16px',
    outline: 'none',
  },
  button: {
    marginTop: '8px',
    padding: '12px',
    backgroundColor: '#1a1a2e',
    color: '#fff',
    border: 'none',
    borderRadius: '4px',
    fontSize: '16px',
    cursor: 'pointer',
  },
  buttonDisabled: {
    backgroundColor: '#aaa',
    cursor: 'not-allowed',
  },
  error: {
    color: '#e00',
    fontSize: '14px',
    margin: '0',
  },
}

export default Login
