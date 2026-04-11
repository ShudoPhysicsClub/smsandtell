import React, { useState, useEffect, useRef } from 'react'
import { sendSMS } from '../api'
import { NodeConnection } from '../websocket'

// SMS画面のProps型定義
interface SMSProps {
  phone: string
  token: string
  conn: NodeConnection
}

// 受信メッセージの型定義
interface Message {
  id: number
  from: string
  body: string
  timestamp: Date
  direction: 'incoming' | 'outgoing'
  to?: string
}

// SMS送受信UIコンポーネント
const SMS: React.FC<SMSProps> = ({ phone, token, conn }) => {
  // 受信・送信メッセージの一覧
  const [messages, setMessages] = useState<Message[]>([])
  // 送信先電話番号
  const [to, setTo] = useState('')
  // メッセージ本文
  const [body, setBody] = useState('')
  // 送信処理中フラグ
  const [sending, setSending] = useState(false)
  // エラーメッセージ
  const [error, setError] = useState('')
  // メッセージ一覧の末尾への参照（自動スクロール用）
  const bottomRef = useRef<HTMLDivElement>(null)
  // メッセージIDカウンター
  const idCounterRef = useRef(0)

  useEffect(() => {
    // WebSocketでSMSを受信するコールバックを登録
    conn.onSMS((from, msgBody) => {
      setMessages((prev) => [
        ...prev,
        {
          id: ++idCounterRef.current,
          from,
          body: msgBody,
          timestamp: new Date(),
          direction: 'incoming',
        },
      ])
    })
  }, [conn])

  useEffect(() => {
    // 新着メッセージ時に自動スクロール
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  // SMS送信処理
  const handleSend = async () => {
    if (!to || !body) {
      setError('宛先と本文を入力してください')
      return
    }

    setSending(true)
    setError('')

    try {
      await sendSMS(token, phone, to, body)
      // 送信済みメッセージを一覧に追加
      setMessages((prev) => [
        ...prev,
        {
          id: ++idCounterRef.current,
          from: phone,
          to,
          body,
          timestamp: new Date(),
          direction: 'outgoing',
        },
      ])
      setBody('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'SMS送信に失敗しました')
    } finally {
      setSending(false)
    }
  }

  // Enterキー（Shift+Enterで改行）で送信
  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      void handleSend()
    }
  }

  // タイムスタンプをHH:MM形式にフォーマット
  const formatTime = (date: Date) =>
    date.toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' })

  return (
    <div style={styles.container}>
      {/* メッセージ一覧エリア */}
      <div style={styles.messageList}>
        {messages.length === 0 && (
          <p style={styles.empty}>メッセージはまだありません</p>
        )}
        {messages.map((msg) => (
          <div
            key={msg.id}
            style={{
              ...styles.messageBubble,
              ...(msg.direction === 'outgoing' ? styles.outgoing : styles.incoming),
            }}
          >
            <div style={styles.messageHeader}>
              <span style={styles.messageFrom}>
                {msg.direction === 'incoming' ? msg.from : `→ ${msg.to ?? ''}`}
              </span>
              <span style={styles.messageTime}>{formatTime(msg.timestamp)}</span>
            </div>
            <p style={styles.messageBody}>{msg.body}</p>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>

      {/* 送信フォームエリア */}
      <div style={styles.sendForm}>
        <input
          type="tel"
          placeholder="宛先電話番号"
          value={to}
          onChange={(e) => setTo(e.target.value)}
          style={styles.input}
          disabled={sending}
        />
        <textarea
          placeholder="メッセージを入力（Enterで送信、Shift+Enterで改行）"
          value={body}
          onChange={(e) => setBody(e.target.value)}
          onKeyDown={handleKeyDown}
          rows={3}
          style={styles.textarea}
          disabled={sending}
        />
        {error && <p style={styles.error}>{error}</p>}
        <button
          onClick={() => void handleSend()}
          disabled={sending}
          style={{ ...styles.button, ...(sending ? styles.buttonDisabled : {}) }}
        >
          {sending ? '送信中...' : '送信'}
        </button>
      </div>
    </div>
  )
}

// スタイル定義
const styles: Record<string, React.CSSProperties> = {
  container: {
    display: 'flex',
    flexDirection: 'column',
    height: '100%',
  },
  messageList: {
    flex: 1,
    overflowY: 'auto',
    padding: '16px',
    backgroundColor: '#f9f9f9',
  },
  empty: {
    textAlign: 'center',
    color: '#aaa',
    marginTop: '40px',
  },
  messageBubble: {
    maxWidth: '70%',
    marginBottom: '12px',
    padding: '10px 14px',
    borderRadius: '8px',
  },
  incoming: {
    backgroundColor: '#fff',
    border: '1px solid #e0e0e0',
    alignSelf: 'flex-start',
    marginRight: 'auto',
  },
  outgoing: {
    backgroundColor: '#1a1a2e',
    color: '#fff',
    alignSelf: 'flex-end',
    marginLeft: 'auto',
  },
  messageHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    marginBottom: '4px',
    gap: '12px',
  },
  messageFrom: {
    fontSize: '12px',
    fontWeight: '600',
    color: '#555',
  },
  messageTime: {
    fontSize: '11px',
    color: '#999',
  },
  messageBody: {
    margin: 0,
    fontSize: '15px',
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-word',
  },
  sendForm: {
    padding: '16px',
    borderTop: '1px solid #e0e0e0',
    backgroundColor: '#fff',
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
  },
  input: {
    padding: '8px 12px',
    border: '1px solid #ccc',
    borderRadius: '4px',
    fontSize: '15px',
  },
  textarea: {
    padding: '8px 12px',
    border: '1px solid #ccc',
    borderRadius: '4px',
    fontSize: '15px',
    resize: 'vertical',
  },
  button: {
    padding: '10px',
    backgroundColor: '#1a1a2e',
    color: '#fff',
    border: 'none',
    borderRadius: '4px',
    fontSize: '15px',
    cursor: 'pointer',
  },
  buttonDisabled: {
    backgroundColor: '#aaa',
    cursor: 'not-allowed',
  },
  error: {
    color: '#e00',
    fontSize: '13px',
    margin: 0,
  },
}

export default SMS
