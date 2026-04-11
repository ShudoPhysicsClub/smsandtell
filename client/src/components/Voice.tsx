import React, { useState, useEffect, useRef } from 'react'
import { sendIceOffer } from '../api'
import { NodeConnection } from '../websocket'

// 音声通話画面のProps型定義
interface VoiceProps {
  phone: string
  token: string
  conn: NodeConnection
}

// 通話状態の型定義
type CallState = 'idle' | 'calling' | 'incoming' | 'connected'

// WebRTC音声通話UIコンポーネント
const Voice: React.FC<VoiceProps> = ({ phone, token, conn }) => {
  // 発信先電話番号
  const [callTo, setCallTo] = useState('')
  // 通話状態
  const [callState, setCallState] = useState<CallState>('idle')
  // 着信元電話番号
  const [incomingFrom, setIncomingFrom] = useState('')
  // 現在の通話ID
  const [currentCallId, setCurrentCallId] = useState('')
  // エラーメッセージ
  const [error, setError] = useState('')

  // WebRTCのピア接続への参照
  const pcRef = useRef<RTCPeerConnection | null>(null)
  // 収集したICE候補リスト
  const iceCandidatesRef = useRef<string[]>([])
  // 着信時のICE offer情報
  const incomingOfferRef = useRef<{ sdp: string; candidates: string[] } | null>(null)
  // リモート音声出力用のaudio要素への参照
  const remoteAudioRef = useRef<HTMLAudioElement | null>(null)

  // STUNサーバー設定
  const RTC_CONFIG: RTCConfiguration = {
    iceServers: [{ urls: 'stun:stun.l.google.com:19302' }],
  }

  useEffect(() => {
    // 着信コールバックを登録
    conn.onIceOffer((from, callId, sdpOffer, candidates) => {
      console.log(`[Voice] 着信: from=${from} callId=${callId}`)
      setIncomingFrom(from)
      setCurrentCallId(callId)
      incomingOfferRef.current = { sdp: sdpOffer, candidates }
      setCallState('incoming')
    })

    // ICE answer受信コールバックを登録（発信側）
    conn.onIceAnswer((callId, sdpAnswer, candidates) => {
      if (callId !== currentCallId) return
      void handleRemoteAnswer(sdpAnswer, candidates)
    })
  }, [conn, currentCallId]) // eslint-disable-line react-hooks/exhaustive-deps

  // RTCPeerConnectionを初期化する
  const createPeerConnection = (): RTCPeerConnection => {
    const pc = new RTCPeerConnection(RTC_CONFIG)
    iceCandidatesRef.current = []

    // ICE候補収集コールバック
    pc.onicecandidate = (event) => {
      if (event.candidate) {
        iceCandidatesRef.current.push(JSON.stringify(event.candidate))
      }
    }

    // リモートトラック受信コールバック（音声を再生）
    pc.ontrack = (event) => {
      if (!remoteAudioRef.current) {
        remoteAudioRef.current = new Audio()
        remoteAudioRef.current.autoplay = true
      }
      const stream = event.streams[0]
      if (stream) {
        remoteAudioRef.current.srcObject = stream
      }
    }

    return pc
  }

  // 発信処理
  const handleCall = async () => {
    if (!callTo) {
      setError('発信先電話番号を入力してください')
      return
    }

    setError('')
    setCallState('calling')

    try {
      const pc = createPeerConnection()
      pcRef.current = pc

      // マイクのオーディオストリームを取得
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true })
      stream.getTracks().forEach((track) => pc.addTrack(track, stream))

      // SDPオファーを作成
      const offer = await pc.createOffer()
      await pc.setLocalDescription(offer)

      // ICE候補の収集が完了するまで待機（最大2秒）
      await waitForIceCandidates(pc)

      // ゲートウェイ経由でICE offerを送信
      const resp = await sendIceOffer(
        token, phone, callTo,
        offer.sdp ?? '',
        iceCandidatesRef.current
      )
      setCurrentCallId(resp.call_id)
      console.log(`[Voice] 発信完了: callId=${resp.call_id}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : '発信に失敗しました')
      setCallState('idle')
      cleanupPeerConnection()
    }
  }

  // 着信応答処理
  const handleAnswer = async () => {
    const offerInfo = incomingOfferRef.current
    if (!offerInfo) return

    setError('')

    try {
      const pc = createPeerConnection()
      pcRef.current = pc

      // マイクのオーディオストリームを取得
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true })
      stream.getTracks().forEach((track) => pc.addTrack(track, stream))

      // リモートのSDPオファーを設定
      await pc.setRemoteDescription(new RTCSessionDescription({
        type: 'offer',
        sdp: offerInfo.sdp,
      }))

      // 発信側のICE候補を追加
      for (const candidateStr of offerInfo.candidates) {
        try {
          const candidate = JSON.parse(candidateStr) as RTCIceCandidateInit
          await pc.addIceCandidate(new RTCIceCandidate(candidate))
        } catch {
          console.warn('[Voice] ICE候補の追加失敗:', candidateStr)
        }
      }

      // SDPアンサーを作成
      const answer = await pc.createAnswer()
      await pc.setLocalDescription(answer)

      // ICE候補の収集が完了するまで待機
      await waitForIceCandidates(pc)

      // ICE answerをWebSocket経由で送信
      conn.sendIceAnswer(currentCallId, answer.sdp ?? '', iceCandidatesRef.current)
      setCallState('connected')
      console.log(`[Voice] 応答完了: callId=${currentCallId}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : '応答に失敗しました')
      setCallState('idle')
      cleanupPeerConnection()
    }
  }

  // 着信拒否処理
  const handleReject = () => {
    incomingOfferRef.current = null
    setCallState('idle')
    setIncomingFrom('')
  }

  // リモートからのICE answerを受信して接続を完了する（発信側）
  const handleRemoteAnswer = async (sdpAnswer: string, candidates: string[]) => {
    const pc = pcRef.current
    if (!pc) return

    try {
      await pc.setRemoteDescription(new RTCSessionDescription({
        type: 'answer',
        sdp: sdpAnswer,
      }))

      // 着信側のICE候補を追加
      for (const candidateStr of candidates) {
        try {
          const candidate = JSON.parse(candidateStr) as RTCIceCandidateInit
          await pc.addIceCandidate(new RTCIceCandidate(candidate))
        } catch {
          console.warn('[Voice] ICE候補の追加失敗:', candidateStr)
        }
      }

      setCallState('connected')
      console.log('[Voice] P2P接続確立')
    } catch (err) {
      console.error('[Voice] アンサー処理失敗:', err)
      setError('通話接続に失敗しました')
      setCallState('idle')
      cleanupPeerConnection()
    }
  }

  // 通話終了処理
  const handleHangup = () => {
    cleanupPeerConnection()
    setCallState('idle')
    setCallTo('')
    setCurrentCallId('')
  }

  // ピア接続をクリーンアップ
  const cleanupPeerConnection = () => {
    if (pcRef.current) {
      pcRef.current.close()
      pcRef.current = null
    }
    if (remoteAudioRef.current) {
      remoteAudioRef.current.srcObject = null
    }
    iceCandidatesRef.current = []
  }

  // ICE候補収集完了まで待機（icegatheringstateがcompleteになるまで最大2秒）
  const waitForIceCandidates = (pc: RTCPeerConnection): Promise<void> => {
    return new Promise((resolve) => {
      if (pc.iceGatheringState === 'complete') {
        resolve()
        return
      }
      const timeout = setTimeout(resolve, 2000)
      pc.addEventListener('icegatheringstatechange', () => {
        if (pc.iceGatheringState === 'complete') {
          clearTimeout(timeout)
          resolve()
        }
      })
    })
  }

  return (
    <div style={styles.container}>
      <h2 style={styles.heading}>音声通話</h2>

      {/* 待機中の発信フォーム */}
      {callState === 'idle' && (
        <div style={styles.form}>
          <label style={styles.label}>発信先電話番号</label>
          <input
            type="tel"
            placeholder="例: 02-87654321"
            value={callTo}
            onChange={(e) => setCallTo(e.target.value)}
            style={styles.input}
          />
          {error && <p style={styles.error}>{error}</p>}
          <button onClick={() => void handleCall()} style={styles.callButton}>
            📞 発信
          </button>
        </div>
      )}

      {/* 発信中の表示 */}
      {callState === 'calling' && (
        <div style={styles.statusBox}>
          <p style={styles.statusText}>📡 {callTo} に発信中...</p>
          <button onClick={handleHangup} style={styles.hangupButton}>
            📵 キャンセル
          </button>
        </div>
      )}

      {/* 着信通知の表示 */}
      {callState === 'incoming' && (
        <div style={styles.incomingBox}>
          <p style={styles.incomingText}>📲 {incomingFrom} から着信中</p>
          <div style={styles.buttonRow}>
            <button onClick={() => void handleAnswer()} style={styles.answerButton}>
              📞 応答
            </button>
            <button onClick={handleReject} style={styles.hangupButton}>
              📵 拒否
            </button>
          </div>
          {error && <p style={styles.error}>{error}</p>}
        </div>
      )}

      {/* 通話中の表示 */}
      {callState === 'connected' && (
        <div style={styles.statusBox}>
          <p style={styles.statusText}>
            🔊 通話中: {callTo || incomingFrom}
          </p>
          <p style={styles.callId}>通話ID: {currentCallId}</p>
          <button onClick={handleHangup} style={styles.hangupButton}>
            📵 終了
          </button>
        </div>
      )}
    </div>
  )
}

// スタイル定義
const styles: Record<string, React.CSSProperties> = {
  container: {
    padding: '24px',
    maxWidth: '480px',
    margin: '0 auto',
  },
  heading: {
    fontSize: '20px',
    fontWeight: 'bold',
    marginBottom: '24px',
    color: '#1a1a2e',
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
  },
  input: {
    padding: '10px 12px',
    border: '1px solid #ccc',
    borderRadius: '4px',
    fontSize: '16px',
  },
  callButton: {
    padding: '12px',
    backgroundColor: '#27ae60',
    color: '#fff',
    border: 'none',
    borderRadius: '4px',
    fontSize: '16px',
    cursor: 'pointer',
  },
  hangupButton: {
    padding: '12px',
    backgroundColor: '#e74c3c',
    color: '#fff',
    border: 'none',
    borderRadius: '4px',
    fontSize: '16px',
    cursor: 'pointer',
  },
  answerButton: {
    padding: '12px',
    backgroundColor: '#27ae60',
    color: '#fff',
    border: 'none',
    borderRadius: '4px',
    fontSize: '16px',
    cursor: 'pointer',
    flex: 1,
  },
  statusBox: {
    backgroundColor: '#f0f8ff',
    border: '1px solid #bee3f8',
    borderRadius: '8px',
    padding: '24px',
    textAlign: 'center',
    display: 'flex',
    flexDirection: 'column',
    gap: '16px',
    alignItems: 'center',
  },
  incomingBox: {
    backgroundColor: '#fff9f0',
    border: '1px solid #fde8c8',
    borderRadius: '8px',
    padding: '24px',
    textAlign: 'center',
    display: 'flex',
    flexDirection: 'column',
    gap: '16px',
    alignItems: 'center',
  },
  statusText: {
    fontSize: '18px',
    fontWeight: '600',
    margin: 0,
    color: '#1a1a2e',
  },
  incomingText: {
    fontSize: '18px',
    fontWeight: '600',
    margin: 0,
    color: '#e67e22',
  },
  callId: {
    fontSize: '12px',
    color: '#999',
    margin: 0,
    wordBreak: 'break-all',
  },
  buttonRow: {
    display: 'flex',
    gap: '12px',
    width: '100%',
  },
  error: {
    color: '#e00',
    fontSize: '13px',
    margin: 0,
  },
}

export default Voice
