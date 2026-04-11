// WebSocket接続管理モジュール
// ノードとのリアルタイム通信を管理する

// ノードから受信するメッセージの基底型
interface BaseMessage {
  type: string
}

// SMS受信メッセージの型定義
interface SMSMessage extends BaseMessage {
  type: 'sms'
  from: string
  to: string
  body: string
}

// ICE offerメッセージの型定義（着信）
interface IceOfferMessage extends BaseMessage {
  type: 'ice_offer'
  from: string
  to: string
  call_id: string
  sdp_offer: string
  candidates: string[]
}

// ICE answerメッセージの型定義
interface IceAnswerMessage extends BaseMessage {
  type: 'ice_answer'
  call_id: string
  sdp_answer: string
  candidates: string[]
}

// SMS受信コールバックの型
type SMSCallback = (from: string, body: string) => void
// ICE offer受信コールバックの型（着信）
type IceOfferCallback = (from: string, callId: string, sdpOffer: string, candidates: string[]) => void
// ICE answer受信コールバックの型
type IceAnswerCallback = (callId: string, sdpAnswer: string, candidates: string[]) => void

// ノードへのWebSocket接続を管理するクラス
export class NodeConnection {
  private ws: WebSocket | null = null
  private smsCallback: SMSCallback | null = null
  private iceOfferCallback: IceOfferCallback | null = null
  private iceAnswerCallback: IceAnswerCallback | null = null

  // 指定したノードに接続する
  connect(nodeUrl: string, phone: string, token: string, iceCandidates: string[]): void {
    // 既存の接続があれば切断
    if (this.ws) this.disconnect()

    // WebSocket URLを構築（ws://またはwss://）
    const wsUrl = nodeUrl.replace(/^http/, 'ws') + '/connect'
    this.ws = new WebSocket(wsUrl)

    this.ws.onopen = () => {
      // 接続確立後に登録メッセージを送信
      const registerMsg = {
        type: 'register',
        phone,
        token,
        ice_cache: iceCandidates,
      }
      this.ws!.send(JSON.stringify(registerMsg))
      console.log(`[WebSocket] ノードに接続: ${nodeUrl}`)
    }

    this.ws.onmessage = (event: MessageEvent) => {
      this.handleMessage(event.data as string, phone)
    }

    this.ws.onerror = (event: Event) => {
      console.error('[WebSocket] エラー発生:', event)
    }

    this.ws.onclose = () => {
      console.log('[WebSocket] 接続切断')
    }
  }

  // 受信メッセージを解析してコールバックを呼び出す
  private handleMessage(data: string, myPhone: string): void {
    let msg: BaseMessage
    try {
      msg = JSON.parse(data) as BaseMessage
    } catch {
      console.error('[WebSocket] JSONパース失敗:', data)
      return
    }

    switch (msg.type) {
      case 'sms': {
        const sms = msg as SMSMessage
        // 自分宛てのSMSのみ処理
        if (sms.to === myPhone && this.smsCallback) {
          this.smsCallback(sms.from, sms.body)
        }
        break
      }
      case 'ice_offer': {
        const offer = msg as IceOfferMessage
        // 自分宛てのICE offerのみ処理（着信）
        if (offer.to === myPhone && this.iceOfferCallback) {
          this.iceOfferCallback(offer.from, offer.call_id, offer.sdp_offer, offer.candidates)
        }
        break
      }
      case 'ice_answer': {
        const answer = msg as IceAnswerMessage
        if (this.iceAnswerCallback) {
          this.iceAnswerCallback(answer.call_id, answer.sdp_answer, answer.candidates)
        }
        break
      }
      default:
        // 未知のメッセージタイプはスキップ
        break
    }
  }

  // SMS受信コールバックを設定
  onSMS(callback: SMSCallback): void {
    this.smsCallback = callback
  }

  // ICE offer受信コールバックを設定（着信）
  onIceOffer(callback: IceOfferCallback): void {
    this.iceOfferCallback = callback
  }

  // ICE answer受信コールバックを設定
  onIceAnswer(callback: IceAnswerCallback): void {
    this.iceAnswerCallback = callback
  }

  // ICE answerを送信（着信応答）
  sendIceAnswer(callId: string, sdpAnswer: string, candidates: string[]): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      console.error('[WebSocket] 接続が確立されていません')
      return
    }
    const answerMsg = {
      type: 'ice_answer',
      call_id: callId,
      sdp_answer: sdpAnswer,
      candidates,
    }
    this.ws.send(JSON.stringify(answerMsg))
  }

  // ノードとの接続を切断
  disconnect(): void {
    if (this.ws) {
      this.ws.close()
      this.ws = null
    }
  }
}
