// APIクライアント
// ゲートウェイとの通信を担当するモジュール

// APIのベースURL
const GATEWAY_URL = 'http://localhost:1919'

// エラーレスポンスの型定義
interface ApiError {
  error: string
}

// HTTPレスポンスを検証してJSONを返すヘルパー
async function fetchJson<T>(url: string, options: RequestInit): Promise<T> {
  const res = await fetch(url, options)
  const data = await res.json()
  if (!res.ok) {
    const err = data as ApiError
    throw new Error(err.error ?? `HTTPエラー: ${res.status}`)
  }
  return data as T
}

// 認証チャレンジレスポンスの型定義
interface ChallengeResponse {
  challenge: string
  expires: number
}

// 認証チャレンジを取得
export async function getChallenge(phone: string): Promise<ChallengeResponse> {
  return fetchJson<ChallengeResponse>(`${GATEWAY_URL}/auth/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ phone }),
  })
}

// 署名検証レスポンスの型定義
interface VerifyResponse {
  token: string
  nodes: string[]
}

// 署名を検証してセッショントークンを取得
export async function verifySignature(
  phone: string,
  pubkey: { x: string; y: string },
  sig: { rx: string; ry: string; s: string },
  challenge: string
): Promise<VerifyResponse> {
  return fetchJson<VerifyResponse>(`${GATEWAY_URL}/auth/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ phone, pubkey, sig, challenge }),
  })
}

// SMS送信レスポンスの型定義
interface SMSResponse {
  status: string
}

// SMS送信
export async function sendSMS(
  token: string,
  from: string,
  to: string,
  body: string
): Promise<SMSResponse> {
  return fetchJson<SMSResponse>(`${GATEWAY_URL}/sms/send`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify({ from, to, body }),
  })
}

// ICE offer送信レスポンスの型定義
interface IceOfferResponse {
  call_id: string
}

// ICE offer送信（通話発信）
export async function sendIceOffer(
  token: string,
  from: string,
  to: string,
  sdpOffer: string,
  candidates: string[]
): Promise<IceOfferResponse> {
  return fetchJson<IceOfferResponse>(`${GATEWAY_URL}/ice/offer`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify({ from, to, sdp_offer: sdpOffer, candidates }),
  })
}
