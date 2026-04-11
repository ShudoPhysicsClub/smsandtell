// P256 (secp256r1) Schnorr署名の純粋TypeScript実装
// 外部ライブラリなし、ブラウザのWebCrypto APIのみ使用

// 楕円曲線上の点を表す型
type Point = { x: bigint; y: bigint }

// P256曲線パラメータ
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n
const Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n
const Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n
const G: Point = { x: Gx, y: Gy }

// A係数（P256: a = -3 mod p）
const A = P - 3n

// フィールド上のモジュラー逆元をフェルマーの小定理で計算
function modInv(a: bigint, m: bigint): bigint {
  return modPow(((a % m) + m) % m, m - 2n, m)
}

// 高速べき乗計算（繰り返し二乗法）
function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n
  base = ((base % mod) + mod) % mod
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod
    base = (base * base) % mod
    exp >>= 1n
  }
  return result
}

// 楕円曲線点の加算
function pointAdd(P1: Point | null, P2: Point | null): Point | null {
  if (P1 === null) return P2
  if (P2 === null) return P1

  const { x: x1, y: y1 } = P1
  const { x: x2, y: y2 } = P2

  // 同じ点の場合は点の2倍算を行う
  if (x1 === x2) {
    if (y1 !== y2) return null // 無限遠点（逆元）
    return pointDouble(P1)
  }

  // 傾きλ = (y2 - y1) / (x2 - x1) mod p
  const lam = (((y2 - y1) % P + P) % P * modInv((x2 - x1 + P) % P, P)) % P
  const x3 = (lam * lam - x1 - x2 + 2n * P) % P
  const y3 = (lam * (x1 - x3 + P) % P - y1 + P) % P
  return { x: x3, y: y3 }
}

// 楕円曲線点の2倍算
function pointDouble(pt: Point): Point | null {
  const { x, y } = pt
  if (y === 0n) return null

  // 傾きλ = (3x^2 + a) / (2y) mod p
  const lam = ((3n * x * x + A) % P * modInv((2n * y) % P, P)) % P
  const x3 = (lam * lam - 2n * x + 2n * P) % P
  const y3 = (lam * (x - x3 + P) % P - y + P) % P
  return { x: x3, y: y3 }
}

// スカラー倍算（ダブルアンドアッド法）
function pointMul(k: bigint, pt: Point): Point | null {
  let result: Point | null = null
  let addend: Point | null = pt
  let scalar = ((k % N) + N) % N

  while (scalar > 0n) {
    if (scalar & 1n) result = pointAdd(result, addend)
    addend = addend === null ? null : pointAdd(addend, addend)
    scalar >>= 1n
  }
  return result
}

// 16進数文字列をbigintに変換
function hexToBigInt(hex: string): bigint {
  return BigInt('0x' + hex)
}

// bigintを32バイトの16進数文字列に変換（ゼロ埋め）
export function bigIntToHex32(n: bigint): string {
  return n.toString(16).padStart(64, '0')
}

// バイト配列からbigintに変換（ビッグエンディアン）
function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n
  for (const b of bytes) {
    result = (result << 8n) | BigInt(b)
  }
  return result
}

// bigintを指定バイト数のUint8Arrayに変換（ビッグエンディアン）
function bigIntToBytes(n: bigint, len: number): Uint8Array {
  const bytes = new Uint8Array(len)
  let val = n
  for (let i = len - 1; i >= 0; i--) {
    bytes[i] = Number(val & 0xffn)
    val >>= 8n
  }
  return bytes
}

// SHA-256ハッシュ（WebCrypto API使用）
async function sha256(data: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  // TypeScript型制約のためArrayBufferにキャストして渡す
  const hashBuffer = await crypto.subtle.digest('SHA-256', data.buffer as ArrayBuffer)
  return new Uint8Array(hashBuffer)
}

// HMAC-SHA256を計算するヘルパー
// WebCrypto APIの型制約を満たすためにArrayBufferにコピーする
async function hmacSha256(
  key: Uint8Array<ArrayBuffer>,
  ...parts: Uint8Array[]
): Promise<Uint8Array<ArrayBuffer>> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  )
  const totalLen = parts.reduce((acc, d) => acc + d.length, 0)
  const combined = new Uint8Array(totalLen)
  let offset = 0
  for (const d of parts) {
    combined.set(d, offset)
    offset += d.length
  }
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, combined)
  return new Uint8Array(sig)
}

// RFC6979 決定論的ノンス生成（HMAC-DRBG）
// privKey: 秘密鍵, msgHash: メッセージハッシュ
async function generateK(privKey: bigint, msgHash: Uint8Array): Promise<bigint> {
  const privBytes = bigIntToBytes(privKey, 32)

  // RFC6979 Step b: V = 0x01 * 32
  let V: Uint8Array<ArrayBuffer> = new Uint8Array(32).fill(0x01)
  // RFC6979 Step c: K = 0x00 * 32
  let K: Uint8Array<ArrayBuffer> = new Uint8Array(32).fill(0x00)

  // RFC6979 Step d: K = HMAC_K(V || 0x00 || privKey || msgHash)
  K = await hmacSha256(K, V, new Uint8Array([0x00]), privBytes, msgHash)
  // RFC6979 Step e: V = HMAC_K(V)
  V = await hmacSha256(K, V)
  // RFC6979 Step f: K = HMAC_K(V || 0x01 || privKey || msgHash)
  K = await hmacSha256(K, V, new Uint8Array([0x01]), privBytes, msgHash)
  // RFC6979 Step g: V = HMAC_K(V)
  V = await hmacSha256(K, V)

  // RFC6979 Step h: 有効なノンスが見つかるまで繰り返す
  for (;;) {
    V = await hmacSha256(K, V)
    const kInt = bytesToBigInt(V)
    if (kInt > 0n && kInt < N) return kInt

    // 有効なノンスが得られなかった場合は再試行
    K = await hmacSha256(K, V, new Uint8Array([0x00]))
    V = await hmacSha256(K, V)
  }
}

// チャレンジハッシュ H(Rx||Ry||Yx||Yy||msg) を計算する
async function schnorrChallenge(
  Rx: bigint, Ry: bigint,
  Yx: bigint, Yy: bigint,
  msg: Uint8Array
): Promise<bigint> {
  const rxBytes = bigIntToBytes(Rx, 32)
  const ryBytes = bigIntToBytes(Ry, 32)
  const yxBytes = bigIntToBytes(Yx, 32)
  const yyBytes = bigIntToBytes(Yy, 32)

  const combined = new Uint8Array(128 + msg.length)
  combined.set(rxBytes, 0)
  combined.set(ryBytes, 32)
  combined.set(yxBytes, 64)
  combined.set(yyBytes, 96)
  combined.set(msg, 128)

  const hash = await sha256(combined)
  return bytesToBigInt(hash)
}

// Schnorr署名生成
// 署名形式: {rx, ry, s} 各32バイト16進数
export async function schnorrSign(
  privKey: bigint,
  message: Uint8Array
): Promise<{ rx: string; ry: string; s: string }> {
  // メッセージをSHA-256でハッシュ化
  const msgHash = await sha256(message)

  // RFC6979で決定論的ノンスkを生成
  const k = await generateK(privKey, msgHash)

  // R = k*G を計算
  const R = pointMul(k, G)
  if (R === null) throw new Error('R点の計算失敗')

  // 公開鍵 Y = privKey*G を計算
  const Y = pointMul(privKey, G)
  if (Y === null) throw new Error('公開鍵の計算失敗')

  // チャレンジハッシュ e = H(Rx||Ry||Yx||Yy||msg) を計算
  const e = await schnorrChallenge(R.x, R.y, Y.x, Y.y, message)

  // s = k - e*privKey mod N を計算
  const s = ((k - (e * privKey) % N) % N + N) % N

  return {
    rx: bigIntToHex32(R.x),
    ry: bigIntToHex32(R.y),
    s: bigIntToHex32(s),
  }
}

// Schnorr署名検証
// 検証式: sG = R + H(Rx||Ry||Yx||Yy||msg) * Y
export async function schnorrVerify(
  pubKey: { x: bigint; y: bigint },
  message: Uint8Array,
  sig: { rx: string; ry: string; s: string }
): Promise<boolean> {
  const Rx = hexToBigInt(sig.rx)
  const Ry = hexToBigInt(sig.ry)
  const s = hexToBigInt(sig.s)

  // sの有効範囲チェック
  if (s <= 0n || s >= N) return false

  // チャレンジハッシュ e = H(Rx||Ry||Yx||Yy||msg) を計算
  const e = await schnorrChallenge(Rx, Ry, pubKey.x, pubKey.y, message)
  const eMod = e % N

  // sG を計算
  const sG = pointMul(s, G)
  if (sG === null) return false

  // eY を計算
  const eY = pointMul(eMod, pubKey)
  if (eY === null) return false

  // R + eY を計算
  const R: Point = { x: Rx, y: Ry }
  const RplusEY = pointAdd(R, eY)
  if (RplusEY === null) return false

  // sG == R + eY を検証
  return sG.x === RplusEY.x && sG.y === RplusEY.y
}

// 秘密鍵から公開鍵を生成
export function getPublicKey(privKey: bigint): { x: bigint; y: bigint } {
  const pub = pointMul(privKey, G)
  if (pub === null) throw new Error('公開鍵の生成失敗')
  return pub
}

// メッセージを組み立てる: challenge || timestamp(10進数文字列) || phone_number
// サーバー（gateway/auth.go）の形式に合わせてタイムスタンプは10進数文字列として結合する
export function buildSignMessage(challenge: string, timestamp: number, phone: string): Uint8Array {
  const enc = new TextEncoder()
  // サーバー側: []byte(challenge + fmt.Sprintf("%d", timestamp) + phone)
  return enc.encode(challenge + String(timestamp) + phone)
}

// パスワードと電話番号からプライベートキーをPBKDF2で生成
// salt: 電話番号をUTF-8エンコードしたバイト列
// iterations: 200000回（ブルートフォース対策）
export async function deriveKeyFromPassword(password: string, phone: string): Promise<bigint> {
  const enc = new TextEncoder()
  // パスワードをWebCryptoにインポート
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  )

  // PBKDF2で256ビットの鍵素材を導出
  const derived = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      // saltには電話番号を使用（ユーザーごとに異なるsalt）
      salt: enc.encode('smsandtell:' + phone),
      iterations: 200000,
      hash: 'SHA-256',
    },
    keyMaterial,
    256
  )

  // 導出したビット列をbigintに変換し、曲線の位数以内に収める
  let key = bytesToBigInt(new Uint8Array(derived)) % (N - 1n) + 1n
  return key
}
