# smsandtell

smsと電話を再現します — tell.com ネットワーク通信システム

## 概要

WebRTC P2P音声通話とSMSメッセージングを提供する分散型通信ネットワークです。
キャリア識別子（電話番号上2桁）によるフェデレーション構造を持ち、異なるネットワーク間の通話・SMSも可能です。
認証にはSchnorr署名（P256曲線）を使用し、サーバーは公開鍵のみを保持します。

## ディレクトリ構成

```
smsandtell/
├── gateway/          # ゲートウェイサーバー (Go, ポート1919)
│   ├── main.go       # エントリポイント
│   ├── auth.go       # 認証エンドポイント (Schnorr署名検証)
│   ├── sms.go        # SMS送受信・ルーティング
│   ├── ice.go        # ICE情報中継 (WebRTC)
│   ├── dns.go        # DNSシードによるネットワーク発見
│   ├── node_ws.go    # ノードとのWebSocket内部通信
│   └── ecsh.go       # P256 Schnorr署名実装
├── node/             # ノードサーバー (Go, ポート334)
│   ├── main.go       # エントリポイント
│   ├── client_ws.go  # クライアントWebSocket接続管理
│   └── mesh.go       # ノード間メッシュ通信
├── client/           # Webクライアント (TypeScript/React)
│   └── src/
│       ├── ecdsa.ts        # P256 Schnorr署名 (純粋TypeScript)
│       ├── api.ts          # ゲートウェイAPIクライアント
│       ├── websocket.ts    # ノードWebSocket接続管理
│       └── components/
│           ├── Login.tsx   # 認証UI
│           ├── SMS.tsx     # SMS送受信UI
│           └── Voice.tsx   # WebRTC音声通話UI
├── go.mod
└── go.sum
```

## セットアップ・起動方法

### ゲートウェイサーバー

```bash
go run ./gateway/...
# または
go build -o gateway-server ./gateway/...
./gateway-server
```

ポート1919でHTTPサーバーが起動します。

### ノードサーバー

```bash
go run ./node/...
# または
go build -o node-server ./node/...
./node-server
```

ポート334でWebSocketサーバーが起動します。

### Webクライアント

```bash
cd client
npm install
npm run dev       # 開発サーバー起動
npm run build     # 本番ビルド
```

## 電話番号体系

形式: `XX-XXXXXXXX`
- 上2桁: ネットワーク/キャリア識別子
- 下8桁: ユーザーID

例: `02-12345678` → ネットワーク02のユーザー12345678

## APIエンドポイント

| メソッド | パス | 説明 |
|----------|------|------|
| POST | /auth/challenge | 認証チャレンジ取得 |
| POST | /auth/verify | Schnorr署名検証・セッション発行 |
| POST | /sms/send | SMS送信 |
| POST | /ice/offer | WebRTC ICE offer送信 |
| WS | /ws | ノードとの内部通信 |

## 技術スタック

| 分類 | 技術 |
|------|------|
| サーバー言語 | Go |
| WebSocket | gorilla/websocket |
| 暗号 | P256 Schnorr署名 (RFC6979) |
| クライアント | TypeScript / React / Vite |
| 音声通話 | WebRTC P2P |
| STUN | stun.l.google.com:19302 |

