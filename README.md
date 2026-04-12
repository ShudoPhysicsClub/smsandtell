# smsandtell

smsと電話を再現します。

## 起動順（必須）

1. dbサービスを起動
2. nodeサービスを起動
3. windowサービスを起動

### Windows一括起動テンプレ

```powershell
./start-all.ps1
```

## client本番ビルド

```powershell
cd client
npm install
npm run build:prod
```

- 生成物: `client/dist/main.js`
- 配信時は `client/index.html` と `client/dist/main.js` を同じ公開ディレクトリに置く

## 環境変数

- db: `db/.env`
- node: `node/.env`
- window: `window/.env`

特に以下は必須です。

- `DB_SERVICE_URL`（node/window）
- `DB_SERVICE_TOKEN`（db/node/windowで同じ値）
- `WINDOW_API_BASE`（nodeが公開鍵を取得する先）
- `TOKEN_TTL_MINUTES`（window。未指定時は15分）
- `NUMBER`（window。自拠点番号）
- DNSシードドメインは `manh2309.org` 固定

## 疎通確認

1. db health

```powershell
Invoke-WebRequest http://DB_SERVER_HOST:32000/health
```

1. windowの公開鍵API

```powershell
Invoke-WebRequest https://WINDOW_SERVER_HOST:30000/pubkey/01-xxxxxx
```

1. nodeの受信確認

- クライアントをnodeにWS接続
- ログイン時に保留メッセージが返ってきたら成功

## 仕様メモ

- メッセージはdbで3日保持し、1時間ごとにUTC基準で削除
- db内部通信はWS（`/ws`）
- 公開鍵取得の入口はwindow経由
- ログイン時のnode接続先は、`02-xxxxxx` のような番号の接頭辞（`02`）を使って `02.manh2309.org` のTXTを引き、ランダム選択
- email確認/再設定トークンはwindowメモリにTTL付きで保持し、1分ごとに期限切れ掃除

### DNSシード例

`01.manh2309.org` のTXTに `window=` と `node=` を並べる。

```txt
window=win-a.example.com:3334 window=win-b.example.com:3334 node=node-a.example.com:334 node=node-b.example.com:334
```

clientは `window=` を `https://<addr>`、`node=` を `wss://<addr>/ws` に正規化して接続する。

## 署名仕様（固定）

- 署名アルゴリズム: ECSH P-256（`node/ecsh.go`）
- 署名値エンコード: hex（96byte = 192 hex chars）
- 公開鍵エンコード: hex（64byte = 128 hex chars）

### ログイン認証署名

署名対象JSON（canonical JSON）:

```json
{"number":"<number>","challenge":"<challenge>"}
```

### メッセージ署名

署名対象JSON（canonical JSON）:

```json
{"timestamp":<unix> ,"message":<json>,"to":"<to>","from":"<from>"}
```
