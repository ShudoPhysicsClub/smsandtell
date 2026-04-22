# smsandtell

SMSと電話を再現するアプリです。

## アーキテクチャ

すべての機能を `server/` の単一サーバーに統合しています。

- **サーバー**: `server/main.go`（Go、SQLite、ポート 35000）
- **クライアント**: `client/`（TypeScript、`tell.manh2309.org:35000` に固定接続）

## 起動方法

### サーバー

```bash
cd server
go build -o server .
JWT_SECRET=your_secret PORT=35000 CERT_FILE=... KEY_FILE=... ./server
```

環境変数の設定例は `server/.env.example` を参照。

### クライアントビルド

```bash
cd client
npm install
npm run build
```

生成物: `client/dist/main.js` + `client/index.html`

これらを `server/static/` ディレクトリ（`STATIC_DIR` 環境変数で変更可）にコピーすると、サーバーが静的ファイルを配信します。

## 環境変数

| 変数 | 説明 | デフォルト |
|------|------|----------|
| `PORT` | リッスンポート | `35000` |
| `JWT_SECRET` | JWT署名シークレット（**必須**） | - |
| `CERT_FILE` | TLS証明書ファイルパス | 未設定時は平文HTTP |
| `KEY_FILE` | TLS秘密鍵ファイルパス | 未設定時は平文HTTP |
| `DB_PATH` | SQLiteファイルパス | `smsandtell.db` |
| `STATIC_DIR` | 静的ファイルディレクトリ | `./static` |

## API エンドポイント

| エンドポイント | 説明 |
|-------------|------|
| `POST /account/new` | 新規登録（username + password） |
| `POST /account/login` | ログイン → JWT + number 返却 |
| `POST /sms/send` | SMS送信（JWT必須） |
| `POST /ice/offer` | ICE offer中継（JWT必須） |
| `POST /ice/answer` | ICE answer中継（JWT必須） |
| `POST /ice/candidate` | ICE candidate中継（JWT必須） |
| `POST /call/auth-ok` | 通話認証OK（JWT必須） |
| `POST /call/reject` | 通話拒否（JWT必須） |
| `POST /call/hangup` | 通話終了（JWT必須） |
| `GET /ws` | WebSocket接続（JWT認証後メッセージ受信） |

## 仕様メモ

- 登録はユーザー名とパスワードのみ（メール不要）
- ユーザー名は重複不可（`username already taken` を返す）
- DBにはユーザー名・番号・パスワードハッシュを保存（SQLite）
- メッセージはDBで3日保持し、1時間ごとに削除
- WebSocket接続時にJWT認証 → 保留メッセージを即配信
- オフライン時はDBに保存 → 次回接続時に配信
- クライアントは `tell.manh2309.org:35000` に固定接続（DNS解決不要）
