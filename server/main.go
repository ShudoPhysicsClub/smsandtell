// server/main.go - 統合サーバー（window + node + db を一つにまとめたもの）
// ポート: 35000 (TLS)
// DB: SQLite (modernc.org/sqlite, CGO不要)
// 登録: ユーザー名 + パスワードのみ（メール不要）
package main

import (
	crand "crypto/rand"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// ---------------------------------------------------------------------------
// グローバル変数
// ---------------------------------------------------------------------------

var (
	db        *sql.DB
	jwtSecret []byte
	upgrader  = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
)

const jwtTokenExpiry = 24 * time.Hour

// ---------------------------------------------------------------------------
// DB 初期化
// ---------------------------------------------------------------------------

func initDB() error {
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "smsandtell.db"
	}
	var err error
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	// SQLite は同時書き込み 1 本が基本。WAL モードで読み取りは並行可能にする。
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.Ping(); err != nil {
		return fmt.Errorf("ping db: %w", err)
	}
	stmts := []string{
		`PRAGMA journal_mode=WAL`,
		`PRAGMA foreign_keys=ON`,
		`CREATE TABLE IF NOT EXISTS users (
			username      TEXT PRIMARY KEY,
			number        TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			created_at    INTEGER DEFAULT (unixepoch())
		)`,
		`CREATE TABLE IF NOT EXISTS messages (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp   INTEGER NOT NULL,
			received_at INTEGER DEFAULT (unixepoch()),
			message     TEXT NOT NULL,
			to_user     TEXT NOT NULL,
			from_user   TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_msg_to   ON messages(to_user)`,
		`CREATE INDEX IF NOT EXISTS idx_msg_recv ON messages(received_at)`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("db init: %w", err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// JWT（HS256、標準ライブラリのみ）
// ---------------------------------------------------------------------------

func base64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func issueJWT(number string) (string, error) {
	header := base64URLEncode([]byte(`{"alg":"HS256","typ":"JWT"}`))
	now := time.Now().Unix()
	exp := time.Now().Add(jwtTokenExpiry).Unix()
	payloadJSON := fmt.Sprintf(`{"sub":%q,"iat":%d,"exp":%d}`, number, now, exp)
	payload := base64URLEncode([]byte(payloadJSON))
	msg := header + "." + payload
	mac := hmac.New(sha256.New, jwtSecret)
	mac.Write([]byte(msg))
	return msg + "." + base64URLEncode(mac.Sum(nil)), nil
}

func verifyJWT(token string) (string, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid token format")
	}
	msg := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, jwtSecret)
	mac.Write([]byte(msg))
	expected := base64URLEncode(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return "", fmt.Errorf("invalid token signature")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("invalid token payload")
	}
	var claims struct {
		Sub string `json:"sub"`
		Exp int64  `json:"exp"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return "", fmt.Errorf("invalid token claims")
	}
	if time.Now().Unix() > claims.Exp {
		return "", fmt.Errorf("token expired")
	}
	if claims.Sub == "" {
		return "", fmt.Errorf("empty subject")
	}
	return claims.Sub, nil
}

// authFromRequest は Authorization: Bearer <token> ヘッダーまたは X-Token ヘッダーから JWT を取得・検証する。
func authFromRequest(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return verifyJWT(strings.TrimPrefix(auth, "Bearer "))
	}
	if tok := r.Header.Get("X-Token"); tok != "" {
		return verifyJWT(tok)
	}
	return "", fmt.Errorf("missing authorization")
}

// ---------------------------------------------------------------------------
// ユーザー管理
// ---------------------------------------------------------------------------

func generateUserNumber() (string, error) {
	for i := 0; i < 200; i++ {
		n, err := crand.Int(crand.Reader, big.NewInt(1000000))
		if err != nil {
			return "", err
		}
		candidate := fmt.Sprintf("01-%06d", n.Int64())
		var exists int
		if err := db.QueryRow("SELECT COUNT(*) FROM users WHERE number = ?", candidate).Scan(&exists); err != nil {
			return "", err
		}
		if exists == 0 {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("failed to generate unique number after 200 attempts")
}

// ---------------------------------------------------------------------------
// メッセージ
// ---------------------------------------------------------------------------

// Message はユーザー間のメッセージ構造体。
type Message struct {
	ID        int64           `json:"id,omitempty"`
	Timestamp int64           `json:"timestamp"`
	Message   json.RawMessage `json:"message"`
	To        string          `json:"to"`
	From      string          `json:"from"`
}

func storeMessage(msg *Message) error {
	_, err := db.Exec(
		"INSERT INTO messages (timestamp, message, to_user, from_user) VALUES (?, ?, ?, ?)",
		msg.Timestamp, string(msg.Message), msg.To, msg.From,
	)
	return err
}

// popMessages は to_user 宛のメッセージを取得して DB から削除する（アトミック）。
func popMessages(userID string) ([]Message, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	rows, err := tx.Query(
		"SELECT id, timestamp, message, to_user, from_user FROM messages WHERE to_user = ? ORDER BY timestamp ASC",
		userID,
	)
	if err != nil {
		return nil, err
	}

	var messages []Message
	for rows.Next() {
		var m Message
		var msgJSON string
		if err := rows.Scan(&m.ID, &m.Timestamp, &msgJSON, &m.To, &m.From); err != nil {
			rows.Close()
			return nil, err
		}
		m.Message = json.RawMessage(msgJSON)
		messages = append(messages, m)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(messages) > 0 {
		if _, err := tx.Exec("DELETE FROM messages WHERE to_user = ?", userID); err != nil {
			return nil, err
		}
	}
	return messages, tx.Commit()
}

// ---------------------------------------------------------------------------
// WebSocket クライアント管理
// ---------------------------------------------------------------------------

// ClientConn は接続中のブラウザクライアントを表す。
type ClientConn struct {
	conn   *websocket.Conn
	number string
	mu     sync.Mutex
}

func (c *ClientConn) send(v any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.WriteJSON(v)
}

var (
	clients   = make(map[string]*ClientConn)
	clientsMu sync.RWMutex
)

// deliverOrStore はオンラインなら即配信、オフラインなら DB に保存する。
func deliverOrStore(msg *Message) error {
	clientsMu.RLock()
	target, online := clients[msg.To]
	clientsMu.RUnlock()

	if online {
		err := target.send(map[string]any{"action": "messages", "messages": []Message{*msg}})
		if err == nil {
			return nil
		}
		log.Printf("deliver failed to %s, fallback to store: %v", msg.To, err)
	}
	return storeMessage(msg)
}

// sendToClient は `to` のクライアントにシグナルを送る（接続中の場合のみ）。
func sendToClient(to string, payload any) {
	clientsMu.RLock()
	target, ok := clients[to]
	clientsMu.RUnlock()
	if ok {
		if err := target.send(payload); err != nil {
			log.Printf("sendToClient(%s) error: %v", to, err)
		}
	}
}

// ---------------------------------------------------------------------------
// CORS ミドルウェア
// ---------------------------------------------------------------------------

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Token, X-Request-ID")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------
// 定期クリーンアップ（3日以上古いメッセージを削除）
// ---------------------------------------------------------------------------

func startCleanup() {
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			res, err := db.Exec("DELETE FROM messages WHERE received_at < unixepoch() - 259200")
			if err != nil {
				log.Printf("cleanup error: %v", err)
				continue
			}
			if n, _ := res.RowsAffected(); n > 0 {
				log.Printf("cleanup: deleted %d old messages", n)
			}
		}
	}()
}

// ---------------------------------------------------------------------------
// HTTP ハンドラ: アカウント管理
// ---------------------------------------------------------------------------

// POST /account/new - ユーザー登録（ユーザー名 + パスワードのみ）
func handleNew(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	body.Username = strings.TrimSpace(body.Username)
	if body.Username == "" {
		http.Error(w, "username is required", http.StatusBadRequest)
		return
	}
	if len(body.Username) > 64 {
		http.Error(w, "username too long (max 64 chars)", http.StatusBadRequest)
		return
	}
	if len(body.Password) < 8 {
		http.Error(w, "password too short (min 8 chars)", http.StatusBadRequest)
		return
	}

	// ユーザー名の重複チェック
	var exists int
	if err := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", body.Username).Scan(&exists); err != nil {
		log.Printf("db error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if exists > 0 {
		http.Error(w, "username already taken", http.StatusConflict)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("bcrypt error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	number, err := generateUserNumber()
	if err != nil {
		log.Printf("generate number error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if _, err := db.Exec(
		"INSERT INTO users (username, number, password_hash) VALUES (?, ?, ?)",
		body.Username, number, string(hash),
	); err != nil {
		log.Printf("insert user error: %v", err)
		http.Error(w, "registration failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"number": number})
}

// POST /account/login - ログイン（ユーザー名 + パスワード）
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	body.Username = strings.TrimSpace(body.Username)
	if body.Username == "" || body.Password == "" {
		http.Error(w, "username and password are required", http.StatusBadRequest)
		return
	}

	var number, passwordHash string
	err := db.QueryRow(
		"SELECT number, password_hash FROM users WHERE username = ?",
		body.Username,
	).Scan(&number, &passwordHash)
	if err != nil {
		// タイミング攻撃を防ぐために一定時間消費する
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$10$invalidhashfortimingnormalization"), []byte(body.Password))
		http.Error(w, "invalid username or password", http.StatusUnauthorized)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(body.Password)); err != nil {
		http.Error(w, "invalid username or password", http.StatusUnauthorized)
		return
	}

	token, err := issueJWT(number)
	if err != nil {
		log.Printf("jwt error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token":  token,
		"number": number,
	})
}

// ---------------------------------------------------------------------------
// HTTP ハンドラ: SMS 送信
// ---------------------------------------------------------------------------

// POST /sms/send - SMS 送信（JWT 必須）
func handleSMSSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	fromNumber, err := authFromRequest(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var msg Message
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(msg.To) == "" || len(msg.Message) == 0 {
		http.Error(w, "to and message are required", http.StatusBadRequest)
		return
	}
	msg.From = fromNumber
	if msg.Timestamp == 0 {
		msg.Timestamp = time.Now().UTC().Unix()
	}

	if err := deliverOrStore(&msg); err != nil {
		log.Printf("deliverOrStore failed from=%s to=%s: %v", msg.From, msg.To, err)
		http.Error(w, "failed to send message", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ---------------------------------------------------------------------------
// HTTP ハンドラ: ICE / 通話シグナリング（JWT 必須）
// ---------------------------------------------------------------------------

// handleSignal は from を JWT から取得して to のクライアントに action を中継する。
func handleSignal(signalType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		fromNumber, err := authFromRequest(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		to, _ := body["to"].(string)
		to = strings.TrimSpace(to)
		if to == "" {
			http.Error(w, "to is required", http.StatusBadRequest)
			return
		}
		// JWT から検証した from で body を上書き（なりすまし防止）
		body["from"] = fromNumber

		sendToClient(to, map[string]any{"action": signalType, "data": body})
		w.WriteHeader(http.StatusOK)
	}
}

// ---------------------------------------------------------------------------
// WebSocket ハンドラ: クライアント接続（ブラウザ）
// ---------------------------------------------------------------------------

// GET /ws - ブラウザクライアントの WebSocket 接続
func handleClientWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("ws upgrade error:", err)
		return
	}
	defer conn.Close()

	// 最初のメッセージで JWT 認証を受け取る
	var authMsg struct {
		Action string `json:"action"`
		Number string `json:"number"`
		Token  string `json:"token"`
	}
	if err := conn.ReadJSON(&authMsg); err != nil {
		return
	}
	if authMsg.Action != "auth" || authMsg.Token == "" {
		_ = conn.WriteJSON(map[string]string{"error": "expected auth action with token"})
		return
	}

	claimedNumber, err := verifyJWT(authMsg.Token)
	if err != nil {
		_ = conn.WriteJSON(map[string]string{"error": "auth failed: " + err.Error()})
		return
	}
	userID := strings.TrimSpace(claimedNumber)
	if userID == "" {
		_ = conn.WriteJSON(map[string]string{"error": "invalid user id"})
		return
	}

	client := &ClientConn{conn: conn, number: userID}
	clientsMu.Lock()
	clients[userID] = client
	clientsMu.Unlock()
	log.Printf("client connected: %s", userID)

	defer func() {
		clientsMu.Lock()
		if clients[userID] == client {
			delete(clients, userID)
		}
		clientsMu.Unlock()
		log.Printf("client disconnected: %s", userID)
	}()

	// 認証成功を通知
	if err := client.send(map[string]string{"status": "authenticated"}); err != nil {
		return
	}

	// 保留メッセージを配信する
	messages, err := popMessages(userID)
	if err != nil {
		log.Printf("popMessages error for %s: %v", userID, err)
	} else if len(messages) > 0 {
		if err := client.send(map[string]any{"action": "messages", "messages": messages}); err != nil {
			log.Printf("failed to send pending messages to %s: %v", userID, err)
		}
	}

	// 接続維持（クライアントからのメッセージは現在未使用）
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}

// ---------------------------------------------------------------------------
// 静的ファイルサーバー
// ---------------------------------------------------------------------------

func handleStatic(staticDir string) http.Handler {
	fs := http.FileServer(http.Dir(staticDir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// path.Clean("/" + ...) ensures the result is absolute and contains no ".." escapes.
		// filepath.Join then keeps the result inside staticDir.
		safePath := path.Clean("/" + r.URL.Path)
		fullPath := filepath.Join(staticDir, filepath.FromSlash(safePath))
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			// SPA フォールバック: index.html を返す
			http.ServeFile(w, r, filepath.Join(staticDir, "index.html"))
			return
		}
		fs.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------
// メイン
// ---------------------------------------------------------------------------

func main() {
	// JWT シークレット
	jwtSecretStr := os.Getenv("JWT_SECRET")
	if jwtSecretStr == "" {
		log.Fatal("JWT_SECRET is required")
	}
	jwtSecret = []byte(jwtSecretStr)

	// DB 初期化
	if err := initDB(); err != nil {
		log.Fatalf("db init failed: %v", err)
	}
	defer db.Close()

	startCleanup()

	// ポートと TLS 設定
	port := os.Getenv("PORT")
	if port == "" {
		port = "35000"
	}
	certFile := os.Getenv("CERT_FILE")
	keyFile := os.Getenv("KEY_FILE")

	// 静的ファイルのディレクトリ（client/dist/ をコピーして配置する想定）
	staticDir := os.Getenv("STATIC_DIR")
	if staticDir == "" {
		staticDir = "./static"
	}

	mux := http.NewServeMux()

	// アカウント管理
	mux.HandleFunc("/account/new", handleNew)
	mux.HandleFunc("/account/login", handleLogin)

	// SMS 送信（JWT 必須）
	mux.HandleFunc("/sms/send", handleSMSSend)

	// ICE シグナリング（JWT 必須）
	mux.HandleFunc("/ice/offer", handleSignal("ice_offer"))
	mux.HandleFunc("/ice/answer", handleSignal("ice_answer"))
	mux.HandleFunc("/ice/candidate", handleSignal("ice_candidate"))

	// 通話シグナリング（JWT 必須）
	mux.HandleFunc("/call/auth-ok", handleSignal("call_auth_ok"))
	mux.HandleFunc("/call/reject", handleSignal("call_reject"))
	mux.HandleFunc("/call/hangup", handleSignal("call_hangup"))

	// WebSocket（ブラウザクライアント接続）
	mux.HandleFunc("/ws", handleClientWS)

	// 静的ファイル（index.html / main.js 等）
	if _, err := os.Stat(staticDir); err == nil {
		mux.Handle("/", handleStatic(staticDir))
		log.Printf("serving static files from %s", staticDir)
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "not found", http.StatusNotFound)
		})
	}

	handler := corsMiddleware(mux)

	if certFile != "" && keyFile != "" {
		log.Printf("smsandtell server listening on :%s (TLS)", port)
		if err := http.ListenAndServeTLS(":"+port, certFile, keyFile, handler); err != nil {
			log.Fatal(err)
		}
	} else {
		log.Printf("smsandtell server listening on :%s (plain HTTP - use TLS in production)", port)
		if err := http.ListenAndServe(":"+port, handler); err != nil {
			log.Fatal(err)
		}
	}
}
