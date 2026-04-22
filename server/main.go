// server/main.go - 統合サーバー（window + node + db を一つにまとめたもの）
// ポート: 35000 (TLS)
// DB: MariaDB
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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
)

var (
	db        *sql.DB
	jwtSecret []byte
	upgrader  = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	clients   = make(map[string]*ClientConn)
	clientsMu sync.RWMutex
)

const jwtTokenExpiry = 24 * time.Hour

func buildMySQLDSN() (string, error) {
	if dsn := os.Getenv("DB_DSN"); dsn != "" {
		return dsn, nil
	}

	user := os.Getenv("DB_USER")
	if user == "" {
		return "", fmt.Errorf("DB_USER is required")
	}
	name := os.Getenv("DB_NAME")
	if name == "" {
		return "", fmt.Errorf("DB_NAME is required")
	}

	host := os.Getenv("DB_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	port := os.Getenv("DB_PORT")
	if port == "" {
		port = "3306"
	}

	cfg := mysql.NewConfig()
	cfg.User = user
	cfg.Passwd = os.Getenv("DB_PASSWORD")
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(host, port)
	cfg.DBName = name
	cfg.ParseTime = true
	cfg.Loc = time.Local
	cfg.Params = map[string]string{"charset": "utf8mb4"}
	return cfg.FormatDSN(), nil
}

func initDB() error {
	dsn, err := buildMySQLDSN()
	if err != nil {
		return err
	}

	db, err = sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)

	if err := db.Ping(); err != nil {
		return fmt.Errorf("ping db: %w", err)
	}

	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			username      VARCHAR(64) PRIMARY KEY,
			number        VARCHAR(32) NOT NULL UNIQUE,
			password_hash VARCHAR(255) NOT NULL,
			created_at    BIGINT NOT NULL
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
		`CREATE TABLE IF NOT EXISTS messages (
			id          BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
			timestamp   BIGINT NOT NULL,
			received_at BIGINT NOT NULL,
			message     LONGTEXT NOT NULL,
			to_user     VARCHAR(32) NOT NULL,
			from_user   VARCHAR(32) NOT NULL,
			INDEX idx_msg_to (to_user),
			INDEX idx_msg_recv (received_at)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("db init: %w", err)
		}
	}
	return nil
}

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

type Message struct {
	ID        int64           `json:"id,omitempty"`
	Timestamp int64           `json:"timestamp"`
	Message   json.RawMessage `json:"message"`
	To        string          `json:"to"`
	From      string          `json:"from"`
}

func storeMessage(msg *Message) error {
	_, err := db.Exec(
		"INSERT INTO messages (timestamp, received_at, message, to_user, from_user) VALUES (?, ?, ?, ?, ?)",
		msg.Timestamp, time.Now().UTC().Unix(), string(msg.Message), msg.To, msg.From,
	)
	return err
}

func popMessages(userID string) ([]Message, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	rows, err := tx.Query("SELECT id, timestamp, message, to_user, from_user FROM messages WHERE to_user = ? ORDER BY timestamp ASC", userID)
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

func deliverOrStore(msg *Message) error {
	clientsMu.RLock()
	target, online := clients[msg.To]
	clientsMu.RUnlock()

	if online {
		if err := target.send(map[string]any{"action": "messages", "messages": []Message{*msg}}); err == nil {
			return nil
		}
		log.Printf("deliver failed to %s, fallback to store", msg.To)
	}
	return storeMessage(msg)
}

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

func startCleanup() {
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			res, err := db.Exec("DELETE FROM messages WHERE received_at < UNIX_TIMESTAMP() - 259200")
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

	if _, err := db.Exec("INSERT INTO users (username, number, password_hash, created_at) VALUES (?, ?, ?, ?)", body.Username, number, string(hash), time.Now().UTC().Unix()); err != nil {
		log.Printf("insert user error: %v", err)
		http.Error(w, "registration failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"number": number})
}

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
	err := db.QueryRow("SELECT number, password_hash FROM users WHERE username = ?", body.Username).Scan(&number, &passwordHash)
	if err != nil {
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
	json.NewEncoder(w).Encode(map[string]string{"token": token, "number": number})
}

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
		body["from"] = fromNumber

		sendToClient(to, map[string]any{"action": signalType, "data": body})
		w.WriteHeader(http.StatusOK)
	}
}

func handleClientWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("ws upgrade error:", err)
		return
	}
	defer conn.Close()

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

	if err := client.send(map[string]string{"status": "authenticated"}); err != nil {
		return
	}

	messages, err := popMessages(userID)
	if err != nil {
		log.Printf("popMessages error for %s: %v", userID, err)
	} else if len(messages) > 0 {
		if err := client.send(map[string]any{"action": "messages", "messages": messages}); err != nil {
			log.Printf("failed to send pending messages to %s: %v", userID, err)
		}
	}

	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}

func handleStatic(staticDir string) http.Handler {
	dir := http.Dir(staticDir)
	fs := http.FileServer(dir)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, err := dir.Open(r.URL.Path)
		if err != nil {
			http.ServeFile(w, r, filepath.Join(staticDir, "index.html"))
			return
		}
		f.Close()
		fs.ServeHTTP(w, r)
	})
}

func main() {
	jwtSecretStr := os.Getenv("JWT_SECRET")
	if jwtSecretStr == "" {
		log.Fatal("JWT_SECRET is required")
	}
	jwtSecret = []byte(jwtSecretStr)

	if err := initDB(); err != nil {
		log.Fatalf("db init failed: %v", err)
	}
	defer db.Close()

	startCleanup()

	port := os.Getenv("PORT")
	if port == "" {
		port = "35000"
	}
	certFile := os.Getenv("CERT_FILE")
	keyFile := os.Getenv("KEY_FILE")

	staticDir := os.Getenv("STATIC_DIR")
	if staticDir == "" {
		staticDir = "./static"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/account/new", handleNew)
	mux.HandleFunc("/account/login", handleLogin)
	mux.HandleFunc("/sms/send", handleSMSSend)
	mux.HandleFunc("/ice/offer", handleSignal("ice_offer"))
	mux.HandleFunc("/ice/answer", handleSignal("ice_answer"))
	mux.HandleFunc("/ice/candidate", handleSignal("ice_candidate"))
	mux.HandleFunc("/call/auth-ok", handleSignal("call_auth_ok"))
	mux.HandleFunc("/call/reject", handleSignal("call_reject"))
	mux.HandleFunc("/call/hangup", handleSignal("call_hangup"))
	mux.HandleFunc("/ws", handleClientWS)

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