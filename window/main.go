package main

import (
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

var dbServiceURL string
var dbServiceToken string
var seedDomain string
var routeNumber string // このwindowサーバーのルーティングプレフィックス（例: "02"）
var dbWSConn *websocket.Conn
var dbWSMu sync.Mutex

const fixedSeedDomain = "manh2309.org"

const (
	dbWSRetries = 3
	dbWSTimeout = 5 * time.Second
)

// --- トークン管理（メモリ） ---

type tokenEntry struct {
	Email     string
	ExpiresAt time.Time
}

var (
	emailVerifyTokens = make(map[string]tokenEntry) // token -> entry
	resetTokens       = make(map[string]tokenEntry) // token -> entry
	tokensMu          sync.RWMutex
	tokenTTL          = 15 * time.Minute
)

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := crand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func initTokenConfig() {
	if v := strings.TrimSpace(os.Getenv("TOKEN_TTL_MINUTES")); v != "" {
		if mins, err := time.ParseDuration(v + "m"); err == nil && mins > 0 {
			tokenTTL = mins
		}
	}
}

func startTokenSweeper() {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			tokensMu.Lock()
			for token, entry := range emailVerifyTokens {
				if now.After(entry.ExpiresAt) {
					delete(emailVerifyTokens, token)
				}
			}
			for token, entry := range resetTokens {
				if now.After(entry.ExpiresAt) {
					delete(resetTokens, token)
				}
			}
			tokensMu.Unlock()
		}
	}()
}

func putToken(store map[string]tokenEntry, token, email string) {
	store[token] = tokenEntry{Email: email, ExpiresAt: time.Now().Add(tokenTTL)}
}

func getTokenEmail(store map[string]tokenEntry, token string) (string, bool) {
	entry, ok := store[token]
	if !ok {
		return "", false
	}
	if time.Now().After(entry.ExpiresAt) {
		return "", false
	}
	return entry.Email, true
}

// atomicConsumeToken はトークンの有効性チェックと削除を書き込みロック下でアトミックに行う。
// RLock → Unlock → Lock の TOCTOU 競合を防ぎ、同一トークンの並行使用を排除する。
func atomicConsumeToken(store map[string]tokenEntry, token string) (string, bool) {
	tokensMu.Lock()
	defer tokensMu.Unlock()
	entry, ok := store[token]
	if !ok || time.Now().After(entry.ExpiresAt) {
		delete(store, token) // 期限切れも即削除
		return "", false
	}
	delete(store, token)
	return entry.Email, true
}

// --- DBサービス ---

func initDBService() error {
	dbServiceURL = os.Getenv("DB_SERVICE_URL")
	if dbServiceURL == "" {
		return fmt.Errorf("DB_SERVICE_URL is required")
	}
	dbServiceToken = os.Getenv("DB_SERVICE_TOKEN")
	if dbServiceToken == "" {
		return fmt.Errorf("DB_SERVICE_TOKEN is required")
	}
	var out map[string]string
	if err := dbWSCall("health", map[string]string{}, &out); err != nil {
		return fmt.Errorf("db service health failed: %w", err)
	}
	log.Println("db service connected:", dbServiceURL)
	return nil
}

func resetDBWSConnLocked() {
	if dbWSConn != nil {
		_ = dbWSConn.Close()
		dbWSConn = nil
	}
}

func getDBWSConnLocked() (*websocket.Conn, error) {
	if dbWSConn != nil {
		return dbWSConn, nil
	}
	dialer := websocket.Dialer{HandshakeTimeout: dbWSTimeout}
	conn, _, err := dialer.Dial(dbServiceURL, nil)
	if err != nil {
		return nil, err
	}
	dbWSConn = conn
	return dbWSConn, nil
}

func dbWSCall(action string, payload any, out any) error {
	var lastErr error
	for attempt := 1; attempt <= dbWSRetries; attempt++ {
		dbWSMu.Lock()
		conn, err := getDBWSConnLocked()
		if err != nil {
			dbWSMu.Unlock()
			lastErr = err
			log.Printf("db ws dial failed (attempt %d/%d): %v", attempt, dbWSRetries, err)
			continue
		}

		req := map[string]any{"action": action, "data": payload, "token": dbServiceToken}
		_ = conn.SetWriteDeadline(time.Now().Add(dbWSTimeout))
		if err := conn.WriteJSON(req); err != nil {
			lastErr = err
			resetDBWSConnLocked()
			dbWSMu.Unlock()
			log.Printf("db ws write failed (attempt %d/%d): %v", attempt, dbWSRetries, err)
			continue
		}

		var resp struct {
			OK    bool            `json:"ok"`
			Error string          `json:"error"`
			Data  json.RawMessage `json:"data"`
		}
		_ = conn.SetReadDeadline(time.Now().Add(dbWSTimeout))
		err = conn.ReadJSON(&resp)
		if err != nil {
			lastErr = err
			resetDBWSConnLocked()
			dbWSMu.Unlock()
			log.Printf("db ws read failed (attempt %d/%d): %v", attempt, dbWSRetries, err)
			continue
		}
		if !resp.OK {
			lastErr = fmt.Errorf("%s", resp.Error)
			if strings.Contains(strings.ToLower(resp.Error), "unauthorized") {
				resetDBWSConnLocked()
			}
			dbWSMu.Unlock()
			log.Printf("db ws response error (attempt %d/%d): %v", attempt, dbWSRetries, lastErr)
			continue
		}

		if out != nil {
			if err := json.Unmarshal(resp.Data, out); err != nil {
				lastErr = err
				dbWSMu.Unlock()
				log.Printf("db ws decode failed (attempt %d/%d): %v", attempt, dbWSRetries, err)
				continue
			}
		}
		dbWSMu.Unlock()
		return nil
	}
	return lastErr
}

func getUserByNumber(number string) (email, pubkey string, err error) {
	var out struct {
		Email     string `json:"email"`
		PublicKey string `json:"public_key"`
	}
	err = dbWSCall("users.getByNumber", map[string]string{"number": number}, &out)
	if err != nil {
		return "", "", err
	}
	return out.Email, out.PublicKey, nil
}

func getUserByPublicKey(pubkey string) (number string, err error) {
	var out struct {
		Number string `json:"number"`
	}
	err = dbWSCall("users.getByPubkey", map[string]string{"public_key": pubkey}, &out)
	if err != nil {
		return "", err
	}
	return out.Number, nil
}

func createUser(email string, pubkey string) (number string, err error) {
	var out struct {
		Number string `json:"number"`
	}
	err = dbWSCall("users.create", map[string]string{"email": email, "public_key": pubkey, "route": routeNumber}, &out)
	if err != nil {
		return "", err
	}
	return out.Number, nil
}

func updatePublicKey(email string, newPubkey string) (number string, err error) {
	var out struct {
		Number string `json:"number"`
	}
	err = dbWSCall("users.updatePubkey", map[string]string{"email": email, "public_key": newPubkey}, &out)
	if err != nil {
		return "", err
	}
	return out.Number, nil
}

func userExistsByEmail(email string) (bool, error) {
	var out struct {
		Exists bool `json:"exists"`
	}
	err := dbWSCall("users.existsEmail", map[string]string{"email": email}, &out)
	if err != nil {
		return false, err
	}
	return out.Exists, nil
}

// --- メール送信 ---

func sendEmail(to, subject, body string) error {
	host := os.Getenv("SMTP_HOST")
	port := os.Getenv("SMTP_PORT")
	user := os.Getenv("SMTP_USER")
	password := os.Getenv("SMTP_PASSWORD")

	// SMTP ヘッダーインジェクション対策: to / subject の改行文字を除去する
	to = strings.NewReplacer("\r", "", "\n", "").Replace(to)
	subject = strings.NewReplacer("\r", "", "\n", "").Replace(subject)

	auth := smtp.PlainAuth("", user, password, host)
	msg := fmt.Sprintf("From: %s\nTo: %s\nSubject: %s\n\n%s", user, to, subject, body)
	err := smtp.SendMail(host+":"+port, auth, user, []string{to}, []byte(msg))
	return err
}

// --- CORS ---

// corsMiddleware はすべてのHTTPレスポンスにCORSヘッダーを付与する。
// ブラウザからのfetchリクエストがCORSポリシーでブロックされないようにする。
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Request-ID")
		w.Header().Set("Access-Control-Max-Age", "86400")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- メッセージ型・署名検証 ---

// Message はSMSメッセージの構造体。node/main.go と同一定義。
type Message struct {
	Timestamp int64           `json:"timestamp"`
	Message   json.RawMessage `json:"message"`
	To        string          `json:"to"`
	From      string          `json:"from"`
	Sig       string          `json:"sig"`
}

func buildMessageSigningPayload(msg *Message) map[string]any {
	return map[string]any{
		"timestamp": msg.Timestamp,
		"message":   json.RawMessage(msg.Message),
		"to":        msg.To,
		"from":      msg.From,
	}
}

// verifyMessageSignature はSMSメッセージの署名をwindow側で検証する。
// DBから送信者の公開鍵を取得してECDSA検証を行う。
func verifyMessageSignature(msg *Message) error {
	if msg.From == "" || msg.To == "" || len(msg.Message) == 0 || msg.Timestamp == 0 || msg.Sig == "" {
		return fmt.Errorf("missing signed fields")
	}
	_, pubHex, err := getUserByNumber(msg.From)
	if err != nil {
		return fmt.Errorf("sender not found: %w", err)
	}
	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil || len(pubBytes) != 64 {
		return fmt.Errorf("invalid public key encoding")
	}
	sigBytes, err := hex.DecodeString(msg.Sig)
	if err != nil || len(sigBytes) != 96 {
		return fmt.Errorf("invalid signature encoding")
	}
	payload := buildMessageSigningPayload(msg)
	normalized, err := CanonicalJSON(payload)
	if err != nil {
		return err
	}
	var pub PublicKey
	copy(pub[:], pubBytes)
	var sig Signature
	copy(sig[:], sigBytes)
	if !Verify(pub, normalized, sig) {
		return fmt.Errorf("signature verify failed")
	}
	return nil
}

// --- ノード管理 ---

type NodeConn struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

var (
	nodes   = make(map[string]*NodeConn) // key: nodeアドレス
	nodesMu sync.RWMutex
)

// broadcast は現在接続中の全ノードにメッセージを送る（TTLなし、受け取ったノードは他に流さない）
func broadcast(msg []byte) {
	nodesMu.RLock()
	defer nodesMu.RUnlock()
	for addr, node := range nodes {
		node.mu.Lock()
		err := node.conn.WriteMessage(websocket.TextMessage, msg)
		node.mu.Unlock()
		if err != nil {
			log.Printf("broadcast error to %s: %v", addr, err)
		}
	}
}

// --- DNSシード ---

func seedLabelFromNumber(number string) string {
	n := strings.TrimSpace(number)
	if n == "" {
		return ""
	}
	parts := strings.SplitN(n, "-", 2)
	return strings.TrimSpace(parts[0])
}

// lookupSeed はTXTレコードからnodeアドレス一覧を返す
// 例: domain=tell.com, number=02 → 02.tell.com のTXTを引く
func lookupSeedRecords(domain, number string) (map[string][]string, error) {
	label := seedLabelFromNumber(number)
	if label == "" {
		return nil, fmt.Errorf("empty number")
	}
	host := fmt.Sprintf("%s.%s", label, domain)
	records, err := net.LookupTXT(host)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed for %s: %w", host, err)
	}
	out := make(map[string][]string)
	for _, record := range records {
		for _, field := range strings.Fields(record) {
			parts := strings.SplitN(field, "=", 2)
			if len(parts) != 2 {
				continue
			}
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			if k == "" || v == "" {
				continue
			}
			out[k] = append(out[k], v)
		}
	}
	return out, nil
}

func lookupSeed(domain, number string) ([]string, error) {
	records, err := lookupSeedRecords(domain, number)
	if err != nil {
		return nil, err
	}
	return records["node"], nil
}

// normalizeMeshURL はDNSレコード等から取得したノードアドレスを
// /mesh エンドポイントの wss:// URL に正規化する。
// 既存のスキームやパスが含まれていても正しく処理する。
func normalizeMeshURL(addr string) string {
	addr = strings.TrimSpace(addr)
	// スキームがあれば除去
	for _, pfx := range []string{"wss://", "ws://", "https://", "http://"} {
		if strings.HasPrefix(addr, pfx) {
			addr = addr[len(pfx):]
			break
		}
	}
	// パスがあれば除去（ホスト:ポートだけ残す）
	if i := strings.Index(addr, "/"); i >= 0 {
		addr = addr[:i]
	}
	return "wss://" + addr + "/mesh"
}

// connectToNode はノードにWSS接続してnodesに登録する
func connectToNode(addr string) {
	nodesMu.Lock()
	if _, exists := nodes[addr]; exists {
		nodesMu.Unlock()
		return
	}
	nodesMu.Unlock()

	meshURL := normalizeMeshURL(addr)
	conn, _, err := websocket.DefaultDialer.Dial(meshURL, nil)
	if err != nil {
		log.Printf("failed to connect to node %s: %v", addr, err)
		return
	}

	node := &NodeConn{conn: conn}
	nodesMu.Lock()
	// ダイヤル中に別のgoroutineが同一アドレスを先に登録していた場合は重複接続を閉じる
	if _, exists := nodes[addr]; exists {
		nodesMu.Unlock()
		conn.Close()
		return
	}
	nodes[addr] = node
	nodesMu.Unlock()
	log.Printf("connected to node: %s", addr)

	// 切断監視
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				nodesMu.Lock()
				// 別の接続が同じアドレスで登録されていれば削除しない
				if cur, ok := nodes[addr]; ok && cur == node {
					delete(nodes, addr)
				}
				nodesMu.Unlock()
				log.Printf("node disconnected: %s", addr)
				return
			}
		}
	}()
}

// startSeedWatcher は起動時と1時間ごとにDNSシードを引いてノードに接続する
func startSeedWatcher(domain, number string) {
	refresh := func() {
		addrs, err := lookupSeed(domain, number)
		if err != nil {
			log.Println("seed lookup error:", err)
			return
		}
		for _, addr := range addrs {
			go connectToNode(addr)
		}
	}

	refresh()
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			refresh()
		}
	}()
}

// --- ハンドラー ---

// GET /pubkey/{番号}
func handleGetPubkey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	number := strings.TrimPrefix(r.URL.Path, "/pubkey/")
	_, pubkey, err := getUserByNumber(number)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"public_key": pubkey,
	})
}

// POST /account/lookup - 公開鍵から番号取得
func handleAccountLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	pubkey := body["public_key"]
	if pubkey == "" {
		http.Error(w, "missing public_key", http.StatusBadRequest)
		return
	}
	number, err := getUserByPublicKey(pubkey)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"number": number})
}

// POST /account/register - 新規登録
func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	email := body["email"]
	if email == "" {
		http.Error(w, "missing email", http.StatusBadRequest)
		return
	}

	token, err := generateToken()
	if err != nil {
		log.Printf("failed to generate token: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	tokensMu.Lock()
	putToken(emailVerifyTokens, token, email)
	tokensMu.Unlock()

	// メール送信
	subject := "Confirm your email"
	mailBody := fmt.Sprintf("Token: %s", token)
	if err := sendEmail(email, subject, mailBody); err != nil {
		log.Printf("failed to send email: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "confirmation email sent"})
}

// POST /account/verify-email - メール確認
func handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	token := body["token"]
	if token == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}

	tokensMu.RLock()
	email, ok := getTokenEmail(emailVerifyTokens, token)
	tokensMu.RUnlock()

	if !ok {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "email": email})
}

// POST /account/new - 新規作成（トークン + 公開鍵 → 番号返却）
func handleNew(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	token := body["token"]
	pubkey := body["public_key"]
	if token == "" || pubkey == "" {
		http.Error(w, "missing token or public_key", http.StatusBadRequest)
		return
	}

	email, ok := atomicConsumeToken(emailVerifyTokens, token)
	if !ok {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	number, err := createUser(email, pubkey)
	if err != nil {
		log.Printf("failed to create user: %v", err)
		http.Error(w, "creation failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"number": number})
}

// POST /account/reset-request - 再設定申請
func handleResetRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	email := body["email"]
	if email == "" {
		http.Error(w, "missing email", http.StatusBadRequest)
		return
	}

	exists, err := userExistsByEmail(email)
	if err != nil {
		log.Printf("failed to check email existence: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, "email not found", http.StatusNotFound)
		return
	}

	token, err := generateToken()
	if err != nil {
		log.Printf("failed to generate reset token: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	tokensMu.Lock()
	putToken(resetTokens, token, email)
	tokensMu.Unlock()

	subject := "Reset password"
	mailBody := fmt.Sprintf("Token: %s", token)
	if err := sendEmail(email, subject, mailBody); err != nil {
		log.Printf("failed to send email: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// POST /account/reset - 再設定実行
func handleReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	token := body["token"]
	pubkey := body["public_key"]
	if token == "" || pubkey == "" {
		http.Error(w, "missing token or public_key", http.StatusBadRequest)
		return
	}

	email, ok := atomicConsumeToken(resetTokens, token)
	if !ok {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	number, err := updatePublicKey(email, pubkey)
	if err != nil {
		log.Printf("failed to update public key: %v", err)
		http.Error(w, "reset failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"number": number, "status": "ok"})
}

// POST /sms/send
func handleSMSSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var msg Message
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if msg.Timestamp == 0 {
		msg.Timestamp = time.Now().UTC().Unix()
	}

	// 署名検証（送信者が正規ユーザーであることを確認）
	if err := verifyMessageSignature(&msg); err != nil {
		log.Printf("sms signature verification failed from=%s: %v", msg.From, err)
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	// DBに直接保存（ノード経由ではなく window が直接保存することでHTTP/TLSの
	// 不整合および ephemeral port 問題を回避する）
	var storeOut map[string]string
	if err := dbWSCall("messages.store", msg, &storeOut); err != nil {
		log.Printf("sms store failed to=%s: %v", msg.To, err)
		http.Error(w, "failed to store message", http.StatusInternalServerError)
		return
	}

	// ライブ配信のためにメッシュ経由でブロードキャスト（ベストエフォート）
	// ノード側はDB保存をせず、オンラインなら即配信するだけにする
	broadcastMsg, _ := json.Marshal(map[string]any{
		"type": "sms",
		"data": msg,
	})
	broadcast(broadcastMsg)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// POST /node/resolve - 番号からDNSを引いてランダムノードWS URLを返す
func handleNodeResolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	number := strings.TrimSpace(body["number"])
	if number == "" {
		http.Error(w, "missing number", http.StatusBadRequest)
		return
	}
	if seedDomain == "" {
		http.Error(w, "seed domain not configured", http.StatusServiceUnavailable)
		return
	}

	records, err := lookupSeedRecords(seedDomain, number)
	if err != nil {
		http.Error(w, "seed lookup failed", http.StatusServiceUnavailable)
		return
	}
	addrs := records["node"]
	windowAddrs := records["window"]
	if len(addrs) == 0 {
		http.Error(w, "no nodes found for number", http.StatusServiceUnavailable)
		return
	}

	wsURLs := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		switch {
		case strings.HasPrefix(addr, "ws://") || strings.HasPrefix(addr, "wss://"):
			wsURLs = append(wsURLs, addr)
		case strings.Contains(addr, "/"):
			wsURLs = append(wsURLs, "wss://"+addr)
		default:
			wsURLs = append(wsURLs, "wss://"+addr+"/ws")
		}
	}
	if len(wsURLs) == 0 {
		http.Error(w, "no valid node url", http.StatusServiceUnavailable)
		return
	}

	windowBases := make([]string, 0, len(windowAddrs))
	for _, addr := range windowAddrs {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		switch {
		case strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://"):
			windowBases = append(windowBases, addr)
		default:
			windowBases = append(windowBases, "https://"+addr)
		}
	}

	idx := 0
	if n, err := crand.Int(crand.Reader, big.NewInt(int64(len(wsURLs)))); err == nil {
		idx = int(n.Int64())
	}
	selected := wsURLs[idx]

	selectedWindow := ""
	if len(windowBases) > 0 {
		widx := 0
		if n, err := crand.Int(crand.Reader, big.NewInt(int64(len(windowBases)))); err == nil {
			widx = int(n.Int64())
		}
		selectedWindow = windowBases[widx]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"number":            number,
		"ws_url":            selected,
		"candidates":        wsURLs,
		"window_base":       selectedWindow,
		"window_candidates": windowBases,
	})
}

func handleICESignal(w http.ResponseWriter, r *http.Request, signalType string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	// 型アサーションで文字列を取得する。null や非文字列型は空文字として扱われる。
	from, _ := body["from"].(string)
	to, _ := body["to"].(string)
	if strings.TrimSpace(from) == "" || strings.TrimSpace(to) == "" {
		http.Error(w, "missing from or to", http.StatusBadRequest)
		return
	}
	msg, _ := json.Marshal(map[string]any{
		"type": signalType,
		"data": body,
	})
	broadcast(msg)
	w.WriteHeader(http.StatusOK)
}

// POST /ice/offer
func handleICEOffer(w http.ResponseWriter, r *http.Request) {
	handleICESignal(w, r, "ice_offer")
}

// POST /ice/answer
func handleICEAnswer(w http.ResponseWriter, r *http.Request) {
	handleICESignal(w, r, "ice_answer")
}

// POST /ice/candidate
func handleICECandidate(w http.ResponseWriter, r *http.Request) {
	handleICESignal(w, r, "ice_candidate")
}

// POST /call/auth-challenge
func handleCallAuthChallenge(w http.ResponseWriter, r *http.Request) {
	handleICESignal(w, r, "call_auth_challenge")
}

// POST /call/auth-response
func handleCallAuthResponse(w http.ResponseWriter, r *http.Request) {
	handleICESignal(w, r, "call_auth_response")
}

// POST /call/reject
func handleCallReject(w http.ResponseWriter, r *http.Request) {
	handleICESignal(w, r, "call_reject")
}

// POST /call/auth-ok
func handleCallAuthOK(w http.ResponseWriter, r *http.Request) {
	handleICESignal(w, r, "call_auth_ok")
}

// POST /call/hangup
func handleCallHangup(w http.ResponseWriter, r *http.Request) {
	handleICESignal(w, r, "call_hangup")
}

// WS /ws (ノードとの内部通信)
func handleNodeWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("ws upgrade error:", err)
		return
	}
	addr := r.RemoteAddr
	node := &NodeConn{conn: conn}
	nodesMu.Lock()
	nodes[addr] = node
	nodesMu.Unlock()
	log.Printf("node connected: %s", addr)

	defer func() {
		conn.Close()
		nodesMu.Lock()
		delete(nodes, addr)
		nodesMu.Unlock()
		log.Printf("node disconnected: %s", addr)
	}()

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			return
		}
	}
}

// --- メイン ---

func main() {
	initTokenConfig()
	startTokenSweeper()

	// DBサービス初期化
	if err := initDBService(); err != nil {
		log.Fatal(err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "30000"
	}
	certFile := os.Getenv("CERT_FILE")
	keyFile := os.Getenv("KEY_FILE")
	seedDomain = fixedSeedDomain
	routeNumber = os.Getenv("NUMBER") // 例: 02

	if seedDomain != "" && routeNumber != "" {
		startSeedWatcher(seedDomain, routeNumber)
	} else {
		log.Println("fixed seed domain or NUMBER not set, skipping DNS seed")
	}

	mux := http.NewServeMux()

	// アカウント管理API
	mux.HandleFunc("/pubkey/", handleGetPubkey)
	mux.HandleFunc("/account/lookup", handleAccountLookup)
	mux.HandleFunc("/account/register", handleRegister)
	mux.HandleFunc("/account/verify-email", handleVerifyEmail)
	mux.HandleFunc("/account/new", handleNew)
	mux.HandleFunc("/account/reset-request", handleResetRequest)
	mux.HandleFunc("/account/reset", handleReset)

	// SMS・内部通信
	mux.HandleFunc("/sms/send", handleSMSSend)
	mux.HandleFunc("/node/resolve", handleNodeResolve)
	mux.HandleFunc("/ice/offer", handleICEOffer)
	mux.HandleFunc("/ice/answer", handleICEAnswer)
	mux.HandleFunc("/ice/candidate", handleICECandidate)
	mux.HandleFunc("/call/auth-challenge", handleCallAuthChallenge)
	mux.HandleFunc("/call/auth-response", handleCallAuthResponse)
	mux.HandleFunc("/call/reject", handleCallReject)
	mux.HandleFunc("/call/auth-ok", handleCallAuthOK)
	mux.HandleFunc("/call/hangup", handleCallHangup)
	mux.HandleFunc("/ws", handleNodeWS)

	if certFile != "" && keyFile != "" {
		log.Println("window listening on :" + port + " (TLS)")
		if err := http.ListenAndServeTLS(":"+port, certFile, keyFile, corsMiddleware(mux)); err != nil {
			log.Fatal(err)
		}
	} else {
		log.Println("window listening on :" + port)
		if err := http.ListenAndServe(":"+port, corsMiddleware(mux)); err != nil {
			log.Fatal(err)
		}
	}
}
