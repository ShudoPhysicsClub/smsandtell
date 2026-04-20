package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var jwtSecret []byte

func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// verifyJWT は JWT を検証して subject（number）を返す。
func verifyJWT(token string) (string, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid token format")
	}
	msg := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, jwtSecret)
	mac.Write([]byte(msg))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return "", fmt.Errorf("invalid token signature")
	}
	payloadBytes, err := base64URLDecode(parts[1])
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

var dbServiceURL string
var dbServiceToken string
var windowAPIBase string
var dbWSConn *websocket.Conn
var dbWSMu sync.Mutex

const (
	dbWSRetries = 3
	dbWSTimeout = 5 * time.Second
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type ClientConn struct {
	conn   *websocket.Conn
	userID string
	mu     sync.Mutex
	authed bool
}

var (
	clients   = make(map[string]*ClientConn)
	clientsMu sync.RWMutex
)

// sendJSON は client.mu を保持した状態で WebSocket に JSON を書き込む。
// handleClientWS 内の直接 conn.WriteJSON 呼び出しと deliverOrStore / mesh relay の
// 並行書き込みを防ぐため、すべての送信はこのメソッドを経由する。
func (c *ClientConn) sendJSON(v any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.WriteJSON(v)
}

type Message struct {
	Timestamp int64           `json:"timestamp"`
	Message   json.RawMessage `json:"message"`
	To        string          `json:"to"`
	From      string          `json:"from"`
	Sig       string          `json:"sig"`
}

func initDBService() error {
	dbServiceURL = os.Getenv("DB_SERVICE_URL")
	if dbServiceURL == "" {
		return fmt.Errorf("DB_SERVICE_URL is required")
	}
	dbServiceToken = os.Getenv("DB_SERVICE_TOKEN")
	if dbServiceToken == "" {
		return fmt.Errorf("DB_SERVICE_TOKEN is required")
	}
	windowAPIBase = os.Getenv("WINDOW_API_BASE")
	if windowAPIBase == "" {
		return fmt.Errorf("WINDOW_API_BASE is required")
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

func getPublicKeyByNumber(number string) (string, error) {
	reqURL := strings.TrimRight(windowAPIBase, "/") + "/pubkey/" + url.PathEscape(number)
	resp, err := http.Get(reqURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("pubkey lookup failed: %s", strings.TrimSpace(string(body)))
	}
	var out struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.PublicKey == "" {
		return "", fmt.Errorf("empty public_key")
	}
	return out.PublicKey, nil
}

func verifyMessageSignature(msg *Message) error {
	if msg.From == "" || msg.To == "" || len(msg.Message) == 0 || msg.Timestamp == 0 || msg.Sig == "" {
		return fmt.Errorf("missing signed fields")
	}
	pubHex, err := getPublicKeyByNumber(msg.From)
	if err != nil {
		return err
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

func buildMessageSigningPayload(msg *Message) map[string]any {
	return map[string]any{
		"timestamp": msg.Timestamp,
		"message":   json.RawMessage(msg.Message),
		"to":        msg.To,
		"from":      msg.From,
	}
}

func consumeChallenge(userID, challenge string) bool {
	return false // チャレンジ認証は廃止（JWT認証に移行）
}

func verifyAuthSignature(userID, challenge, sigHex string) error {
	return fmt.Errorf("challenge-response auth is removed")
}

func saveMessage(msg *Message) error {
	var out map[string]string
	return dbWSCall("messages.store", msg, &out)
}

func popMessages(userID string) ([]Message, error) {
	var out struct {
		Messages []Message `json:"messages"`
	}
	if err := dbWSCall("messages.pop", map[string]string{"to": userID}, &out); err != nil {
		return nil, err
	}
	return out.Messages, nil
}

// deliverOrStore はオンラインなら即配信、オフラインならDBに保存する
func deliverOrStore(msg *Message) error {
	clientsMu.RLock()
	target, online := clients[msg.To]
	clientsMu.RUnlock()

	if online {
		target.mu.Lock()
		authed := target.authed
		if authed {
			err := target.conn.WriteJSON(map[string]any{
				"action":   "messages",
				"messages": []Message{*msg},
			})
			target.mu.Unlock()
			if err == nil {
				return nil // 配信成功 → DBに保存不要
			}
			log.Printf("deliver failed to %s, falling back to store: %v", msg.To, err)
		} else {
			target.mu.Unlock()
		}
	}

	// オフライン or 配信失敗 → DBに保存
	return saveMessage(msg)
}

var (
	challenges   = make(map[string]map[string]string)
	challengesMu sync.RWMutex
)

func startChallengeSweeper() {} // チャレンジ認証は廃止（JWT認証に移行）

func generateChallenge(userID string) (string, error) {
	return "", fmt.Errorf("challenge-response auth is removed")
}

func handleClientWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("ws upgrade error:", err)
		return
	}
	defer conn.Close()

	// 最初のメッセージで JWT 認証を行う
	var authMsg struct {
		Action string `json:"action"`
		Number string `json:"number"`
		Token  string `json:"token"`
	}
	if err := conn.ReadJSON(&authMsg); err != nil {
		log.Println("failed to read auth message:", err)
		return
	}
	if authMsg.Action != "auth" || authMsg.Token == "" {
		conn.WriteMessage(websocket.TextMessage, []byte(`{"error":"expected auth action with token"}`))
		return
	}

	// JWT 検証
	claimedNumber, err := verifyJWT(authMsg.Token)
	if err != nil {
		log.Printf("JWT verification failed: %v", err)
		conn.WriteMessage(websocket.TextMessage, []byte(`{"error":"auth failed"}`))
		return
	}

	// JWT の sub とリクエストの number が一致することを確認
	userIDStr := strings.TrimSpace(claimedNumber)
	if userIDStr == "" || len(userIDStr) > 128 {
		conn.WriteMessage(websocket.TextMessage, []byte(`{"error":"invalid user id"}`))
		return
	}
	if authMsg.Number != "" && strings.TrimSpace(authMsg.Number) != userIDStr {
		conn.WriteMessage(websocket.TextMessage, []byte(`{"error":"number mismatch"}`))
		return
	}

	client := &ClientConn{conn: conn, userID: userIDStr, authed: true}

	clientsMu.Lock()
	clients[userIDStr] = client
	clientsMu.Unlock()
	log.Printf("client connected: %s", userIDStr)

	defer func() {
		clientsMu.Lock()
		if clients[userIDStr] == client {
			delete(clients, userIDStr)
		}
		clientsMu.Unlock()
		log.Printf("client disconnected: %s", userIDStr)
	}()

	// 認証成功を通知し、保留メッセージを配信する
	if err := client.sendJSON(map[string]string{"status": "authenticated"}); err != nil {
		return
	}
	messages, err := popMessages(userIDStr)
	if err == nil && len(messages) > 0 {
		if err := client.sendJSON(map[string]any{"action": "messages", "messages": messages}); err != nil {
			log.Printf("failed to send cached messages: %v", err)
		}
	}

	for {
		var req map[string]interface{}
		if err := conn.ReadJSON(&req); err != nil {
			return
		}

		action, ok := req["action"].(string)
		if !ok {
			client.sendJSON(map[string]string{"error": "missing action"})
			continue
		}

		switch action {
		case "send_message":
			msgData, _ := json.Marshal(req["data"])
			var msg Message
			if err := json.Unmarshal(msgData, &msg); err != nil {
				client.sendJSON(map[string]string{"error": "invalid message"})
				continue
			}
			msg.From = userIDStr
			if err := verifyMessageSignature(&msg); err != nil {
				client.sendJSON(map[string]string{"error": "invalid signature"})
				continue
			}
			if err := deliverOrStore(&msg); err != nil {
				client.sendJSON(map[string]string{"error": "failed to save message"})
				continue
			}
			client.sendJSON(map[string]string{"status": "ok"})

		default:
			client.sendJSON(map[string]string{"error": "unknown action"})
		}
	}
}

func handleMeshWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("mesh ws upgrade error:", err)
		return
	}
	defer conn.Close()

	for {
		var msg struct {
			Type string         `json:"type"`
			Data map[string]any `json:"data"`
		}
		if err := conn.ReadJSON(&msg); err != nil {
			return
		}
		if msg.Type == "" || msg.Data == nil {
			continue
		}
		to, _ := msg.Data["to"].(string)
		to = strings.TrimSpace(to)
		if to == "" {
			continue
		}

		clientsMu.RLock()
		target, ok := clients[to]
		clientsMu.RUnlock()

		if msg.Type == "sms" {
			// SMS: windowがすでにDBに保存済みのため、ここではライブ配信のみ行う。
			// DB保存は window/handleSMSSend が責任を持つ。
			if ok {
				target.mu.Lock()
				authed := target.authed
				if authed {
					_ = target.conn.WriteJSON(map[string]any{"action": "messages", "messages": []map[string]any{msg.Data}})
				}
				target.mu.Unlock()
			}
			continue
		}

		// SMS以外（ice_offer等）: オンラインのクライアントにそのまま中継
		if !ok {
			continue
		}
		var relayErr error
		target.mu.Lock()
		authed := target.authed
		if authed {
			relayErr = target.conn.WriteJSON(map[string]any{"action": msg.Type, "data": msg.Data})
		}
		target.mu.Unlock()
		if relayErr != nil {
			log.Printf("mesh relay failed to %s: %v", to, relayErr)
		}
	}
}

// window から呼ばれる保存API（オンラインなら即配信、オフラインならDB保存）
func handleStoreMessage(w http.ResponseWriter, r *http.Request) {
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
	if err := verifyMessageSignature(&msg); err != nil {
		log.Printf("signature verification failed: %v", err)
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	if err := deliverOrStore(&msg); err != nil {
		log.Printf("failed to deliver/store message: %v", err)
		http.Error(w, "save failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func main() {
	jwtSecretStr := os.Getenv("JWT_SECRET")
	if jwtSecretStr == "" {
		log.Fatal("JWT_SECRET is required")
	}
	jwtSecret = []byte(jwtSecretStr)

	if err := initDBService(); err != nil {
		log.Fatal(err)
	}

	startChallengeSweeper()

	port := os.Getenv("PORT")
	if port == "" {
		port = "31000"
	}
	certFile := os.Getenv("CERT_FILE")
	keyFile := os.Getenv("KEY_FILE")

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", handleClientWS)
	mux.HandleFunc("/mesh", handleMeshWS)
	mux.HandleFunc("/store-message", handleStoreMessage)

	if certFile != "" && keyFile != "" {
		log.Println("node listening on :" + port + " (TLS)")
		if err := http.ListenAndServeTLS(":"+port, certFile, keyFile, mux); err != nil {
			log.Fatal(err)
		}
	} else {
		log.Println("node listening on :" + port)
		if err := http.ListenAndServe(":"+port, mux); err != nil {
			log.Fatal(err)
		}
	}
}