package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

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
	url := strings.TrimRight(windowAPIBase, "/") + "/pubkey/" + number
	resp, err := http.Get(url)
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
	challengesMu.Lock()
	defer challengesMu.Unlock()
	items, ok := challenges[userID]
	if !ok {
		return false
	}
	exp, ok := items[challenge]
	if !ok {
		return false
	}
	t, err := time.Parse(time.RFC3339, exp)
	if err != nil || time.Now().After(t) {
		delete(items, challenge)
		return false
	}
	delete(items, challenge)
	return true
}

func verifyAuthSignature(userID, challenge, sigHex string) error {
	if !consumeChallenge(userID, challenge) {
		return fmt.Errorf("invalid challenge")
	}
	pubHex, err := getPublicKeyByNumber(userID)
	if err != nil {
		return err
	}
	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil || len(pubBytes) != 64 {
		return fmt.Errorf("invalid public key encoding")
	}
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil || len(sigBytes) != 96 {
		return fmt.Errorf("invalid signature encoding")
	}
	payload := buildAuthSigningPayload(userID, challenge)
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

func buildAuthSigningPayload(number, challenge string) map[string]any {
	return map[string]any{"number": number, "challenge": challenge}
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

// startChallengeSweeper は期限切れチャレンジを定期的にメモリから削除する。
// 認証を完了しないままの接続が残した場合でもメモリリークしないようにする。
func startChallengeSweeper() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			challengesMu.Lock()
			for userID, items := range challenges {
				for ch, exp := range items {
					t, err := time.Parse(time.RFC3339, exp)
					if err != nil || now.After(t) {
						delete(items, ch)
					}
				}
				if len(items) == 0 {
					delete(challenges, userID)
				}
			}
			challengesMu.Unlock()
		}
	}()
}

func generateChallenge(userID string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	challenge := fmt.Sprintf("%x", b)

	challengesMu.Lock()
	if challenges[userID] == nil {
		challenges[userID] = make(map[string]string)
	}
	challenges[userID][challenge] = time.Now().Add(5 * time.Minute).Format(time.RFC3339)
	challengesMu.Unlock()

	return challenge, nil
}

func handleClientWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("ws upgrade error:", err)
		return
	}
	defer conn.Close()

	_, userIDBytes, err := conn.ReadMessage()
	if err != nil {
		log.Println("failed to read user id:", err)
		return
	}

	userIDStr := strings.TrimSpace(string(userIDBytes))
	client := &ClientConn{conn: conn, userID: userIDStr}

	clientsMu.Lock()
	clients[userIDStr] = client
	clientsMu.Unlock()
	log.Printf("client connected: %s", userIDStr)
	authenticated := false

	defer func() {
		clientsMu.Lock()
		delete(clients, userIDStr)
		clientsMu.Unlock()
		log.Printf("client disconnected: %s", userIDStr)
	}()

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
		case "challenge":
			challenge, _ := generateChallenge(userIDStr)
			client.sendJSON(map[string]string{"challenge": challenge})

		case "auth_verify":
			challenge, _ := req["challenge"].(string)
			sig, _ := req["sig"].(string)
			if challenge == "" || sig == "" {
				client.sendJSON(map[string]string{"error": "missing challenge or sig"})
				continue
			}
			if err := verifyAuthSignature(userIDStr, challenge, sig); err != nil {
				client.sendJSON(map[string]string{"error": "auth failed"})
				continue
			}
			authenticated = true
			client.mu.Lock()
			client.authed = true
			client.mu.Unlock()
			client.sendJSON(map[string]string{"status": "authenticated"})

			messages, err := popMessages(userIDStr)
			if err == nil && len(messages) > 0 {
				if err := client.sendJSON(map[string]interface{}{"action": "messages", "messages": messages}); err != nil {
					log.Printf("failed to send cached messages: %v", err)
				}
			}

		case "send_message":
			if !authenticated {
				client.sendJSON(map[string]string{"error": "not authenticated"})
				continue
			}
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
		target.mu.Lock()
		authed := target.authed
		if authed {
			err = target.conn.WriteJSON(map[string]any{"action": msg.Type, "data": msg.Data})
		}
		target.mu.Unlock()
		if err != nil {
			log.Printf("mesh relay failed to %s: %v", to, err)
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