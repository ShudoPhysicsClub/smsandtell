package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/websocket"
)

var db *sql.DB
var serviceNumber string
var dbServiceToken string
var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

type Message struct {
	ID        int64           `json:"id,omitempty"`
	Timestamp int64           `json:"timestamp"`
	Message   json.RawMessage `json:"message"`
	To        string          `json:"to"`
	From      string          `json:"from"`
	Sig       string          `json:"sig"`
}

func initDB() error {
	dbName := os.Getenv("DATABASE_NAME")
	dbUser := os.Getenv("DATABASE_USER")
	dbPass := os.Getenv("DATABASE_PASSWORD")
	dbAddr := os.Getenv("DATABASE_ADDRESS")

	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s?parseTime=true", dbUser, dbPass, dbAddr, dbName)
	var err error
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("failed to open db: %w", err)
	}
	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping db: %w", err)
	}
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS messages (
		id BIGINT PRIMARY KEY AUTO_INCREMENT,
		timestamp BIGINT NOT NULL,
		received_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		message JSON NOT NULL,
		to_user VARCHAR(128) NOT NULL,
		from_user VARCHAR(128) NOT NULL,
		sig TEXT NOT NULL,
		INDEX idx_received_at (received_at),
		INDEX idx_to_user (to_user)
	)
	`)
	if err != nil {
		return err
	}
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		email VARCHAR(255) PRIMARY KEY,
		number VARCHAR(128) UNIQUE NOT NULL,
		public_key CHAR(128) NOT NULL,
		password_hash VARCHAR(255) NOT NULL DEFAULT '',
		encrypted_key TEXT NOT NULL DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		INDEX idx_number (number),
		INDEX idx_pubkey (public_key)
	)
	`)
	if err != nil {
		return err
	}
	// 既存テーブルへのカラム追加（移行対応）
	for _, col := range []string{
		"ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255) NOT NULL DEFAULT ''",
		"ALTER TABLE users ADD COLUMN IF NOT EXISTS encrypted_key TEXT NOT NULL DEFAULT ''",
	} {
		if _, err := db.Exec(col); err != nil {
			// 既にカラムが存在する場合は無視する（MySQL 8.0 以前は IF NOT EXISTS 非対応）
			_ = err
		}
	}
	if err != nil {
		return err
	}
	return nil
}

func generateUserNumber(route string) (string, error) {
	prefix := strings.TrimSpace(route)
	if prefix == "" {
		prefix = serviceNumber
	}
	for {
		candidate := fmt.Sprintf("%s-%06d", prefix, time.Now().UTC().UnixNano()%1000000)
		var exists int
		err := db.QueryRow("SELECT COUNT(*) FROM users WHERE number = ?", candidate).Scan(&exists)
		if err != nil {
			return "", err
		}
		if exists == 0 {
			return candidate, nil
		}
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "number": serviceNumber})
}

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
	_, err := db.Exec(
		"INSERT INTO messages (timestamp, message, to_user, from_user, sig) VALUES (?, ?, ?, ?, ?)",
		msg.Timestamp, string(msg.Message), msg.To, msg.From, msg.Sig,
	)
	if err != nil {
		http.Error(w, "insert failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleGetUserByNumber(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Number string `json:"number"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.Number == "" {
		http.Error(w, "missing number", http.StatusBadRequest)
		return
	}
	var email, pubkey string
	if err := db.QueryRow("SELECT email, public_key FROM users WHERE number = ?", req.Number).Scan(&email, &pubkey); err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"email": email, "public_key": pubkey})
}

func handleGetUserByPubkey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.PublicKey == "" {
		http.Error(w, "missing public_key", http.StatusBadRequest)
		return
	}
	var number string
	if err := db.QueryRow("SELECT number FROM users WHERE public_key = ?", req.PublicKey).Scan(&number); err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"number": number})
}

func handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Email     string `json:"email"`
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.Email == "" || req.PublicKey == "" {
		http.Error(w, "missing email or public_key", http.StatusBadRequest)
		return
	}
	number, err := generateUserNumber("")
	if err != nil {
		http.Error(w, "failed to generate number", http.StatusInternalServerError)
		return
	}
	if _, err := db.Exec("INSERT INTO users (email, number, public_key) VALUES (?, ?, ?)", req.Email, number, req.PublicKey); err != nil {
		http.Error(w, "create failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"number": number})
}

func handleExistsEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.Email == "" {
		http.Error(w, "missing email", http.StatusBadRequest)
		return
	}
	var exists int
	if err := db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ?", req.Email).Scan(&exists); err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"exists": exists > 0})
}

func handleUpdatePubkey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Email     string `json:"email"`
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.Email == "" || req.PublicKey == "" {
		http.Error(w, "missing email or public_key", http.StatusBadRequest)
		return
	}
	var number string
	if err := db.QueryRow("SELECT number FROM users WHERE email = ?", req.Email).Scan(&number); err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	if _, err := db.Exec("UPDATE users SET public_key = ? WHERE email = ?", req.PublicKey, req.Email); err != nil {
		http.Error(w, "update failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"number": number})
}

func handlePopMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		To string `json:"to"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.To == "" {
		http.Error(w, "missing to", http.StatusBadRequest)
		return
	}

	tx, err := db.Begin()
	if err != nil {
		http.Error(w, "tx failed", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	rows, err := tx.Query(
		"SELECT id, timestamp, message, to_user, from_user, sig FROM messages WHERE to_user = ? ORDER BY timestamp ASC FOR UPDATE",
		req.To,
	)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	messages := make([]Message, 0)
	for rows.Next() {
		var msg Message
		var msgJSON string
		if err := rows.Scan(&msg.ID, &msg.Timestamp, &msgJSON, &msg.To, &msg.From, &msg.Sig); err != nil {
			http.Error(w, "scan failed", http.StatusInternalServerError)
			return
		}
		msg.Message = json.RawMessage(msgJSON)
		messages = append(messages, msg)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "rows failed", http.StatusInternalServerError)
		return
	}

	if len(messages) > 0 {
		if _, err := tx.Exec("DELETE FROM messages WHERE to_user = ?", req.To); err != nil {
			http.Error(w, "delete failed", http.StatusInternalServerError)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		http.Error(w, "commit failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"messages": messages})
}

func startCleanup() {
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			res, err := db.Exec("DELETE FROM messages WHERE received_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL 3 DAY)")
			if err != nil {
				log.Printf("cleanup error: %v", err)
				continue
			}
			if n, _ := res.RowsAffected(); n > 0 {
				log.Printf("cleanup deleted %d messages", n)
			}
		}
	}()
}

func writeWSError(conn *websocket.Conn, msg string) {
	_ = conn.WriteJSON(map[string]any{"ok": false, "error": msg})
}

func handleDBWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("db ws upgrade error: %v", err)
		return
	}
	defer conn.Close()

	for {
		var req struct {
			Action string          `json:"action"`
			Data   json.RawMessage `json:"data"`
			Token  string          `json:"token"`
		}
		if err := conn.ReadJSON(&req); err != nil {
			return
		}
		if req.Token != dbServiceToken {
			writeWSError(conn, "unauthorized")
			continue
		}

		switch req.Action {
		case "health":
			_ = conn.WriteJSON(map[string]any{"ok": true, "data": map[string]string{"status": "ok", "number": serviceNumber}})

		case "messages.store":
			var msg Message
			if err := json.Unmarshal(req.Data, &msg); err != nil {
				writeWSError(conn, "invalid data")
				continue
			}
			if msg.Timestamp == 0 {
				msg.Timestamp = time.Now().UTC().Unix()
			}
			_, err := db.Exec(
				"INSERT INTO messages (timestamp, message, to_user, from_user, sig) VALUES (?, ?, ?, ?, ?)",
				msg.Timestamp, string(msg.Message), msg.To, msg.From, msg.Sig,
			)
			if err != nil {
				writeWSError(conn, "insert failed")
				continue
			}
			_ = conn.WriteJSON(map[string]any{"ok": true, "data": map[string]string{"status": "ok"}})

		case "messages.pop":
			var in struct {
				To string `json:"to"`
			}
			if err := json.Unmarshal(req.Data, &in); err != nil || in.To == "" {
				writeWSError(conn, "missing to")
				continue
			}

			tx, err := db.Begin()
			if err != nil {
				writeWSError(conn, "tx failed")
				continue
			}

			rows, err := tx.Query(
				"SELECT id, timestamp, message, to_user, from_user, sig FROM messages WHERE to_user = ? ORDER BY timestamp ASC FOR UPDATE",
				in.To,
			)
			if err != nil {
				_ = tx.Rollback()
				writeWSError(conn, "query failed")
				continue
			}

			messages := make([]Message, 0)
			var scanErr error
			for rows.Next() {
				var m Message
				var msgJSON string
				if err := rows.Scan(&m.ID, &m.Timestamp, &msgJSON, &m.To, &m.From, &m.Sig); err != nil {
					scanErr = err
					break // continue→breakに変更: ロールバック済みtxの再利用を防ぐ
				}
				m.Message = json.RawMessage(msgJSON)
				messages = append(messages, m)
			}
			rows.Close()
			if scanErr != nil {
				_ = tx.Rollback()
				writeWSError(conn, "scan failed")
				continue // 外側のforループを正しく継続する
			}
			if err := rows.Err(); err != nil {
				_ = tx.Rollback()
				writeWSError(conn, "rows error")
				continue
			}

			if len(messages) > 0 {
				if _, err := tx.Exec("DELETE FROM messages WHERE to_user = ?", in.To); err != nil {
					_ = tx.Rollback()
					writeWSError(conn, "delete failed")
					continue
				}
			}
			if err := tx.Commit(); err != nil {
				writeWSError(conn, "commit failed")
				continue
			}
			_ = conn.WriteJSON(map[string]any{"ok": true, "data": map[string]any{"messages": messages}})

		case "users.getByNumber":
			var in struct {
				Number string `json:"number"`
			}
			if err := json.Unmarshal(req.Data, &in); err != nil || in.Number == "" {
				writeWSError(conn, "missing number")
				continue
			}
			var email, pubkey string
			if err := db.QueryRow("SELECT email, public_key FROM users WHERE number = ?", in.Number).Scan(&email, &pubkey); err != nil {
				writeWSError(conn, "user not found")
				continue
			}
			_ = conn.WriteJSON(map[string]any{"ok": true, "data": map[string]string{"email": email, "public_key": pubkey}})

		case "users.getByPubkey":
			var in struct {
				PublicKey string `json:"public_key"`
			}
			if err := json.Unmarshal(req.Data, &in); err != nil || in.PublicKey == "" {
				writeWSError(conn, "missing public_key")
				continue
			}
			var number string
			if err := db.QueryRow("SELECT number FROM users WHERE public_key = ?", in.PublicKey).Scan(&number); err != nil {
				writeWSError(conn, "user not found")
				continue
			}
			_ = conn.WriteJSON(map[string]any{"ok": true, "data": map[string]string{"number": number}})

		case "users.create":
			var in struct {
				Email        string `json:"email"`
				PublicKey    string `json:"public_key"`
				Route        string `json:"route"`
				PasswordHash string `json:"password_hash"`
				EncryptedKey string `json:"encrypted_key"`
			}
			if err := json.Unmarshal(req.Data, &in); err != nil || in.Email == "" || in.PublicKey == "" {
				writeWSError(conn, "missing email or public_key")
				continue
			}
			number, err := generateUserNumber(in.Route)
			if err != nil {
				writeWSError(conn, "failed to generate number")
				continue
			}
			if _, err := db.Exec(
				"INSERT INTO users (email, number, public_key, password_hash, encrypted_key) VALUES (?, ?, ?, ?, ?)",
				in.Email, number, in.PublicKey, in.PasswordHash, in.EncryptedKey,
			); err != nil {
				writeWSError(conn, "create failed")
				continue
			}
			_ = conn.WriteJSON(map[string]any{"ok": true, "data": map[string]string{"number": number}})

		case "users.existsEmail":
			var in struct {
				Email string `json:"email"`
			}
			if err := json.Unmarshal(req.Data, &in); err != nil || in.Email == "" {
				writeWSError(conn, "missing email")
				continue
			}
			var exists int
			if err := db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ?", in.Email).Scan(&exists); err != nil {
				writeWSError(conn, "query failed")
				continue
			}
			_ = conn.WriteJSON(map[string]any{"ok": true, "data": map[string]bool{"exists": exists > 0}})

		case "users.updatePubkey":
			var in struct {
				Email        string `json:"email"`
				PublicKey    string `json:"public_key"`
				PasswordHash string `json:"password_hash"`
				EncryptedKey string `json:"encrypted_key"`
			}
			if err := json.Unmarshal(req.Data, &in); err != nil || in.Email == "" || in.PublicKey == "" {
				writeWSError(conn, "missing email or public_key")
				continue
			}
			var number string
			if err := db.QueryRow("SELECT number FROM users WHERE email = ?", in.Email).Scan(&number); err != nil {
				writeWSError(conn, "user not found")
				continue
			}
			if _, err := db.Exec(
				"UPDATE users SET public_key = ?, password_hash = ?, encrypted_key = ? WHERE email = ?",
				in.PublicKey, in.PasswordHash, in.EncryptedKey, in.Email,
			); err != nil {
				writeWSError(conn, "update failed")
				continue
			}
			_ = conn.WriteJSON(map[string]any{"ok": true, "data": map[string]string{"number": number}})

		case "users.getAuthInfo":
			var in struct {
				Email string `json:"email"`
			}
			if err := json.Unmarshal(req.Data, &in); err != nil || in.Email == "" {
				writeWSError(conn, "missing email")
				continue
			}
			var number, pubkey, passwordHash, encryptedKey string
			if err := db.QueryRow(
				"SELECT number, public_key, password_hash, encrypted_key FROM users WHERE email = ?",
				in.Email,
			).Scan(&number, &pubkey, &passwordHash, &encryptedKey); err != nil {
				writeWSError(conn, "user not found")
				continue
			}
			_ = conn.WriteJSON(map[string]any{"ok": true, "data": map[string]string{
				"number":        number,
				"public_key":    pubkey,
				"password_hash": passwordHash,
				"encrypted_key": encryptedKey,
			}})

		default:
			writeWSError(conn, "unknown action")
		}
	}
}

func main() {
	serviceNumber = os.Getenv("NUMBER")
	if serviceNumber == "" {
		serviceNumber = "01"
	}
	dbServiceToken = os.Getenv("DB_SERVICE_TOKEN")
	if dbServiceToken == "" {
		log.Fatal("DB_SERVICE_TOKEN is required")
	}

	if err := initDB(); err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	startCleanup()

	port := os.Getenv("PORT")
	if port == "" {
		port = "32000"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/ws", handleDBWS)
	mux.HandleFunc("/messages/store", handleStoreMessage)
	mux.HandleFunc("/messages/pop", handlePopMessages)
	mux.HandleFunc("/users/get-by-number", handleGetUserByNumber)
	mux.HandleFunc("/users/get-by-pubkey", handleGetUserByPubkey)
	mux.HandleFunc("/users/create", handleCreateUser)
	mux.HandleFunc("/users/exists-email", handleExistsEmail)
	mux.HandleFunc("/users/update-pubkey", handleUpdatePubkey)

	log.Printf("db service #%s listening on :%s", serviceNumber, port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}
