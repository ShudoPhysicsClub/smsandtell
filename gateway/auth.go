// auth.go - 認証エンドポイントの実装
// POST /auth/challenge: チャレンジノンスの発行
// POST /auth/verify: Schnorr署名検証とセッショントークン発行
package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
)

// challengeEntry はチャレンジの情報を保持する構造体
type challengeEntry struct {
	// チャレンジノンス（16進数）
	Nonce string
	// 電話番号
	Phone string
	// 有効期限（Unixタイムスタンプ）
	ExpiresAt int64
}

// セッションとチャレンジのインメモリストア
var (
	// チャレンジストア: phone → challengeEntry
	challengeStore = make(map[string]challengeEntry)
	challengeMu    sync.RWMutex

	// セッションストア: token → phone
	sessionStore = make(map[string]string)
	sessionMu    sync.RWMutex
)

// チャレンジの有効期限（5分）
const challengeTTL = 5 * 60

// challengeRequest はチャレンジリクエストのJSON構造体
type challengeRequest struct {
	Phone string `json:"phone"`
}

// challengeResponse はチャレンジレスポンスのJSON構造体
type challengeResponse struct {
	Challenge string `json:"challenge"`
	Expires   int64  `json:"expires"`
}

// verifyRequest はSchnorr署名検証リクエストのJSON構造体
type verifyRequest struct {
	Phone     string      `json:"phone"`
	PubKey    SchnorrPubKey `json:"pubkey"`
	Sig       sigFields   `json:"sig"`
	Challenge string      `json:"challenge"`
}

// sigFields はSchnorr署名の各フィールドを保持する構造体
type sigFields struct {
	Rx string `json:"rx"`
	Ry string `json:"ry"`
	S  string `json:"s"`
}

// verifyResponse はセッショントークン発行レスポンスのJSON構造体
type verifyResponse struct {
	Token string   `json:"token"`
	Nodes []string `json:"nodes"`
}

// HandleChallenge は POST /auth/challenge エンドポイントのハンドラー
// 電話番号に対してランダムなノンスを生成して返す
func HandleChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POSTメソッドのみ対応")
		return
	}

	var req challengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "リクエストのデコード失敗")
		return
	}
	if req.Phone == "" {
		writeError(w, http.StatusBadRequest, "電話番号が必要です")
		return
	}

	// 32バイトのランダムノンスを生成
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		writeError(w, http.StatusInternalServerError, "ノンス生成失敗")
		return
	}
	nonce := hex.EncodeToString(nonceBytes)
	expiresAt := time.Now().Unix() + challengeTTL

	// チャレンジをインメモリに保存
	challengeMu.Lock()
	challengeStore[req.Phone] = challengeEntry{
		Nonce:     nonce,
		Phone:     req.Phone,
		ExpiresAt: expiresAt,
	}
	challengeMu.Unlock()

	fmt.Printf("[認証] チャレンジ発行: phone=%s\n", req.Phone)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(challengeResponse{
		Challenge: nonce,
		Expires:   expiresAt,
	})
}

// HandleVerify は POST /auth/verify エンドポイントのハンドラー
// Schnorr署名を検証してセッショントークンを発行する
func HandleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POSTメソッドのみ対応")
		return
	}

	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "リクエストのデコード失敗")
		return
	}

	// チャレンジの存在と有効期限を確認
	challengeMu.RLock()
	entry, exists := challengeStore[req.Phone]
	challengeMu.RUnlock()

	if !exists {
		writeError(w, http.StatusUnauthorized, "チャレンジが見つかりません")
		return
	}
	if time.Now().Unix() > entry.ExpiresAt {
		writeError(w, http.StatusUnauthorized, "チャレンジの有効期限切れ")
		return
	}
	if entry.Nonce != req.Challenge {
		writeError(w, http.StatusUnauthorized, "チャレンジが一致しません")
		return
	}

	// 署名対象メッセージを構成: challenge || timestamp || phone_number
	timestamp := fmt.Sprintf("%d", entry.ExpiresAt-challengeTTL)
	msg := []byte(req.Challenge + timestamp + req.Phone)

	// Schnorr署名を検証
	valid, err := SchnorrVerify(req.PubKey, req.Sig.Rx, req.Sig.Ry, req.Sig.S, msg)
	if err != nil {
		writeError(w, http.StatusBadRequest, "署名検証エラー: "+err.Error())
		return
	}
	if !valid {
		writeError(w, http.StatusUnauthorized, "署名が無効です")
		return
	}

	// セッショントークンを生成して保存
	token := uuid.New().String()
	sessionMu.Lock()
	sessionStore[token] = req.Phone
	sessionMu.Unlock()

	// 使用済みチャレンジを削除
	challengeMu.Lock()
	delete(challengeStore, req.Phone)
	challengeMu.Unlock()

	fmt.Printf("[認証] セッション発行: phone=%s token=%s\n", req.Phone, token)

	// 接続可能なノードリストを返す
	nodes := GetNodeList()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(verifyResponse{
		Token: token,
		Nodes: nodes,
	})
}

// ValidateToken はセッショントークンを検証して電話番号を返す
// トークンが無効な場合は空文字列を返す
func ValidateToken(token string) string {
	sessionMu.RLock()
	defer sessionMu.RUnlock()
	return sessionStore[token]
}

// writeError はJSONエラーレスポンスを書き込む
func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// extractBearerToken はAuthorizationヘッダーからBearerトークンを抽出する
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return ""
}
