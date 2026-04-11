// client_ws.go - クライアントのWebSocket接続管理の実装
// WS /connect エンドポイントでクライアントの常時接続を管理する
// クライアントは登録メッセージでセッション認証を行い、SMS/ICEメッセージを受信する
package node

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

// WebSocketアップグレーダーの設定
// すべてのオリジンを許可（デモ用）
var clientUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// clientConn はクライアントのWebSocket接続を表す構造体
type clientConn struct {
	// WebSocket接続
	conn *websocket.Conn
	// クライアントの電話番号
	phone string
	// ICEキャッシュ（接続時にクライアントから受け取ったICE候補）
	iceCache []string
	// 送信チャネル
	send chan []byte
}

// クライアント接続の管理
var (
	// 電話番号 → clientConn のマップ
	clients   = make(map[string]*clientConn)
	clientsMu sync.RWMutex
)

// registerMessage はクライアント登録メッセージのJSON構造体
type registerMessage struct {
	Type     string   `json:"type"`
	Phone    string   `json:"phone"`
	Token    string   `json:"token"`
	IceCache []string `json:"ice_cache"`
}

// incomingMessage はクライアントから受信するメッセージの型識別用構造体
type incomingMessage struct {
	Type string `json:"type"`
}

// iceAnswerMessage はICE answerメッセージのJSON構造体（クライアント→ノード）
type iceAnswerMessage struct {
	Type       string   `json:"type"`
	CallID     string   `json:"call_id"`
	SDPAnswer  string   `json:"sdp_answer"`
	Candidates []string `json:"candidates"`
}

// HandleClientWS は WS /connect エンドポイントのハンドラー
// クライアントのWebSocket接続を受け付けて登録・メッセージ処理を行う
func HandleClientWS(w http.ResponseWriter, r *http.Request) {
	// WebSocketにアップグレード
	conn, err := clientUpgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Printf("[クライアントWS] アップグレード失敗: %v\n", err)
		return
	}

	cc := &clientConn{
		conn: conn,
		send: make(chan []byte, 256),
	}

	// 最初のメッセージで登録処理を実施
	_, rawMsg, err := conn.ReadMessage()
	if err != nil {
		fmt.Printf("[クライアントWS] 登録メッセージ受信失敗: %v\n", err)
		conn.Close()
		return
	}

	var reg registerMessage
	if err := json.Unmarshal(rawMsg, &reg); err != nil || reg.Type != "register" {
		fmt.Printf("[クライアントWS] 無効な登録メッセージ\n")
		conn.Close()
		return
	}

	// セッショントークンを検証（ゲートウェイのセッションストアは共有しないためノード内で簡易検証）
	// デモ用: トークンが空でない場合は許可
	if reg.Token == "" {
		fmt.Printf("[クライアントWS] トークンが空です\n")
		conn.Close()
		return
	}

	cc.phone = reg.Phone
	cc.iceCache = reg.IceCache

	// クライアントを登録
	clientsMu.Lock()
	// 既存の接続がある場合は切断
	if old, exists := clients[reg.Phone]; exists {
		close(old.send)
	}
	clients[reg.Phone] = cc
	clientsMu.Unlock()

	fmt.Printf("[クライアントWS] クライアント登録: phone=%s iceCache=%d件\n", reg.Phone, len(cc.iceCache))

	// 送信ゴルーチンを起動
	go cc.clientWritePump()

	// 受信ループ（ice_answerなどのメッセージを処理）
	cc.clientReadPump()

	// 接続切断時にクライアントを削除
	clientsMu.Lock()
	if c, exists := clients[reg.Phone]; exists && c == cc {
		delete(clients, reg.Phone)
	}
	clientsMu.Unlock()
	fmt.Printf("[クライアントWS] クライアント切断: phone=%s\n", reg.Phone)
}

// clientReadPump はクライアントからのメッセージを受信して処理する
func (cc *clientConn) clientReadPump() {
	defer cc.conn.Close()
	for {
		_, rawMsg, err := cc.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				fmt.Printf("[クライアントWS] 受信エラー phone=%s: %v\n", cc.phone, err)
			}
			break
		}

		// メッセージタイプを識別
		var base incomingMessage
		if err := json.Unmarshal(rawMsg, &base); err != nil {
			continue
		}

		switch base.Type {
		case "ice_answer":
			// ICE answerをメッシュ経由で発信側ノードに転送
			var ans iceAnswerMessage
			if err := json.Unmarshal(rawMsg, &ans); err != nil {
				continue
			}
			fmt.Printf("[クライアントWS] ICE answer受信: phone=%s callID=%s\n", cc.phone, ans.CallID)
			// メッシュ経由でブロードキャスト
			BroadcastToMesh(rawMsg)
		default:
			fmt.Printf("[クライアントWS] 未知のメッセージタイプ: type=%s\n", base.Type)
		}
	}
}

// clientWritePump はsendチャネルからメッセージを取得してクライアントに送信する
func (cc *clientConn) clientWritePump() {
	defer cc.conn.Close()
	for msg := range cc.send {
		if err := cc.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			fmt.Printf("[クライアントWS] 送信エラー phone=%s: %v\n", cc.phone, err)
			return
		}
	}
}

// DeliverToClient は指定した電話番号のクライアントにメッセージを配信する
// 該当クライアントが接続中の場合はtrueを返す
func DeliverToClient(phone string, data []byte) bool {
	clientsMu.RLock()
	cc, exists := clients[phone]
	clientsMu.RUnlock()
	if !exists {
		return false
	}
	select {
	case cc.send <- data:
		return true
	default:
		// 送信バッファが満杯の場合はスキップ
		fmt.Printf("[クライアントWS] 送信バッファ満杯: phone=%s\n", phone)
		return false
	}
}

// GetClientICECache は指定した電話番号のクライアントのICEキャッシュを返す
func GetClientICECache(phone string) []string {
	clientsMu.RLock()
	defer clientsMu.RUnlock()
	if cc, exists := clients[phone]; exists {
		return cc.iceCache
	}
	return nil
}
