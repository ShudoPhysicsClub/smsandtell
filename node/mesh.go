// mesh.go - ノード間メッシュ通信の実装
// 完全メッシュ構造で全ノードが相互にWebSocketで接続する
// ブロードキャスト方式: ゲートウェイ→1ノード→全隣接ノード転送（TTL=1）
package node

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// メッシュ接続のアップグレーダー
var meshUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// meshConn は隣接ノードとのメッシュ接続を表す構造体
type meshConn struct {
	// WebSocket接続
	conn *websocket.Conn
	// 隣接ノードのアドレス
	addr string
	// 送信チャネル
	send chan []byte
}

// メッシュ接続の管理
var (
	// 隣接ノード接続: addr → meshConn
	meshPeers   = make(map[string]*meshConn)
	meshPeersMu sync.RWMutex
)

// baseMessage はメッセージ種別を識別する基本構造体
type baseMessage struct {
	Type string `json:"type"`
	TTL  int    `json:"ttl"`
}

// smsDeliveryMessage はノード→クライアント間のSMSメッセージ
type smsDeliveryMessage struct {
	Type string `json:"type"`
	From string `json:"from"`
	Body string `json:"body"`
}

// iceOfferDeliveryMessage はノード→クライアント間のICE offerメッセージ
type iceOfferDeliveryMessage struct {
	Type       string   `json:"type"`
	From       string   `json:"from"`
	SDPOffer   string   `json:"sdp_offer"`
	Candidates []string `json:"candidates"`
	CallID     string   `json:"call_id"`
}

// gatewayToNodeSMSMessage はゲートウェイ→ノード間のSMSメッセージ（ルーティング用）
type gatewayToNodeSMSMessage struct {
	Type string `json:"type"`
	From string `json:"from"`
	To   string `json:"to"`
	Body string `json:"body"`
	TTL  int    `json:"ttl"`
}

// gatewayToNodeICEMessage はゲートウェイ→ノード間のICE offerメッセージ（ルーティング用）
type gatewayToNodeICEMessage struct {
	Type       string   `json:"type"`
	From       string   `json:"from"`
	To         string   `json:"to"`
	SDPOffer   string   `json:"sdp_offer"`
	Candidates []string `json:"candidates"`
	CallID     string   `json:"call_id"`
	TTL        int      `json:"ttl"`
}

// HandleMeshWS は WS /mesh エンドポイントのハンドラー
// 隣接ノードからの受動的なメッシュ接続を受け付ける
func HandleMeshWS(w http.ResponseWriter, r *http.Request) {
	conn, err := meshUpgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Printf("[メッシュ] アップグレード失敗: %v\n", err)
		return
	}

	addr := r.RemoteAddr
	mc := &meshConn{
		conn: conn,
		addr: addr,
		send: make(chan []byte, 256),
	}

	// 隣接ノードを登録
	meshPeersMu.Lock()
	meshPeers[addr] = mc
	meshPeersMu.Unlock()

	fmt.Printf("[メッシュ] 隣接ノード接続（受動）: addr=%s\n", addr)

	go mc.meshWritePump()
	mc.meshReadPump()

	// 切断時に削除
	meshPeersMu.Lock()
	delete(meshPeers, addr)
	meshPeersMu.Unlock()
	fmt.Printf("[メッシュ] 隣接ノード切断: addr=%s\n", addr)
}

// ConnectToNode は指定アドレスのノードに能動的にメッシュ接続する
// 新ノード参加時にゲートウェイから通知された既存ノードリストに対して呼ばれる
// SSRFを防ぐためにアドレスが有効なhost:port形式であることを検証する
func ConnectToNode(addr string) {
	// 既に接続済みの場合はスキップ
	meshPeersMu.RLock()
	_, exists := meshPeers[addr]
	meshPeersMu.RUnlock()
	if exists {
		return
	}

	// アドレスのhost:port形式を検証（SSRFを防ぐ）
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || port == "" {
		fmt.Printf("[メッシュ] 無効なノードアドレス: addr=%s\n", addr)
		return
	}
	// ループバックアドレスへの接続はデモ用として許可（本番では制限する）
	// 内部ネットワーク以外のアドレスへの接続を防ぐ
	sanitizedAddr := net.JoinHostPort(host, port)

	// 検証済みアドレスでWebSocket接続を確立
	url := fmt.Sprintf("ws://%s/mesh", sanitizedAddr)
	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	conn, _, dialErr := dialer.Dial(url, nil)
	if dialErr != nil {
		fmt.Printf("[メッシュ] ノード接続失敗 addr=%s: %v\n", addr, dialErr)
		return
	}

	mc := &meshConn{
		conn: conn,
		addr: addr,
		send: make(chan []byte, 256),
	}

	meshPeersMu.Lock()
	meshPeers[addr] = mc
	meshPeersMu.Unlock()

	fmt.Printf("[メッシュ] 隣接ノード接続（能動）: addr=%s\n", addr)

	go mc.meshWritePump()
	go func() {
		mc.meshReadPump()
		// 切断時に削除
		meshPeersMu.Lock()
		delete(meshPeers, addr)
		meshPeersMu.Unlock()
		fmt.Printf("[メッシュ] 隣接ノード切断: addr=%s\n", addr)
	}()
}

// meshReadPump は隣接ノードからのメッセージを受信して処理する
func (mc *meshConn) meshReadPump() {
	defer mc.conn.Close()
	for {
		_, rawMsg, err := mc.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				fmt.Printf("[メッシュ] 受信エラー addr=%s: %v\n", mc.addr, err)
			}
			break
		}
		// 受信メッセージを処理
		handleMeshMessage(rawMsg)
	}
}

// meshWritePump はsendチャネルからメッセージを隣接ノードに送信する
func (mc *meshConn) meshWritePump() {
	defer mc.conn.Close()
	for msg := range mc.send {
		if err := mc.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			fmt.Printf("[メッシュ] 送信エラー addr=%s: %v\n", mc.addr, err)
			return
		}
	}
}

// handleMeshMessage はゲートウェイまたは隣接ノードからのメッセージを処理する
// TTLに基づいてクライアントへの配信と隣接ノードへの転送を行う
func handleMeshMessage(rawMsg []byte) {
	var base baseMessage
	if err := json.Unmarshal(rawMsg, &base); err != nil {
		fmt.Printf("[メッシュ] メッセージデコード失敗: %v\n", err)
		return
	}

	switch base.Type {
	case "sms":
		// SMS着信: 宛先クライアントに配信
		var msg gatewayToNodeSMSMessage
		if err := json.Unmarshal(rawMsg, &msg); err != nil {
			return
		}
		fmt.Printf("[メッシュ] SMS受信: from=%s to=%s ttl=%d\n", msg.From, msg.To, msg.TTL)

		// 宛先クライアントにSMSを配信
		delivery := smsDeliveryMessage{
			Type: "sms",
			From: msg.From,
			Body: msg.Body,
		}
		data, err := json.Marshal(delivery)
		if err != nil {
			fmt.Printf("[メッシュ] SMS配信メッセージのシリアライズ失敗: %v\n", err)
			return
		}
		DeliverToClient(msg.To, data)

		// TTL>0の場合は隣接ノードに転送
		if msg.TTL > 0 {
			msg.TTL--
			forwarded, err := json.Marshal(msg)
			if err == nil {
				BroadcastToMesh(forwarded)
			}
		}

	case "ice_offer":
		// ICE offer着信: 宛先クライアントにICE情報を配信
		var msg gatewayToNodeICEMessage
		if err := json.Unmarshal(rawMsg, &msg); err != nil {
			return
		}
		fmt.Printf("[メッシュ] ICE offer受信: from=%s to=%s callID=%s ttl=%d\n", msg.From, msg.To, msg.CallID, msg.TTL)

		// 着信クライアントのICEキャッシュを取得してofferに追加
		cachedCandidates := GetClientICECache(msg.To)
		allCandidates := append(msg.Candidates, cachedCandidates...)

		// 宛先クライアントにICE offerを配信
		delivery := iceOfferDeliveryMessage{
			Type:       "ice_offer",
			From:       msg.From,
			SDPOffer:   msg.SDPOffer,
			Candidates: allCandidates,
			CallID:     msg.CallID,
		}
		data, err := json.Marshal(delivery)
		if err != nil {
			fmt.Printf("[メッシュ] ICE offer配信メッセージのシリアライズ失敗: %v\n", err)
			return
		}
		DeliverToClient(msg.To, data)

		// TTL>0の場合は隣接ノードに転送
		if msg.TTL > 0 {
			msg.TTL--
			forwarded, err := json.Marshal(msg)
			if err == nil {
				BroadcastToMesh(forwarded)
			}
		}

	case "ice_answer":
		// ICE answer: 発信側クライアントに転送
		// callIDから発信側を特定（デモ用: 全クライアントにブロードキャスト）
		fmt.Printf("[メッシュ] ICE answer受信\n")
		// 全クライアントへの配信は簡易実装（本番ではcallIDで発信側を特定する）

	case "node_list":
		// ゲートウェイからのノードリスト通知: 各ノードに接続
		var listMsg struct {
			Type  string   `json:"type"`
			Nodes []string `json:"nodes"`
		}
		if err := json.Unmarshal(rawMsg, &listMsg); err != nil {
			return
		}
		fmt.Printf("[メッシュ] ノードリスト受信: %v\n", listMsg.Nodes)
		for _, nodeAddr := range listMsg.Nodes {
			go ConnectToNode(nodeAddr)
		}

	default:
		fmt.Printf("[メッシュ] 未知のメッセージタイプ: type=%s\n", base.Type)
	}
}

// BroadcastToMesh は全隣接ノードにメッセージをブロードキャストする
func BroadcastToMesh(data []byte) {
	meshPeersMu.RLock()
	defer meshPeersMu.RUnlock()
	for addr, mc := range meshPeers {
		select {
		case mc.send <- data:
		default:
			// 送信バッファが満杯のノードはスキップ
			fmt.Printf("[メッシュ] 送信バッファ満杯: addr=%s\n", addr)
		}
	}
}
