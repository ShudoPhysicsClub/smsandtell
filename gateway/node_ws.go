// node_ws.go - ノードとのWebSocket通信管理の実装
// ゲートウェイとノード間の内部通信チャネルを管理する
// WS /ws エンドポイントを通じてノードが接続する
package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

// WebSocketアップグレーダーの設定
// すべてのオリジンを許可（デモ用）
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// nodeConn はノードとのWebSocket接続を表す構造体
type nodeConn struct {
	// WebSocket接続
	conn *websocket.Conn
	// ノードの識別アドレス（host:port）
	addr string
	// 送信チャネル
	send chan []byte
}

// ノード接続の管理
var (
	// 接続中のノード一覧: addr → nodeConn
	nodes   = make(map[string]*nodeConn)
	nodesMu sync.RWMutex
)

// nodeListMessage はノードリストを通知するメッセージのJSON構造体
type nodeListMessage struct {
	Type  string   `json:"type"`
	Nodes []string `json:"nodes"`
}

// HandleNodeWS は WS /ws エンドポイントのハンドラー
// ノードからのWebSocket接続を受け付けて管理する
func HandleNodeWS(w http.ResponseWriter, r *http.Request) {
	// WebSocketにアップグレード
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Printf("[ノードWS] アップグレード失敗: %v\n", err)
		return
	}

	// 接続ノードのアドレスを取得
	addr := r.RemoteAddr
	nc := &nodeConn{
		conn: conn,
		addr: addr,
		send: make(chan []byte, 256),
	}

	// ノードを登録
	nodesMu.Lock()
	nodes[addr] = nc
	// 既存ノードリストを構築して新ノードに通知
	existingNodes := make([]string, 0, len(nodes)-1)
	for a := range nodes {
		if a != addr {
			existingNodes = append(existingNodes, a)
		}
	}
	nodesMu.Unlock()

	fmt.Printf("[ノードWS] ノード接続: addr=%s 既存ノード数=%d\n", addr, len(existingNodes))

	// 既存ノードリストを新ノードに送信
	if len(existingNodes) > 0 {
		listMsg := nodeListMessage{
			Type:  "node_list",
			Nodes: existingNodes,
		}
		data, err := json.Marshal(listMsg)
		if err == nil {
			nc.send <- data
		} else {
			fmt.Printf("[ノードWS] ノードリストのシリアライズ失敗: %v\n", err)
		}
	}

	// 既存の全ノードに新ノードの参加を通知
	newNodeMsg := nodeListMessage{
		Type:  "node_list",
		Nodes: []string{addr},
	}
	newNodeData, err := json.Marshal(newNodeMsg)
	if err != nil {
		fmt.Printf("[ノードWS] 新ノード通知のシリアライズ失敗: %v\n", err)
		newNodeData = nil
	}
	nodesMu.RLock()
	for a, existing := range nodes {
		if a != addr && newNodeData != nil {
			select {
			case existing.send <- newNodeData:
			default:
				// 送信バッファが満杯の場合はスキップ
			}
		}
	}
	nodesMu.RUnlock()

	// 送信ゴルーチンを起動
	go nc.writePump()

	// 受信ループ（ノードからのメッセージを処理）
	nc.readPump()

	// 接続切断時にノードを削除
	nodesMu.Lock()
	delete(nodes, addr)
	nodesMu.Unlock()
	fmt.Printf("[ノードWS] ノード切断: addr=%s\n", addr)
}

// readPump はノードからのメッセージを受信して処理する
func (nc *nodeConn) readPump() {
	defer nc.conn.Close()
	for {
		_, msg, err := nc.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				fmt.Printf("[ノードWS] 受信エラー addr=%s: %v\n", nc.addr, err)
			}
			break
		}
		// ノードからのメッセージを他のノードに転送（現在はログのみ）
		fmt.Printf("[ノードWS] ノードからメッセージ受信: addr=%s len=%d\n", nc.addr, len(msg))
	}
}

// writePump はsendチャネルからメッセージを取得してノードに送信する
func (nc *nodeConn) writePump() {
	defer nc.conn.Close()
	for msg := range nc.send {
		if err := nc.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			fmt.Printf("[ノードWS] 送信エラー addr=%s: %v\n", nc.addr, err)
			return
		}
	}
}

// BroadcastToNodes は全接続ノードにメッセージをブロードキャストする
func BroadcastToNodes(data []byte) {
	nodesMu.RLock()
	defer nodesMu.RUnlock()
	for _, nc := range nodes {
		select {
		case nc.send <- data:
		default:
			// 送信バッファが満杯のノードはスキップ
			fmt.Printf("[ノードWS] 送信バッファ満杯: addr=%s\n", nc.addr)
		}
	}
}

// GetNodeList は接続中のノードアドレス一覧を返す
func GetNodeList() []string {
	nodesMu.RLock()
	defer nodesMu.RUnlock()
	list := make([]string, 0, len(nodes))
	for addr := range nodes {
		list = append(list, addr)
	}
	return list
}
