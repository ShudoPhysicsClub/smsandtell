// main.go - ノードサーバーのエントリポイント
// ポート334でWebSocketサーバーを起動する
// クライアント接続（/connect）とメッシュ接続（/mesh）を処理する
package node

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gorilla/websocket"
)

// gatewayConn はゲートウェイとのWebSocket接続を管理する構造体
type gatewayConn struct {
	// WebSocket接続
	conn *websocket.Conn
}

// Run はノードサーバーを起動する
// ポート334でリッスンし、クライアントとメッシュ接続を受け付ける
func Run() {
	mux := http.NewServeMux()

	// クライアントの常時接続エンドポイント
	mux.HandleFunc("/connect", HandleClientWS)

	// ノード間メッシュ通信エンドポイント
	mux.HandleFunc("/mesh", HandleMeshWS)

	// 環境変数からゲートウェイアドレスを取得（デフォルト: localhost:1919）
	gatewayAddr := os.Getenv("GATEWAY_ADDR")
	if gatewayAddr == "" {
		gatewayAddr = "localhost:1919"
	}

	// 非同期でゲートウェイに接続
	go connectToGateway(gatewayAddr)

	addr := ":334"
	fmt.Printf("[ノード] サーバー起動: addr=%s gateway=%s\n", addr, gatewayAddr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Printf("[ノード] サーバーエラー: %v\n", err)
	}
}

// connectToGateway はゲートウェイのWSエンドポイントに接続する
// ゲートウェイからのブロードキャストメッセージを受信して処理する
func connectToGateway(gatewayAddr string) {
	url := fmt.Sprintf("ws://%s/ws", gatewayAddr)
	dialer := websocket.DefaultDialer

	conn, _, err := dialer.Dial(url, nil)
	if err != nil {
		fmt.Printf("[ノード] ゲートウェイ接続失敗 addr=%s: %v\n", gatewayAddr, err)
		return
	}
	defer conn.Close()

	fmt.Printf("[ノード] ゲートウェイ接続成功: addr=%s\n", gatewayAddr)

	// ゲートウェイからのメッセージを受信ループ
	for {
		_, rawMsg, err := conn.ReadMessage()
		if err != nil {
			fmt.Printf("[ノード] ゲートウェイからの受信エラー: %v\n", err)
			break
		}
		// メッシュメッセージハンドラーで処理
		handleMeshMessage(rawMsg)
	}
}
