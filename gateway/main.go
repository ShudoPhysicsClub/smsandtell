// main.go - ゲートウェイサーバーのエントリポイント
// ポート1919でHTTPサーバーを起動し、各エンドポイントをルーティングする
package gateway

import (
	"fmt"
	"net/http"
)

// Run はゲートウェイサーバーを起動する
// ポート1919でリッスンし、各エンドポイントにハンドラーを登録する
func Run() {
	mux := http.NewServeMux()

	// 認証エンドポイント
	mux.HandleFunc("/auth/challenge", HandleChallenge)
	mux.HandleFunc("/auth/verify", HandleVerify)

	// SMS送受信エンドポイント
	mux.HandleFunc("/sms/send", HandleSMSSend)

	// ICE情報中継エンドポイント
	mux.HandleFunc("/ice/offer", HandleICEOffer)

	// ノードとの内部WebSocket通信エンドポイント
	mux.HandleFunc("/ws", HandleNodeWS)

	addr := ":1919"
	fmt.Printf("[ゲートウェイ] サーバー起動: addr=%s\n", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Printf("[ゲートウェイ] サーバーエラー: %v\n", err)
	}
}
