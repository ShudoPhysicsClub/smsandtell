// sms.go - SMS送受信エンドポイントの実装
// POST /sms/send: SMSを送信する（宛先ノードへの転送または異ネットワーク間ルーティング）
package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// smsRequest はSMS送信リクエストのJSON構造体
type smsRequest struct {
	// 送信元電話番号
	From string `json:"from"`
	// 宛先電話番号
	To string `json:"to"`
	// SMSの本文
	Body string `json:"body"`
}

// smsResponse はSMS送信レスポンスのJSON構造体
type smsResponse struct {
	// 配信ステータス: "delivered" | "stored" | "routed"
	Status string `json:"status"`
}

// smsMessage はノード間で転送するSMSメッセージのJSON構造体
type smsMessage struct {
	Type string `json:"type"`
	From string `json:"from"`
	To   string `json:"to"`
	Body string `json:"body"`
	// 転送回数制限（TTL=1で1ホップのみ）
	TTL int `json:"ttl"`
}

// HandleSMSSend は POST /sms/send エンドポイントのハンドラー
// セッション認証後、宛先に応じてSMSを配信する
func HandleSMSSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POSTメソッドのみ対応")
		return
	}

	// Bearerトークンでセッションを検証
	token := extractBearerToken(r)
	fromPhone := ValidateToken(token)
	if fromPhone == "" {
		writeError(w, http.StatusUnauthorized, "無効なセッショントークン")
		return
	}

	var req smsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "リクエストのデコード失敗")
		return
	}
	if req.To == "" || req.Body == "" {
		writeError(w, http.StatusBadRequest, "宛先と本文は必須です")
		return
	}
	// 送信元はセッションから取得した電話番号を使用
	req.From = fromPhone

	// 宛先の電話番号からネットワークを判定
	targetNetwork := extractNetworkPrefix(req.To)
	localNetwork := extractNetworkPrefix(fromPhone)

	var status string

	if targetNetwork != localNetwork {
		// 異ネットワーク宛ての場合はDNSルーティングで転送
		fmt.Printf("[SMS] 異ネットワーク転送: from=%s to=%s network=%s\n", req.From, req.To, targetNetwork)
		if err := routeSMSToRemote(req.From, req.To, req.Body, targetNetwork); err != nil {
			fmt.Printf("[SMS] 異ネットワーク転送失敗: %v\n", err)
			// 転送失敗時はローカルに保存
			status = "stored"
		} else {
			status = "routed"
		}
	} else {
		// 同一ネットワーク内の場合はノードにブロードキャスト
		msg := smsMessage{
			Type: "sms",
			From: req.From,
			To:   req.To,
			Body: req.Body,
			TTL:  1,
		}
		data, _ := json.Marshal(msg)
		BroadcastToNodes(data)
		fmt.Printf("[SMS] ブロードキャスト: from=%s to=%s\n", req.From, req.To)
		status = "delivered"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(smsResponse{Status: status})
}

// extractNetworkPrefix は電話番号の上2桁からネットワーク識別子を返す
func extractNetworkPrefix(phone string) string {
	// ハイフンや+を除いた先頭2文字を取得
	digits := ""
	for _, c := range phone {
		if c >= '0' && c <= '9' {
			digits += string(c)
			if len(digits) >= 2 {
				break
			}
		}
	}
	if len(digits) < 2 {
		return "00"
	}
	return digits
}
