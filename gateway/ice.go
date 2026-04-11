// ice.go - ICE情報の中継エンドポイントの実装
// POST /ice/offer: 発信側のICE情報をノード経由で着信側に転送する
package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

// iceOfferRequest はICE offer送信リクエストのJSON構造体
type iceOfferRequest struct {
	// 発信側電話番号
	From string `json:"from"`
	// 着信側電話番号
	To string `json:"to"`
	// WebRTC SDPオファー
	SDPOffer string `json:"sdp_offer"`
	// ICE候補リスト
	Candidates []string `json:"candidates"`
}

// iceOfferResponse はICE offer送信レスポンスのJSON構造体
type iceOfferResponse struct {
	// 通話識別子
	CallID string `json:"call_id"`
}

// iceOfferMessage はノード間で転送するICE offerメッセージのJSON構造体
type iceOfferMessage struct {
	Type       string   `json:"type"`
	From       string   `json:"from"`
	To         string   `json:"to"`
	SDPOffer   string   `json:"sdp_offer"`
	Candidates []string `json:"candidates"`
	// 通話識別子
	CallID string `json:"call_id"`
	// 転送回数制限（TTL=1で1ホップのみ）
	TTL int `json:"ttl"`
}

// HandleICEOffer は POST /ice/offer エンドポイントのハンドラー
// 発信側のICE情報を取得してノード経由で着信側に転送する
func HandleICEOffer(w http.ResponseWriter, r *http.Request) {
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

	var req iceOfferRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "リクエストのデコード失敗")
		return
	}
	if req.To == "" {
		writeError(w, http.StatusBadRequest, "宛先電話番号は必須です")
		return
	}
	// 発信元はセッションから取得した電話番号を使用
	req.From = fromPhone

	// 通話IDを生成
	callID := uuid.New().String()

	// ICE offerメッセージを構築してノードにブロードキャスト
	msg := iceOfferMessage{
		Type:       "ice_offer",
		From:       req.From,
		To:         req.To,
		SDPOffer:   req.SDPOffer,
		Candidates: req.Candidates,
		CallID:     callID,
		TTL:        1,
	}
	data, err := json.Marshal(msg)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "メッセージのシリアライズ失敗")
		return
	}
	BroadcastToNodes(data)

	fmt.Printf("[ICE] offerブロードキャスト: from=%s to=%s callID=%s\n", req.From, req.To, callID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(iceOfferResponse{CallID: callID})
}
