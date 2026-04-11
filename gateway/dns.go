// dns.go - DNS解決による異ネットワーク間ルーティングの実装
// 電話番号の上2桁から XX.tell.com のTXTレコードを解決してゲートウェイを発見する
// TXTレコード形式: gateway=gw1.tell2.com:1919
package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// remoteGatewayInfo はリモートゲートウェイの接続情報
type remoteGatewayInfo struct {
	// ゲートウェイのホストとポート（例: gw1.tell2.com:1919）
	Address string
}

// resolveGateway はネットワーク識別子からゲートウェイアドレスをDNSで解決する
// XX.tell.com のTXTレコードに "gateway=..." の形式でアドレスが記載されている
func resolveGateway(networkPrefix string) (*remoteGatewayInfo, error) {
	// DNSクエリ対象のドメインを構築
	domain := fmt.Sprintf("%s.tell.com", networkPrefix)

	// TXTレコードを解決
	txts, err := net.LookupTXT(domain)
	if err != nil {
		return nil, fmt.Errorf("TXTレコード解決失敗 domain=%s: %w", domain, err)
	}

	// TXTレコードから "gateway=..." を検索
	for _, txt := range txts {
		if strings.HasPrefix(txt, "gateway=") {
			addr := strings.TrimPrefix(txt, "gateway=")
			if addr != "" {
				return &remoteGatewayInfo{Address: addr}, nil
			}
		}
	}

	return nil, fmt.Errorf("ゲートウェイのTXTレコードが見つかりません: domain=%s", domain)
}

// remoteSMSPayload はリモートゲートウェイへ送信するSMSペイロード
type remoteSMSPayload struct {
	From string `json:"from"`
	To   string `json:"to"`
	Body string `json:"body"`
}

// routeSMSToRemote は異ネットワーク宛てのSMSをDNSで発見したゲートウェイに転送する
func routeSMSToRemote(from, to, body, networkPrefix string) error {
	// DNSでリモートゲートウェイを解決
	gw, err := resolveGateway(networkPrefix)
	if err != nil {
		return err
	}

	// リモートゲートウェイのSMS送信エンドポイントにHTTP POSTで転送
	targetURL := fmt.Sprintf("http://%s/sms/send", gw.Address)
	payload := remoteSMSPayload{From: from, To: to, Body: body}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("ペイロードのシリアライズ失敗: %w", err)
	}

	// HTTPクライアントにタイムアウトを設定
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(targetURL, "application/json", strings.NewReader(string(data)))
	if err != nil {
		return fmt.Errorf("リモートゲートウェイへの送信失敗: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return errors.New(fmt.Sprintf("リモートゲートウェイエラー: ステータス=%d", resp.StatusCode))
	}

	fmt.Printf("[DNS] リモート転送成功: gateway=%s from=%s to=%s\n", gw.Address, from, to)
	return nil
}
