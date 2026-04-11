// ecsh.go - P256曲線を使用したSchnorr署名の実装
// 署名形式: (Rx, Ry, s) 各32バイト = 計96バイト
// 署名検証式: sG = R + H(Rx||Ry||Yx||Yy||msg) * Y
package gateway

import (
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
)

// P256曲線のパラメータを取得
var curve = elliptic.P256()

// SchnorrSig はSchnorr署名の構造体 (Rx, Ry, s)
type SchnorrSig struct {
	// 署名コミットメントRのx座標
	Rx []byte
	// 署名コミットメントRのy座標
	Ry []byte
	// 署名スカラー値
	S []byte
}

// SchnorrPubKey は公開鍵の構造体
type SchnorrPubKey struct {
	// x座標（16進数文字列）
	X string `json:"x"`
	// y座標（16進数文字列）
	Y string `json:"y"`
}

// hmacDRBG はRFC6979準拠の決定論的ノンス生成（HMAC-DRBG）
// privKey: 秘密鍵バイト列, msg: メッセージハッシュ
func hmacDRBG(privKey, msg []byte) *big.Int {
	// RFC6979 Step b: V = 0x01 * 32
	v := make([]byte, 32)
	for i := range v {
		v[i] = 0x01
	}
	// RFC6979 Step c: K = 0x00 * 32
	k := make([]byte, 32)

	// RFC6979 Step d: K = HMAC_K(V || 0x00 || privKey || msg)
	mac := hmac.New(sha256.New, k)
	mac.Write(v)
	mac.Write([]byte{0x00})
	mac.Write(privKey)
	mac.Write(msg)
	k = mac.Sum(nil)

	// RFC6979 Step e: V = HMAC_K(V)
	mac = hmac.New(sha256.New, k)
	mac.Write(v)
	v = mac.Sum(nil)

	// RFC6979 Step f: K = HMAC_K(V || 0x01 || privKey || msg)
	mac = hmac.New(sha256.New, k)
	mac.Write(v)
	mac.Write([]byte{0x01})
	mac.Write(privKey)
	mac.Write(msg)
	k = mac.Sum(nil)

	// RFC6979 Step g: V = HMAC_K(V)
	mac = hmac.New(sha256.New, k)
	mac.Write(v)
	v = mac.Sum(nil)

	// RFC6979 Step h: ノンスを生成して曲線の位数より小さい値を返す
	N := curve.Params().N
	for {
		mac = hmac.New(sha256.New, k)
		mac.Write(v)
		v = mac.Sum(nil)

		kInt := new(big.Int).SetBytes(v)
		// 位数より小さく0より大きい場合は有効なノンス
		if kInt.Sign() > 0 && kInt.Cmp(N) < 0 {
			return kInt
		}

		// 有効なノンスが得られなかった場合は再試行
		mac = hmac.New(sha256.New, k)
		mac.Write(v)
		mac.Write([]byte{0x00})
		k = mac.Sum(nil)

		mac = hmac.New(sha256.New, k)
		mac.Write(v)
		v = mac.Sum(nil)
	}
}

// SchnorrSign はP256曲線でSchnorr署名を生成する
// privKey: 秘密鍵（32バイト）, msg: 署名対象メッセージ
// 戻り値: 96バイトの署名 (Rx||Ry||s)
func SchnorrSign(privKeyBytes, msg []byte) ([]byte, error) {
	N := curve.Params().N
	// 秘密鍵をbig.Intに変換
	d := new(big.Int).SetBytes(privKeyBytes)
	if d.Sign() == 0 || d.Cmp(N) >= 0 {
		return nil, errors.New("無効な秘密鍵")
	}

	// メッセージをSHA-256でハッシュ化
	msgHash := sha256.Sum256(msg)

	// RFC6979で決定論的ノンスkを生成
	k := hmacDRBG(privKeyBytes, msgHash[:])

	// R = k*G を計算
	Rx, Ry := curve.ScalarBaseMult(k.Bytes())

	// 公開鍵 Y = d*G を計算
	Yx, Yy := curve.ScalarBaseMult(privKeyBytes)

	// チャレンジハッシュ e = H(Rx||Ry||Yx||Yy||msg) を計算
	e := schnorrChallenge(Rx, Ry, Yx, Yy, msg)

	// s = k - e*d mod N を計算
	s := new(big.Int).Mul(e, d)
	s.Mod(s, N)
	s.Sub(k, s)
	s.Mod(s, N)

	// 署名を96バイトに詰める (Rx||Ry||s)
	sig := make([]byte, 96)
	rxBytes := Rx.Bytes()
	ryBytes := Ry.Bytes()
	sBytes := s.Bytes()

	// 各フィールドを32バイトに右詰め
	copy(sig[32-len(rxBytes):32], rxBytes)
	copy(sig[64-len(ryBytes):64], ryBytes)
	copy(sig[96-len(sBytes):96], sBytes)

	return sig, nil
}

// schnorrChallenge はチャレンジハッシュ H(Rx||Ry||Yx||Yy||msg) を計算する
func schnorrChallenge(Rx, Ry, Yx, Yy *big.Int, msg []byte) *big.Int {
	h := sha256.New()
	// 各値を32バイトに詰めてハッシュ化
	h.Write(padTo32(Rx.Bytes()))
	h.Write(padTo32(Ry.Bytes()))
	h.Write(padTo32(Yx.Bytes()))
	h.Write(padTo32(Yy.Bytes()))
	h.Write(msg)
	eBytes := h.Sum(nil)
	return new(big.Int).SetBytes(eBytes)
}

// padTo32 はバイト列を32バイトに左ゼロ埋めする
func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}

// SchnorrVerify はSchnorr署名を検証する
// 検証式: sG = R + H(Rx||Ry||Yx||Yy||msg) * Y
// pubKey: 公開鍵, sigHex: 署名(rx, ry, sのhex), msg: 署名対象メッセージ
func SchnorrVerify(pubKey SchnorrPubKey, rxHex, ryHex, sHex string, msg []byte) (bool, error) {
	// 公開鍵をbig.Intに変換
	Yx, ok1 := new(big.Int).SetString(pubKey.X, 16)
	Yy, ok2 := new(big.Int).SetString(pubKey.Y, 16)
	if !ok1 || !ok2 {
		return false, errors.New("無効な公開鍵形式")
	}

	// 署名コンポーネントをデコード
	rxBytes, err := hex.DecodeString(rxHex)
	if err != nil {
		return false, errors.New("Rxのデコード失敗")
	}
	ryBytes, err := hex.DecodeString(ryHex)
	if err != nil {
		return false, errors.New("Ryのデコード失敗")
	}
	sBytes, err := hex.DecodeString(sHex)
	if err != nil {
		return false, errors.New("sのデコード失敗")
	}

	Rx := new(big.Int).SetBytes(rxBytes)
	Ry := new(big.Int).SetBytes(ryBytes)
	s := new(big.Int).SetBytes(sBytes)

	N := curve.Params().N
	// sが有効範囲内か確認
	if s.Sign() <= 0 || s.Cmp(N) >= 0 {
		return false, errors.New("無効なs値")
	}

	// 公開鍵が曲線上の点か確認
	if !curve.IsOnCurve(Yx, Yy) {
		return false, errors.New("公開鍵が曲線上にない")
	}

	// チャレンジハッシュ e = H(Rx||Ry||Yx||Yy||msg) を計算
	e := schnorrChallenge(Rx, Ry, Yx, Yy, msg)
	e.Mod(e, N)

	// sG を計算
	sGx, sGy := curve.ScalarBaseMult(s.Bytes())

	// eY を計算
	eYx, eYy := curve.ScalarMult(Yx, Yy, e.Bytes())

	// R + eY を計算
	RplusEYx, RplusEYy := curve.Add(Rx, Ry, eYx, eYy)

	// sG == R + eY を検証
	if sGx.Cmp(RplusEYx) == 0 && sGy.Cmp(RplusEYy) == 0 {
		return true, nil
	}
	return false, nil
}
