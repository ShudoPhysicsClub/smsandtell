package main

import (
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math/big"
	"sort"
)

var curve = elliptic.P256()
var params = curve.Params()

// --- 型定義 ---

type PrivateKey [32]byte
type PublicKey [64]byte // X(32) + Y(32)
type Signature [96]byte // Rx(32) + Ry(32) + S(32)

// --- 変換ユーティリティ ---

func bigToBytes32(n *big.Int) [32]byte {
	var b [32]byte
	nb := n.Bytes()
	copy(b[32-len(nb):], nb)
	return b
}

func bytesToBig(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

func normalizeMessage(msg []byte) [32]byte {
	var out [32]byte
	if len(msg) >= len(out) {
		copy(out[:], msg[len(msg)-len(out):])
		return out
	}
	copy(out[len(out)-len(msg):], msg)
	return out
}

func sha256Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func hmacSha256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func concat(arrays ...[]byte) []byte {
	var total int
	for _, a := range arrays {
		total += len(a)
	}
	out := make([]byte, 0, total)
	for _, a := range arrays {
		out = append(out, a...)
	}
	return out
}

func canonicalJSONValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for key := range x {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		ordered := make(map[string]any, len(x))
		for _, key := range keys {
			ordered[key] = canonicalJSONValue(x[key])
		}
		return ordered
	case []any:
		items := make([]any, len(x))
		for i := range x {
			items[i] = canonicalJSONValue(x[i])
		}
		return items
	default:
		return v
	}
}

// CanonicalJSON は JSON オブジェクトのキー順を辞書順に正規化する。
// Node 側の canonicalJSON と同じく、配列の順序は維持しつつ、
// オブジェクトはキーをソートした再帰的な JSON を返す。
func CanonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, err
	}
	return json.Marshal(canonicalJSONValue(decoded))
}

// --- RFC6979 決定論的ノンス生成 ---

func generateK(priv PrivateKey, msg []byte) *big.Int {
	qLen := 32
	normalized := normalizeMessage(msg)
	h1 := sha256Hash(normalized[:])

	V := make([]byte, qLen)
	for i := range V {
		V[i] = 0x01
	}
	K := make([]byte, qLen) // 0x00で初期化済み

	b0 := []byte{0x00}
	b1 := []byte{0x01}

	K = hmacSha256(K, concat(V, b0, priv[:], h1))
	V = hmacSha256(K, V)
	K = hmacSha256(K, concat(V, b1, priv[:], h1))
	V = hmacSha256(K, V)

	for {
		var T []byte
		for len(T) < qLen {
			V = hmacSha256(K, V)
			T = append(T, V...)
		}

		k := new(big.Int).SetBytes(T[:qLen])
		if k.Sign() >= 1 && k.Cmp(params.N) < 0 {
			return k
		}

		K = hmacSha256(K, concat(V, b0))
		V = hmacSha256(K, V)
	}
}

// --- 公開鍵導出 ---

func DerivePublicKey(priv PrivateKey) (PublicKey, error) {
	d := bytesToBig(priv[:])
	if d.Sign() <= 0 || d.Cmp(params.N) >= 0 {
		return PublicKey{}, errors.New("ecsh: invalid private key")
	}

	x, y := curve.ScalarBaseMult(priv[:])

	var pub PublicKey
	xb := bigToBytes32(x)
	yb := bigToBytes32(y)
	copy(pub[:32], xb[:])
	copy(pub[32:], yb[:])
	return pub, nil
}

// --- 署名 ---

func Sign(priv PrivateKey, msg []byte) (Signature, error) {
	d := bytesToBig(priv[:])
	if d.Sign() <= 0 || d.Cmp(params.N) >= 0 {
		return Signature{}, errors.New("ecsh: invalid private key")
	}

	pub, err := DerivePublicKey(priv)
	if err != nil {
		return Signature{}, err
	}
	normalized := normalizeMessage(msg)
	msgBytes := normalized[:]

	// RFC6979で決定論的にkを生成
	k := generateK(priv, msgBytes)

	Rx, Ry := curve.ScalarBaseMult(k.Bytes())

	rxb := bigToBytes32(Rx)
	ryb := bigToBytes32(Ry)
	h := sha256.New()
	h.Write(rxb[:])
	h.Write(ryb[:])
	h.Write(pub[:32]) // Yx
	h.Write(pub[32:]) // Yy
	h.Write(msgBytes)
	e := new(big.Int).SetBytes(h.Sum(nil))
	e.Mod(e, params.N)

	s := new(big.Int).Mul(e, d)
	s.Add(s, k)
	s.Mod(s, params.N)

	var sig Signature
	sb := bigToBytes32(s)
	copy(sig[:32], rxb[:])
	copy(sig[32:64], ryb[:])
	copy(sig[64:], sb[:])
	return sig, nil
}

// --- 検証 ---

func Verify(pub PublicKey, msg []byte, sig Signature) bool {
	normalized := normalizeMessage(msg)
	msgBytes := normalized[:]
	Yx := bytesToBig(pub[:32])
	Yy := bytesToBig(pub[32:])
	if !curve.IsOnCurve(Yx, Yy) {
		return false
	}

	Rx := bytesToBig(sig[:32])
	Ry := bytesToBig(sig[32:64])
	s := bytesToBig(sig[64:])
	if s.Sign() <= 0 || s.Cmp(params.N) >= 0 {
		return false
	}
	if !curve.IsOnCurve(Rx, Ry) {
		return false
	}

	h := sha256.New()
	h.Write(sig[:32])   // Rx
	h.Write(sig[32:64]) // Ry
	h.Write(pub[:32])   // Yx
	h.Write(pub[32:])   // Yy
	h.Write(msgBytes)
	e := new(big.Int).SetBytes(h.Sum(nil))
	e.Mod(e, params.N)

	sGx, sGy := curve.ScalarBaseMult(s.Bytes())
	eYx, eYy := curve.ScalarMult(Yx, Yy, e.Bytes())
	checkX, checkY := curve.Add(Rx, Ry, eYx, eYy)

	return sGx.Cmp(checkX) == 0 && sGy.Cmp(checkY) == 0
}
