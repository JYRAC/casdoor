package main

// 署名つきの例外: Cloudflare の Worker（pr.jyrac.stki.org）が、Casdoor に呼ぶ 2 つの通信だけを、
// IP 制限の例外にする。Worker の送信元 IP は、許可リストで表せないため、IP ではなく、
// 共有の秘密（HMAC-SHA256）で、相手を確かめる。
//
//   GATE_SIGNED_SECRET   共有の秘密（32 文字以上）。OpenBao の kv/secrets/casdoor/config の
//                        gate_signed_secret を、Agent が、環境変数に出す。空、または短いときは、無効
//
// 例外にするのは、完全一致の 2 つだけ（クエリなし）:
//   POST /api/login/oauth/access_token   認可コードとトークンの交換
//   GET  /.well-known/jwks               id_token の検証用の公開鍵
//
// 署名する文字列（改行区切り）:
//   gate-v1 / タイムスタンプ(秒) / ナンス / メソッド / パス / 本文の SHA-256（16進、小文字）
// ヘッダー: X-Gate-Timestamp, X-Gate-Nonce, X-Gate-Signature（16進、小文字）
//
// 本文のハッシュを署名に含めるので、通信の途中で、本文（認可コードなど）を差し替えられない。
// タイムスタンプは ±60 秒、ナンスは、期限内の再利用を拒否する（再送の対策）。
// 署名が合わないときは、例外にしない（通常の判定に進む）。X-Gate-* は、アプリには渡さない。
//
// client_secret とは、別の秘密にする（ここで漏れても、Casdoor のアプリの資格情報は、無関係）。

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"
)

const (
	hdrSignedTS    = "X-Gate-Timestamp"
	hdrSignedNonce = "X-Gate-Nonce"
	hdrSignedSig   = "X-Gate-Signature"

	signedVersion   = "gate-v1"
	signedMaxBody   = 64 << 10
	signedMinSecret = 32
	signedSkew      = 60 * time.Second
	signedMaxSeen   = 4096
)

var reNonce = regexp.MustCompile(`^[0-9a-f]{16,64}$`)

type Signer struct {
	secret []byte
	skew   time.Duration
	now    func() time.Time

	mu   sync.Mutex
	seen map[string]time.Time // ナンス → 期限
}

// newSigner は、秘密が空、または短いとき、nil（無効）を返す。
// OpenBao のテンプレートで、キーが無いときに出る "<no value>" も、短いので、無効になる。
func newSigner(secret string) *Signer {
	if len(secret) < signedMinSecret {
		return nil
	}
	return &Signer{secret: []byte(secret), skew: signedSkew, now: time.Now, seen: map[string]time.Time{}}
}

func signedString(ts, nonce, method, path string, body []byte) string {
	sum := sha256.Sum256(body)
	return signedVersion + "\n" + ts + "\n" + nonce + "\n" + method + "\n" + path + "\n" + hex.EncodeToString(sum[:])
}

func (s *Signer) sign(ts, nonce, method, path string, body []byte) string {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte(signedString(ts, nonce, method, path, body)))
	return hex.EncodeToString(m.Sum(nil))
}

// signedTarget は、例外にしてよい 2 つの通信（完全一致、クエリなし）。
func signedTarget(r *http.Request) bool {
	if r.URL.RawQuery != "" || !cleanExact(r) {
		return false
	}
	return (r.Method == http.MethodPost && r.URL.Path == "/api/login/oauth/access_token") ||
		(r.Method == http.MethodGet && r.URL.Path == "/.well-known/jwks")
}

func hasSignedHeaders(r *http.Request) bool {
	return len(r.Header.Values(hdrSignedTS)) > 0 || len(r.Header.Values(hdrSignedNonce)) > 0 || len(r.Header.Values(hdrSignedSig)) > 0
}

// verify は、署名ヘッダーがあるリクエストだけを検証する。ヘッダーが無いときは、何も記録しない。
// 本文を読んだときは、r.Body を、読み直せる形に戻す。
func (s *Signer) verify(r *http.Request) bool {
	if s == nil || !hasSignedHeaders(r) {
		return false
	}
	reject := func(reason string) bool {
		log.Printf("GATE_SIGNED_REJECT reason=%s method=%q path=%q", reason, r.Method, r.URL.Path)
		return false
	}

	ts, nonce, sig := r.Header.Values(hdrSignedTS), r.Header.Values(hdrSignedNonce), r.Header.Values(hdrSignedSig)
	if len(ts) != 1 || len(nonce) != 1 || len(sig) != 1 {
		return reject("bad_headers")
	}
	if !signedTarget(r) {
		return reject("target_not_allowed")
	}
	sec, err := strconv.ParseInt(ts[0], 10, 64)
	if err != nil {
		return reject("bad_timestamp")
	}
	now := s.now()
	if d := now.Sub(time.Unix(sec, 0)); d > s.skew || d < -s.skew {
		return reject("timestamp_out_of_range")
	}
	if !reNonce.MatchString(nonce[0]) {
		return reject("bad_nonce")
	}

	var body []byte
	if r.Method == http.MethodPost {
		if r.ContentLength < 0 || r.ContentLength > signedMaxBody {
			return reject("bad_body_length")
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, signedMaxBody+1))
		if err != nil || len(b) > signedMaxBody {
			return reject("bad_body")
		}
		body = b
		r.Body = io.NopCloser(bytes.NewReader(b))
	} else if r.ContentLength > 0 {
		return reject("unexpected_body")
	}

	want := s.sign(ts[0], nonce[0], r.Method, r.URL.Path, body)
	if !hmac.Equal([]byte(want), []byte(sig[0])) {
		return reject("bad_signature")
	}

	// 署名が合ったものだけを、ナンスの記録に入れる（秘密を知らない相手が、記録を埋められないように）
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, exp := range s.seen {
		if !now.Before(exp) {
			delete(s.seen, k)
		}
	}
	if _, dup := s.seen[nonce[0]]; dup {
		return reject("replay")
	}
	if len(s.seen) >= signedMaxSeen {
		return reject("nonce_store_full")
	}
	s.seen[nonce[0]] = now.Add(2 * s.skew)
	log.Printf("GATE_SIGNED_ALLOW method=%q path=%q", r.Method, r.URL.Path)
	return true
}

// stripSignedHeaders は、アプリに渡す前に、X-Gate-* を消す。
func stripSignedHeaders(h http.Header) {
	h.Del(hdrSignedTS)
	h.Del(hdrSignedNonce)
	h.Del(hdrSignedSig)
}
