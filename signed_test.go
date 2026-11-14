package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

var fixedNow = time.Unix(1700000000, 0)

func testSigner() *Signer {
	s := newSigner(testSecret)
	s.now = func() time.Time { return fixedNow }
	return s
}

// Worker（JavaScript）側のテストと、同じ値。Worker とゲートが、同じ署名を作ることの確認。
func TestSignedVector(t *testing.T) {
	got := testSigner().sign("1700000000", "00112233445566778899aabbccddeeff",
		"POST", "/api/login/oauth/access_token", []byte("grant_type=authorization_code&code=abc"))
	want := "ccad5e3cad44635ddcdcf07a11b24da8f4416aece345fd26ac3cde102ae6a291"
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestNewSignerDisabled(t *testing.T) {
	for _, s := range []string{"", "<no value>", strings.Repeat("a", signedMinSecret-1)} {
		if newSigner(s) != nil {
			t.Errorf("secret %q は無効のはず", s)
		}
	}
	if newSigner(strings.Repeat("a", signedMinSecret)) == nil {
		t.Error("32 文字は有効のはず")
	}
	var s *Signer
	if s.verify(httptest.NewRequest("GET", "/.well-known/jwks", nil)) {
		t.Error("nil の Signer は、false のはず")
	}
}

type seenReq struct {
	body    string
	headers http.Header
	n       int
}

// signedGate は、許可リストが 203.0.113.10 だけの、enforce のゲートを作る。
func signedGate(t *testing.T, signer *Signer) (*Gate, *seenReq) {
	t.Helper()
	seen := &seenReq{}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen.body, seen.headers = string(b), r.Header.Clone()
		seen.n++
		w.WriteHeader(200)
	}))
	t.Cleanup(up.Close)
	target, _ := url.Parse(up.URL)
	store := &Store{}
	store.p.Store(&Policy{
		allow: []entry{{prefix: netip.MustParsePrefix("203.0.113.10/32")}},
		deny:  []entry{{prefix: netip.MustParsePrefix("198.51.100.66/32")}},
	})
	return &Gate{
		store:       store,
		next:        newProxy(target),
		health:      newHealthChecker(store, target.Host, "", false),
		healthPath:  "/gate/healthz",
		exactAllow:  map[string]bool{},
		signer:      signer,
		redirectURL: "https://gate.example/",
		deniedURL:   "https://gate.example/denied",
		enforce:     true,
	}, seen
}

type sreq struct {
	method, target, body string
	tsOffset             int64
	nonce                string
	ip                   string
	mutate               func(*http.Request)
}

func (s sreq) build(sg *Signer) *http.Request {
	var rd io.Reader
	if s.body != "" {
		rd = strings.NewReader(s.body)
	}
	r := httptest.NewRequest(s.method, s.target, rd)
	ip := s.ip
	if ip == "" {
		ip = "192.0.2.77" // 許可リストの外
	}
	r.Header.Set("CF-Connecting-IP", ip)
	ts := strconv.FormatInt(fixedNow.Unix()+s.tsOffset, 10)
	nonce := s.nonce
	if nonce == "" {
		nonce = fmt.Sprintf("%032x", time.Now().UnixNano())
	}
	path := r.URL.Path
	r.Header.Set(hdrSignedTS, ts)
	r.Header.Set(hdrSignedNonce, nonce)
	r.Header.Set(hdrSignedSig, sg.sign(ts, nonce, r.Method, path, []byte(s.body)))
	if s.mutate != nil {
		s.mutate(r)
	}
	return r
}

func serve(g *Gate, r *http.Request) int {
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	return w.Code
}

func TestSignedException(t *testing.T) {
	const token = "/api/login/oauth/access_token"
	body := "grant_type=authorization_code&code=abc&code_verifier=v"
	cases := []struct {
		name string
		r    sreq
		want int
	}{
		{"トークン交換（POST、署名あり）", sreq{method: "POST", target: token, body: body}, 200},
		{"JWKS（GET、署名あり）", sreq{method: "GET", target: "/.well-known/jwks"}, 200},
		{"本文を差し替えた", sreq{method: "POST", target: token, body: body, mutate: func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(strings.Replace(body, "abc", "xyz", 1)))
		}}, 403},
		{"例外にないパス（正しく署名しても）", sreq{method: "GET", target: "/api/userinfo"}, 403},
		{"例外にないパス（管理 API）", sreq{method: "POST", target: "/api/update-application", body: "x=1"}, 403},
		{"メソッドが違う（GET でトークン）", sreq{method: "GET", target: token}, 403},
		{"メソッドが違う（POST で JWKS）", sreq{method: "POST", target: "/.well-known/jwks", body: "x=1"}, 403},
		{"クエリ付き", sreq{method: "GET", target: "/.well-known/jwks?x=1"}, 403},
		{"アプリ別の JWKS は、例外にしない", sreq{method: "GET", target: "/.well-known/app/jwks"}, 403},
		{"二重スラッシュ", sreq{method: "GET", target: "//.well-known/jwks"}, 403},
		{"期限切れ（61 秒前）", sreq{method: "GET", target: "/.well-known/jwks", tsOffset: -61}, 403},
		{"未来（61 秒後）", sreq{method: "GET", target: "/.well-known/jwks", tsOffset: 61}, 403},
		{"期限の内（59 秒前）", sreq{method: "GET", target: "/.well-known/jwks", tsOffset: -59}, 200},
		{"署名が違う", sreq{method: "GET", target: "/.well-known/jwks", mutate: func(r *http.Request) {
			r.Header.Set(hdrSignedSig, strings.Repeat("0", 64))
		}}, 403},
		{"署名ヘッダーが無い", sreq{method: "GET", target: "/.well-known/jwks", mutate: func(r *http.Request) {
			r.Header.Del(hdrSignedSig)
		}}, 403},
		{"署名ヘッダーが 2 つ", sreq{method: "GET", target: "/.well-known/jwks", mutate: func(r *http.Request) {
			r.Header.Add(hdrSignedSig, r.Header.Get(hdrSignedSig))
		}}, 403},
		{"ナンスの形式が違う", sreq{method: "GET", target: "/.well-known/jwks", nonce: "short"}, 403},
		{"拒否リストの IP は、署名があっても、通さない", sreq{method: "GET", target: "/.well-known/jwks", ip: "198.51.100.66"}, 403},
		{"CF のヘッダーが無い", sreq{method: "GET", target: "/.well-known/jwks", mutate: func(r *http.Request) {
			r.Header.Del("CF-Connecting-IP")
		}}, 403},
		{"本文が大きすぎる", sreq{method: "POST", target: token, body: strings.Repeat("a", signedMaxBody+1)}, 403},
		{"GET に本文", sreq{method: "GET", target: "/.well-known/jwks", mutate: func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader("x"))
			r.ContentLength = 1
		}}, 403},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sg := testSigner()
			g, seen := signedGate(t, sg)
			got := serve(g, c.r.build(sg))
			if got != c.want {
				t.Fatalf("status=%d want=%d", got, c.want)
			}
			if c.want == 200 {
				if seen.n != 1 {
					t.Fatalf("アプリに届いた回数 %d", seen.n)
				}
				if c.r.body != "" && seen.body != c.r.body {
					t.Fatalf("本文が変わった: %q", seen.body)
				}
				for _, h := range []string{hdrSignedTS, hdrSignedNonce, hdrSignedSig} {
					if seen.headers.Get(h) != "" {
						t.Fatalf("%s が、アプリに渡った", h)
					}
				}
			} else if seen.n != 0 {
				t.Fatalf("拒否したのに、アプリに届いた")
			}
		})
	}
}

func TestSignedReplay(t *testing.T) {
	sg := testSigner()
	g, _ := signedGate(t, sg)
	s := sreq{method: "GET", target: "/.well-known/jwks", nonce: "aaaaaaaaaaaaaaaa"}
	if got := serve(g, s.build(sg)); got != 200 {
		t.Fatalf("1 回目 %d", got)
	}
	if got := serve(g, s.build(sg)); got != 403 {
		t.Fatalf("同じナンスの再送は、拒否のはず: %d", got)
	}
	// 期限の後は、記録が消える（同じナンスを使えるが、タイムスタンプが新しい別のリクエスト）
	sg.now = func() time.Time { return fixedNow.Add(3 * time.Minute) }
	s.tsOffset = 180
	if got := serve(g, s.build(sg)); got != 200 {
		t.Fatalf("期限後は通るはず: %d", got)
	}
}

func TestSignedBadSignatureDoesNotBurnNonce(t *testing.T) {
	sg := testSigner()
	g, _ := signedGate(t, sg)
	bad := sreq{method: "GET", target: "/.well-known/jwks", nonce: "bbbbbbbbbbbbbbbb", mutate: func(r *http.Request) {
		r.Header.Set(hdrSignedSig, strings.Repeat("1", 64))
	}}
	if got := serve(g, bad.build(sg)); got != 403 {
		t.Fatal("拒否のはず")
	}
	good := sreq{method: "GET", target: "/.well-known/jwks", nonce: "bbbbbbbbbbbbbbbb"}
	if got := serve(g, good.build(sg)); got != 200 {
		t.Fatalf("偽の署名で、ナンスが使われてはいけない: %d", got)
	}
}

func TestSignedNonceStoreFull(t *testing.T) {
	sg := testSigner()
	g, _ := signedGate(t, sg)
	for i := 0; i < signedMaxSeen; i++ {
		s := sreq{method: "GET", target: "/.well-known/jwks", nonce: fmt.Sprintf("%032x", i)}
		if got := serve(g, s.build(sg)); got != 200 {
			t.Fatalf("%d 件目 %d", i, got)
		}
	}
	s := sreq{method: "GET", target: "/.well-known/jwks", nonce: fmt.Sprintf("%032x", signedMaxSeen+1)}
	if got := serve(g, s.build(sg)); got != 403 {
		t.Fatalf("満杯のときは、通さない: %d", got)
	}
}

func TestSignedDisabledAndAllowlistedStrip(t *testing.T) {
	sg := testSigner()
	// 秘密が無い（無効）ゲートでは、署名があっても、例外にならない
	g, _ := signedGate(t, nil)
	if got := serve(g, sreq{method: "GET", target: "/.well-known/jwks"}.build(sg)); got != 403 {
		t.Fatalf("無効のときは、通さない: %d", got)
	}
	// 許可リストの IP からのときも、X-Gate-* は、アプリに渡さない
	g, seen := signedGate(t, sg)
	if got := serve(g, sreq{method: "GET", target: "/api/health", ip: "203.0.113.10"}.build(sg)); got != 200 {
		t.Fatalf("許可リストの IP は通る: %d", got)
	}
	if seen.headers.Get(hdrSignedSig) != "" || seen.headers.Get(hdrSignedNonce) != "" {
		t.Fatal("X-Gate-* が、アプリに渡った")
	}
}

func TestSignedInternalProxyStrips(t *testing.T) {
	var got http.Header
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Header.Clone() }))
	defer up.Close()
	target, _ := url.Parse(up.URL)
	p := httptest.NewServer(newInternalProxy(target, "auth.example"))
	defer p.Close()
	req, _ := http.NewRequest("GET", p.URL+"/x", nil)
	req.Header.Set(hdrSignedSig, "x")
	req.Header.Set(hdrSignedTS, "1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got.Get(hdrSignedSig) != "" || got.Get(hdrSignedTS) != "" {
		t.Fatal("内部口でも、X-Gate-* は渡さない")
	}
}
