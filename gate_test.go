package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func req(method, target string) *http.Request {
	return httptest.NewRequest(method, target, nil)
}

// ---- 内部口の許可リスト ----

func TestInternalARules(t *testing.T) {
	cases := []struct {
		method, target string
		want           bool
	}{
		{"GET", "/.well-known/openid-configuration", true},
		{"GET", "/.well-known/app-vikunja/openid-configuration", true},
		{"GET", "/.well-known/jwks", true},
		{"GET", "/.well-known/app-directus/jwks", true},
		{"POST", "/api/login/oauth/access_token", true},
		{"POST", "/api/login/oauth/access_token?grant_type=refresh_token", true},
		{"GET", "/api/userinfo", true},

		// メソッド違い
		{"POST", "/.well-known/openid-configuration", false},
		{"GET", "/api/login/oauth/access_token", false},
		{"POST", "/api/userinfo", false},
		// クエリ付き（URL にトークンを載せる形、など）
		{"GET", "/api/userinfo?accessToken=x", false},
		{"GET", "/.well-known/jwks?x=1", false},
		// 管理 API は、A では通さない
		{"GET", "/api/get-application?id=admin/app-vikunja", false},
		{"POST", "/api/update-application?id=admin/app-vikunja", false},
		{"GET", "/api/get-users", false},
		{"POST", "/api/login", false},
		{"GET", "/api/health", false},
		{"GET", "/", false},
		// 前方一致、末尾違い、アプリ名の不正
		{"GET", "/.well-known/jwks/x", false},
		{"GET", "/.well-known/a/b/jwks", false},
		{"GET", "/.well-known/app.x/jwks", false},
		{"GET", "/.well-known/oauth-authorization-server", false},
		{"GET", "/api/userinfo/", false},
	}
	for _, c := range cases {
		r := req(c.method, c.target)
		got := cleanExact(r) && anyRule(internalARules, r)
		if got != c.want {
			t.Errorf("A %s %s: got %v want %v", c.method, c.target, got, c.want)
		}
	}
}

func TestInternalBRules(t *testing.T) {
	cases := []struct {
		method, target string
		want           bool
	}{
		{"GET", "/api/get-application?id=admin/app-vikunja", true},
		{"GET", "/api/get-application?id=admin%2Fapp-vikunja", true},
		{"POST", "/api/update-application?id=admin/app-directus", true},
		{"POST", "/api/update-application?id=admin/pr.portal_1", true},

		{"POST", "/api/get-application?id=admin/x", false},
		{"GET", "/api/update-application?id=admin/x", false},
		{"GET", "/api/get-application", false},
		{"GET", "/api/get-application?id=built-in/x", false},
		{"GET", "/api/get-application?id=admin/", false},
		{"GET", "/api/get-application?id=admin/a/b", false},
		{"GET", "/api/get-application?id=admin/x&id=admin/y", false},
		{"GET", "/api/get-application?id=admin/x&owner=admin", false},
		{"GET", "/api/get-applications?owner=admin", false},
		{"POST", "/api/delete-application?id=admin/x", false},
		{"POST", "/api/add-application", false},
		{"GET", "/api/get-users?owner=admin", false},
		{"POST", "/api/login/oauth/access_token", false},
		{"GET", "/.well-known/jwks", false},
	}
	for _, c := range cases {
		r := req(c.method, c.target)
		got := cleanExact(r) && anyRule(internalBRules, r)
		if got != c.want {
			t.Errorf("B %s %s: got %v want %v", c.method, c.target, got, c.want)
		}
	}
}

// パスの表記ゆれで、完全一致をすり抜けられないこと
func TestInternalPathTricks(t *testing.T) {
	for _, target := range []string{
		"/api/userinfo;x=1",
		"/api//userinfo",
		"/api/./userinfo",
		"/api/x/../userinfo",
		"/api/%75serinfo",
		"/.well-known/jwks%2F",
	} {
		r := req("GET", target)
		if cleanExact(r) && anyRule(internalARules, r) {
			t.Errorf("A が通してしまった: %s", target)
		}
	}
}

// ---- 内部口のプロキシ ----

func TestInternalProxyHostAndHeaders(t *testing.T) {
	var gotHost string
	var gotHdr http.Header
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotHdr = r.Header.Clone()
		_, _ = io.WriteString(w, "upstream-ok")
	}))
	defer up.Close()
	target, _ := url.Parse(up.URL)

	h := newInternalHandler("A", internalARules, newInternalProxy(target, "auth.jyrac.stki.org"))
	r := httptest.NewRequest("GET", "http://100.125.1.1:8443/.well-known/openid-configuration", nil)
	r.Header.Set("CF-Connecting-IP", "198.51.100.9")
	r.Header.Set("X-Forwarded-For", "203.0.113.5")
	r.Header.Set("X-Forwarded-Host", "evil.example")
	r.Header.Set("X-Real-Ip", "203.0.113.6")
	r.Header.Set("Forwarded", "for=203.0.113.7")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != 200 || w.Body.String() != "upstream-ok" {
		t.Fatalf("code=%d body=%q", w.Code, w.Body.String())
	}
	if gotHost != "auth.jyrac.stki.org" {
		t.Errorf("Host=%q", gotHost)
	}
	for _, k := range []string{"Cf-Connecting-Ip", "X-Forwarded-Host", "X-Real-Ip", "Forwarded"} {
		if v := gotHdr.Get(k); v != "" {
			t.Errorf("%s が上流に渡った: %q", k, v)
		}
	}
	if v := gotHdr.Get("X-Forwarded-For"); strings.Contains(v, "203.0.113.5") {
		t.Errorf("偽装した X-Forwarded-For が渡った: %q", v)
	}
	if gotHdr.Get("X-Forwarded-Proto") != "https" {
		t.Errorf("X-Forwarded-Proto=%q", gotHdr.Get("X-Forwarded-Proto"))
	}
}

func TestInternalHandlerDenies(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
	h := newInternalHandler("B", internalBRules, next)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req("POST", "/api/login/oauth/access_token"))
	if w.Code != http.StatusForbidden || called {
		t.Fatalf("code=%d called=%v", w.Code, called)
	}
}

// ---- TLS（1.3 だけ）と、実際の待ち受け ----

func writeTestCert(t *testing.T, dir string) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "auth.jyrac.stki.org"},
		DNSNames:              []string{"auth.jyrac.stki.org"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	pool = x509.NewCertPool()
	pool.AddCert(c)
	return
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func TestInternalServersTLS(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "host="+r.Host)
	}))
	defer up.Close()
	target, _ := url.Parse(up.URL)

	dir := t.TempDir()
	certFile, keyFile, pool := writeTestCert(t, dir)
	addrA, addrB := freeAddr(t), freeAddr(t)
	servers := internalServers(internalConfig{
		AddrA: addrA, AddrB: addrB, CertFile: certFile, KeyFile: keyFile, Host: "auth.jyrac.stki.org",
	}, target)
	if len(servers) != 2 {
		t.Fatalf("servers=%d", len(servers))
	}
	startInternal(servers)
	defer func() {
		for _, s := range servers {
			_ = s.Close()
		}
	}()

	client := func(maxVer uint16) *http.Client {
		return &http.Client{
			Timeout: 3 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{
				RootCAs: pool, ServerName: "auth.jyrac.stki.org", MaxVersion: maxVer,
			}},
		}
	}
	get := func(c *http.Client, addr, path string) (int, string, error) {
		var resp *http.Response
		var err error
		for i := 0; i < 20; i++ { // 待ち受けの開始待ち
			resp, err = c.Get("https://" + addr + path)
			if err == nil {
				break
			}
			if strings.Contains(err.Error(), "refused") {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return 0, "", err
		}
		if err != nil {
			return 0, "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), nil
	}

	// A: 許可したパスは、通り、Host が固定される
	code, body, err := get(client(tls.VersionTLS13), addrA, "/.well-known/jwks")
	if err != nil || code != 200 || body != "host=auth.jyrac.stki.org" {
		t.Errorf("A allowed: code=%d body=%q err=%v", code, body, err)
	}
	// A: 管理 API は、403
	if code, _, err := get(client(tls.VersionTLS13), addrA, "/api/get-application?id=admin/x"); err != nil || code != 403 {
		t.Errorf("A admin: code=%d err=%v", code, err)
	}
	// B: 管理 API は通り、OIDC は 403
	if code, _, err := get(client(tls.VersionTLS13), addrB, "/api/get-application?id=admin/x"); err != nil || code != 200 {
		t.Errorf("B admin: code=%d err=%v", code, err)
	}
	if code, _, err := get(client(tls.VersionTLS13), addrB, "/.well-known/jwks"); err != nil || code != 403 {
		t.Errorf("B oidc: code=%d err=%v", code, err)
	}
	// TLS 1.2 は、つながらない
	if _, _, err := get(client(tls.VersionTLS12), addrA, "/.well-known/jwks"); err == nil {
		t.Errorf("TLS 1.2 で、つながってしまった")
	}
}

func TestInternalServersDisabled(t *testing.T) {
	target, _ := url.Parse("http://127.0.0.1:1")
	// アドレスなし
	if s := internalServers(internalConfig{}, target); s != nil {
		t.Errorf("アドレスなしで、有効になった")
	}
	// 証明書なし: 公開口を止めず、内部口だけを無効にする
	if s := internalServers(internalConfig{AddrA: "127.0.0.1:1", CertFile: "/nonexistent/c.pem", KeyFile: "/nonexistent/k.pem"}, target); s != nil {
		t.Errorf("証明書なしで、有効になった")
	}
}

// ---- 公開口の判定（Directus と同じ。観察と enforce）----

func TestGateObserveAndEnforce(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "app")
	}))
	defer up.Close()
	target, _ := url.Parse(up.URL)

	store := &Store{}
	store.p.Store(&Policy{allow: []entry{{prefix: netip.MustParsePrefix("203.0.113.10/32")}}})

	mk := func(enforce bool) *Gate {
		return &Gate{
			store:       store,
			next:        newProxy(target),
			health:      newHealthChecker(store, target.Host, "", false),
			healthPath:  "/gate/healthz",
			exactAllow:  map[string]bool{},
			redirectURL: "https://gate.example/",
			deniedURL:   "https://gate.example/denied",
			enforce:     enforce,
		}
	}
	do := func(g *Gate, ip string) int {
		r := httptest.NewRequest("GET", "/api/health", nil)
		if ip != "" {
			r.Header.Set("CF-Connecting-IP", ip)
		}
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		return w.Code
	}

	obs, enf := mk(false), mk(true)
	if c := do(obs, "198.51.100.1"); c != 200 {
		t.Errorf("observe: 許可外のIPが止まった code=%d", c)
	}
	if c := do(enf, "203.0.113.10"); c != 200 {
		t.Errorf("enforce: 許可IPが止まった code=%d", c)
	}
	if c := do(enf, "198.51.100.1"); c != 403 {
		t.Errorf("enforce: 許可外のIPが通った code=%d", c)
	}
	if c := do(enf, ""); c != 403 {
		t.Errorf("enforce: CFヘッダー無しが通った code=%d", c)
	}
}

func TestParseRulesCasdoor(t *testing.T) {
	if r, err := parseRules(""); err != nil || len(r) != 0 {
		t.Errorf("空: r=%v err=%v", r, err)
	}
	if _, err := parseRules("directus_news"); err == nil {
		t.Errorf("未知のルール名が通った")
	}
}
