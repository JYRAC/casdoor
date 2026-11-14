package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writePair は、指定した期間の証明書と鍵を、dir/<name>.pem と dir/<name>.key に書く。
// withChain が true のとき、cert には、葉の後ろに、別の証明書（中間のつもり）を連結する。
func writePair(t *testing.T, dir, name string, notBefore, notAfter time.Time, withChain bool) (certFile, keyFile string) {
	t.Helper()
	mk := func(cn string, ca bool) (*ecdsa.PrivateKey, []byte) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(time.Now().UnixNano()),
			Subject:               pkix.Name{CommonName: cn},
			DNSNames:              []string{"auth.jyrac.stki.org"},
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			IsCA:                  ca,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		return key, der
	}
	key, der := mk("auth.jyrac.stki.org", false)
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if withChain {
		_, inter := mk("intermediate", true)
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: inter})...)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certFile = filepath.Join(dir, name+".pem")
	keyFile = filepath.Join(dir, name+".key")
	if err := os.WriteFile(certFile, out, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return
}

// setDefaults は、既定の組（KV の自己署名）の場所を、テスト用に差し替える。
func setDefaults(t *testing.T, cert, key string) {
	t.Helper()
	oc, ok := defaultInternalCert, defaultInternalKey
	defaultInternalCert, defaultInternalKey = cert, key
	t.Cleanup(func() {
		defaultInternalCert, defaultInternalKey = oc, ok
		internalCertInfo.Store(nil)
	})
}

func healthHeaders(t *testing.T) http.Header {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer up.Close()
	target, _ := url.Parse(up.URL)
	h := newHealthChecker(&Store{}, target.Host, "", false)
	w := httptest.NewRecorder()
	h.serve(w, httptest.NewRequest("GET", "/gate/healthz", nil))
	if w.Code != 200 {
		t.Fatalf("healthz=%d", w.Code)
	}
	return w.Header()
}

func TestInternalCertPrimaryWithChain(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	na := now.Add(90 * 24 * time.Hour).Truncate(time.Second)
	pc, pk := writePair(t, dir, "pki", now.Add(-time.Hour), na, true) // 葉 + 中間の連結
	kc, kk := writePair(t, dir, "kv", now.Add(-time.Hour), now.Add(200*24*time.Hour), false)
	setDefaults(t, kc, kk)
	target, _ := url.Parse("http://127.0.0.1:1")

	if s := internalServers(internalConfig{AddrA: "127.0.0.1:1", CertFile: pc, KeyFile: pk}, target); len(s) != 1 {
		t.Fatalf("servers=%d", len(s))
	}
	h := healthHeaders(t)
	if got := h.Get("X-Gate-Internal-Cert-Source"); got != "pki" {
		t.Errorf("source=%q", got)
	}
	// 期限は、連結の、最初の 1 枚（葉）のもの
	if got := h.Get("X-Gate-Internal-Cert-Expires"); got != na.UTC().Format(time.RFC3339) {
		t.Errorf("expires=%q want %q", got, na.UTC().Format(time.RFC3339))
	}
}

func TestInternalCertFallback(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	kc, kk := writePair(t, dir, "kv", now.Add(-time.Hour), now.Add(200*24*time.Hour), false)
	setDefaults(t, kc, kk)
	target, _ := url.Parse("http://127.0.0.1:1")
	expiredC, expiredK := writePair(t, dir, "expired", now.Add(-48*time.Hour), now.Add(-time.Hour), false)

	for name, cfg := range map[string]internalConfig{
		"指定した組が、無い":   {AddrA: "127.0.0.1:1", CertFile: "/nonexistent/c.pem", KeyFile: "/nonexistent/k.pem"},
		"指定した組が、期限切れ": {AddrA: "127.0.0.1:1", CertFile: expiredC, KeyFile: expiredK},
		"鍵が、対応しない":    {AddrA: "127.0.0.1:1", CertFile: kc, KeyFile: expiredK},
	} {
		t.Run(name, func(t *testing.T) {
			if s := internalServers(cfg, target); len(s) != 1 {
				t.Fatalf("servers=%d", len(s))
			}
			if got := healthHeaders(t).Get("X-Gate-Internal-Cert-Source"); got != "kv-fallback" {
				t.Errorf("source=%q", got)
			}
		})
	}
}

func TestInternalCertNoneUsable(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	ec, ek := writePair(t, dir, "expired", now.Add(-48*time.Hour), now.Add(-time.Hour), false)
	setDefaults(t, ec, ek) // 既定の組も、期限切れ
	target, _ := url.Parse("http://127.0.0.1:1")
	if s := internalServers(internalConfig{AddrA: "127.0.0.1:1", CertFile: ec, KeyFile: ek}, target); s != nil {
		t.Fatal("使える証明書が無いのに、有効になった")
	}
	if internalCertInfo.Load() != nil {
		t.Error("無効のときは、期限の情報が、空のはず")
	}
	if got := healthHeaders(t).Get("X-Gate-Internal-Cert-Expires"); got != "" {
		t.Errorf("無効のときに、ヘッダーが出た: %q", got)
	}
}

func TestInternalCertNoHeaderWhenDisabled(t *testing.T) {
	setDefaults(t, "/nonexistent/c.pem", "/nonexistent/k.pem")
	target, _ := url.Parse("http://127.0.0.1:1")
	internalServers(internalConfig{}, target) // アドレスなし
	if got := healthHeaders(t).Get("X-Gate-Internal-Cert-Source"); got != "" {
		t.Errorf("ヘッダーが出た: %q", got)
	}
}

func TestInternalCertDefaultIsKV(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	kc, kk := writePair(t, dir, "kv", now.Add(-time.Hour), now.Add(200*24*time.Hour), false)
	setDefaults(t, kc, kk)
	target, _ := url.Parse("http://127.0.0.1:1")
	// 指定なし（既定の組）: 出どころは kv
	if s := internalServers(internalConfig{AddrA: "127.0.0.1:1", CertFile: kc, KeyFile: kk}, target); len(s) != 1 {
		t.Fatalf("servers=%d", len(s))
	}
	if got := healthHeaders(t).Get("X-Gate-Internal-Cert-Source"); got != "kv" {
		t.Errorf("source=%q", got)
	}
}
