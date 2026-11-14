package main

// 内部口（A、B）: NetBird の内側から届く、サーバー側の通信だけを受ける、TLS の待ち受け。
//
//   GATE_INTERNAL_A_ADDR   内部口 A の待ち受け（例 127.0.0.1:8443）。空なら、無効
//   GATE_INTERNAL_B_ADDR   内部口 B の待ち受け（例 127.0.0.1:8444）。空なら、無効
//   GATE_INTERNAL_CERT     証明書（PEM）。OpenBao から、entrypoint.sh が /tmp/tls/cert.pem に置く
//   GATE_INTERNAL_KEY      秘密鍵（PEM）。同上
//   GATE_INTERNAL_HOST     アプリに渡す Host（既定 auth.jyrac.stki.org）。discovery の URL と iss を、
//                          公開ドメインのまま合わせるため
//
// 公開口と違って、観察モードは無い（新しい口なので、移すクライアントが無く、最初から許可リストで絞る）。
// 証明書か鍵が無い、または読めないときは、内部口を開かず、公開口は、そのまま動く。
//
// NetBird の転送は、送信元が 127.0.0.1 に見えるので、ここでは、IP で相手を区別しない
// （NetBird の ACL と、各 API の認証で守る。rules.go）。

import (
	"crypto/tls"
	"errors"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

type internalConfig struct {
	AddrA, AddrB, CertFile, KeyFile, Host string
}

func internalConfigFromEnv() internalConfig {
	return internalConfig{
		AddrA:    getenv("GATE_INTERNAL_A_ADDR", ""),
		AddrB:    getenv("GATE_INTERNAL_B_ADDR", ""),
		CertFile: getenv("GATE_INTERNAL_CERT", "/tmp/tls/cert.pem"),
		KeyFile:  getenv("GATE_INTERNAL_KEY", "/tmp/tls/key.pem"),
		Host:     getenv("GATE_INTERNAL_HOST", "auth.jyrac.stki.org"),
	}
}

func anyRule(rules []internalRule, r *http.Request) bool {
	for _, rule := range rules {
		if rule(r) {
			return true
		}
	}
	return false
}

// newInternalHandler は、許可リストに一致したものだけを、next に渡す。それ以外は 403。
// ログには、パスだけを出す（クエリに、値が入ることがあるため）。
func newInternalHandler(name string, rules []internalRule, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !cleanExact(r) || !anyRule(rules, r) {
			log.Printf("GATE_INTERNAL_DENY port=%s method=%q path=%q", name, r.Method, r.URL.Path)
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		log.Printf("GATE_INTERNAL_ALLOW port=%s method=%q path=%q", name, r.Method, r.URL.Path)
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		next.ServeHTTP(w, r)
	})
}

// newInternalProxy は、Host を、公開ドメインに固定して、アプリへ渡す。
// 内部の呼び出し元が付けた転送系のヘッダーや、CF-Connecting-IP（利用者の IP の偽装）は、渡さない。
func newInternalProxy(target *url.URL, host string) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = host
			for _, h := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-Ip", "CF-Connecting-IP"} {
				pr.Out.Header.Del(h)
			}
			pr.Out.Header.Set("X-Forwarded-Proto", "https")
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("internal proxy error: %v", err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}
}

func newInternalServer(addr, name string, rules []internalRule, proxy http.Handler, cert tls.Certificate) *http.Server {
	return &http.Server{
		Addr:    addr,
		Handler: newInternalHandler(name, rules, proxy),
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
		},
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
}

// internalServers は、設定で有効な内部口の、サーバーを作る（まだ待ち受けない）。
func internalServers(c internalConfig, upstream *url.URL) []*http.Server {
	if c.AddrA == "" && c.AddrB == "" {
		log.Printf("GATE_INTERNAL_DISABLED reason=no_addr")
		return nil
	}
	cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		// エラー文に、鍵の中身は入らない。公開口は、そのまま動かす
		log.Printf("GATE_INTERNAL_DISABLED reason=no_cert err=%v", err)
		return nil
	}
	proxy := newInternalProxy(upstream, c.Host)
	var out []*http.Server
	if c.AddrA != "" {
		out = append(out, newInternalServer(c.AddrA, "A", internalARules, proxy, cert))
	}
	if c.AddrB != "" {
		out = append(out, newInternalServer(c.AddrB, "B", internalBRules, proxy, cert))
	}
	return out
}

// startInternal は、内部口の待ち受けを始める（背景で）。
func startInternal(servers []*http.Server) {
	for _, s := range servers {
		go func(s *http.Server) {
			log.Printf("GATE_INTERNAL_LISTENING addr=%s tls=1.3", s.Addr)
			if err := s.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("GATE_INTERNAL_FAILED addr=%s err=%v", s.Addr, err)
			}
		}(s)
	}
}
