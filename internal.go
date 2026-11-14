package main

// 内部口（A、B）: NetBird の内側から届く、サーバー側の通信だけを受ける、TLS の待ち受け。
//
//   GATE_INTERNAL_A_ADDR   内部口 A の待ち受け（例 127.0.0.1:8443）。空なら、無効
//   GATE_INTERNAL_B_ADDR   内部口 B の待ち受け（例 127.0.0.1:8444）。空なら、無効
//   GATE_INTERNAL_CERT     証明書（PEM。葉と中間の連結でもよい）。既定 /tmp/tls/cert.pem（OpenBao の KV の自己署名）。
//                          PKI から発行できたときだけ、entrypoint.sh が、/tmp/tls/pki/bundle.pem を指定する
//   GATE_INTERNAL_KEY      秘密鍵（PEM）。既定 /tmp/tls/key.pem。同上
//
// 指定した証明書が、読めない、または、期限切れのときは、既定の組（KV の自己署名）で、もう一度試す（出どころは kv-fallback）。
// どちらも使えなければ、内部口だけを開かない。読み込んだ、最初の 1 枚の期限は、/gate/healthz のヘッダー
// （X-Gate-Internal-Cert-Expires）に出す。watchdog が、残り日数を見て、再デプロイを起動する。
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
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
	"time"
)

// 既定の証明書（KV の自己署名）。PKI の証明書が使えないときの、戻り先でもある（テストで差し替える）。
var (
	defaultInternalCert = "/tmp/tls/cert.pem"
	defaultInternalKey  = "/tmp/tls/key.pem"
)

// certInfo は、読み込んだ証明書の、最初の 1 枚の期限と、出どころ。
//
//	pki:         GATE_INTERNAL_CERT で指定した組（entrypoint.sh が、PKI から発行できたときに指定する）
//	kv:          既定の組（KV の自己署名）を、そのまま使っている
//	kv-fallback: 指定した組が、使えなかったので、既定の組に戻った
type certInfo struct {
	notAfter time.Time
	source   string
}

// internalCertInfo は、内部口が有効なときだけ、入る。/gate/healthz が、ヘッダーに出す。
var internalCertInfo atomic.Pointer[certInfo]

type internalConfig struct {
	AddrA, AddrB, CertFile, KeyFile, Host string
}

func internalConfigFromEnv() internalConfig {
	return internalConfig{
		AddrA:    getenv("GATE_INTERNAL_A_ADDR", ""),
		AddrB:    getenv("GATE_INTERNAL_B_ADDR", ""),
		CertFile: getenv("GATE_INTERNAL_CERT", defaultInternalCert),
		KeyFile:  getenv("GATE_INTERNAL_KEY", defaultInternalKey),
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
			stripSignedHeaders(pr.Out.Header)
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

// loadInternalCert は、指定した組を試し、だめなら既定の組を試す。期限切れは、使えないものとして扱う。
func loadInternalCert(c internalConfig, now time.Time) (tls.Certificate, *certInfo, error) {
	type cand struct{ cert, key, source string }
	isDefault := c.CertFile == defaultInternalCert && c.KeyFile == defaultInternalKey
	var cands []cand
	if isDefault {
		cands = []cand{{c.CertFile, c.KeyFile, "kv"}}
	} else {
		cands = []cand{{c.CertFile, c.KeyFile, "pki"}, {defaultInternalCert, defaultInternalKey, "kv-fallback"}}
	}
	var firstErr error
	for _, k := range cands {
		cert, err := tls.LoadX509KeyPair(k.cert, k.key)
		if err == nil {
			var leaf *x509.Certificate
			if leaf, err = x509.ParseCertificate(cert.Certificate[0]); err == nil && !now.Before(leaf.NotAfter) {
				err = fmt.Errorf("expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
			}
			if err == nil {
				return cert, &certInfo{notAfter: leaf.NotAfter, source: k.source}, nil
			}
		}
		// エラー文に、鍵の中身は入らない
		log.Printf("GATE_INTERNAL_CERT_UNUSABLE source=%s err=%v", k.source, err)
		if firstErr == nil {
			firstErr = err
		}
	}
	return tls.Certificate{}, nil, firstErr
}

// internalServers は、設定で有効な内部口の、サーバーを作る（まだ待ち受けない）。
func internalServers(c internalConfig, upstream *url.URL) []*http.Server {
	internalCertInfo.Store(nil)
	if c.AddrA == "" && c.AddrB == "" {
		log.Printf("GATE_INTERNAL_DISABLED reason=no_addr")
		return nil
	}
	now := time.Now()
	cert, info, err := loadInternalCert(c, now)
	if err != nil {
		// 公開口は、そのまま動かす
		log.Printf("GATE_INTERNAL_DISABLED reason=no_cert err=%v", err)
		return nil
	}
	log.Printf("GATE_INTERNAL_CERT source=%s not_after=%s days_left=%d",
		info.source, info.notAfter.UTC().Format(time.RFC3339), int(info.notAfter.Sub(now).Hours()/24))
	internalCertInfo.Store(info)
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
