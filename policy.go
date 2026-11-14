package main

// 許可・拒否リストの読み込み（Supabase）と、判定ロジック。
//
// ※ このファイルは Go のコンパイラなしで書きました（作成環境に Go が無いため）。
//    取り込んだら、まず `go vet ./...` と `go test ./...` を通してください。

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
)

// ---- ポリシー ----

type entry struct {
	prefix  netip.Prefix
	expires time.Time // ゼロ値 = 無期限
}

func (e entry) active(now time.Time) bool {
	return e.expires.IsZero() || now.Before(e.expires)
}

type Policy struct {
	allow []entry
	deny  []entry
}

func matches(list []entry, a netip.Addr, now time.Time) bool {
	for _, e := range list {
		if e.active(now) && e.prefix.Contains(a) {
			return true
		}
	}
	return false
}

type Decision struct {
	Allowed bool
	Reason  string
}

// decide: ポリシー未読み込み → 不正なCFヘッダー → 拒否リスト（優先）→ 許可リスト の順。
func decide(p *Policy, ip netip.Addr, ok bool, now time.Time) Decision {
	switch {
	case p == nil:
		return Decision{false, "policy_not_loaded"}
	case !ok:
		return Decision{false, "no_valid_cf_ip"}
	case matches(p.deny, ip, now):
		return Decision{false, "denylist"}
	case matches(p.allow, ip, now):
		return Decision{true, "allowlist"}
	default:
		return Decision{false, "not_in_allowlist"}
	}
}

// ParsePrefix は、DBの cidr / inet のテキストを正規化する（単体IP、IPv4-mapped も受け付ける）。
func ParsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, err2 := netip.ParseAddr(s)
		if err2 != nil {
			return netip.Prefix{}, err
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked(), nil
}

// 許可リストの安全網: DB側の仕様（IPv4は/32、IPv6は/64、手動でも/24・/48より狭い）より
// ずっと緩い下限。これより広い許可は、誤りとみなして無視する。
func acceptAllow(p netip.Prefix) bool {
	if p.Addr().Is4() {
		return p.Bits() >= 16
	}
	return p.Bits() >= 32
}

// ---- DB ----

type DBConfig struct {
	Host, Port, Name, User, Password, SSLMode, SSLRootCert string
}

func (c DBConfig) connConfig() (*pgx.ConnConfig, error) {
	q := url.Values{}
	q.Set("sslmode", c.SSLMode)
	if c.SSLRootCert != "" {
		q.Set("sslrootcert", c.SSLRootCert)
	}
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(c.User, c.Password),
		Host:     net.JoinHostPort(c.Host, c.Port),
		Path:     "/" + c.Name,
		RawQuery: q.Encode(),
	}
	cfg, err := pgx.ParseConfig(u.String())
	if err != nil {
		// エラー文に接続文字列（パスワード）が入らないよう、詳細は出さない
		return nil, fmt.Errorf("invalid GATE_DB_* settings")
	}
	// Supavisor（トランザクションモード、6543）はプリペアドステートメントが使えない
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	cfg.ConnectTimeout = 8 * time.Second
	return cfg, nil
}

type IngestHealth struct {
	Known      bool
	OK         bool
	IngestAgeS *float64
	UsersAgeS  *float64
	Err        error
}

func queryCIDRs(ctx context.Context, conn *pgx.Conn, q string, isAllow bool) ([]entry, error) {
	rows, err := conn.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []entry
	for rows.Next() {
		var cidr string
		var exp *time.Time
		if err := rows.Scan(&cidr, &exp); err != nil {
			return nil, err
		}
		p, err := ParsePrefix(cidr)
		if err != nil {
			log.Printf("GATE_POLICY_BAD_CIDR value=%q", cidr)
			continue
		}
		if isAllow && !acceptAllow(p) {
			log.Printf("GATE_POLICY_IGNORED reason=allow_too_broad value=%q", p.String())
			continue
		}
		if !isAllow && p.Bits() == 0 {
			log.Printf("GATE_POLICY_DENY_ALL value=%q", p.String())
		}
		e := entry{prefix: p}
		if exp != nil {
			e.expires = *exp
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Load は、短命の接続を1本開いて、3つのビューを読む。毎回つなぎ直す
// （トランザクションモードのプーラー越しに、接続を持ち続けないため）。
func (c DBConfig) Load(ctx context.Context) (*Policy, IngestHealth, error) {
	cfg, err := c.connConfig()
	if err != nil {
		return nil, IngestHealth{}, err
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, IngestHealth{}, fmt.Errorf("connect: %w", err)
	}
	defer conn.Close(context.Background())

	allow, err := queryCIDRs(ctx, conn, "select cidr::text, expires_at from gate.allow_cidrs", true)
	if err != nil {
		return nil, IngestHealth{}, fmt.Errorf("allow_cidrs: %w", err)
	}
	deny, err := queryCIDRs(ctx, conn, "select cidr::text, expires_at from gate.deny_cidrs", false)
	if err != nil {
		return nil, IngestHealth{}, fmt.Errorf("deny_cidrs: %w", err)
	}

	var h IngestHealth
	var ok *bool
	var ia, ua *float64
	err = conn.QueryRow(ctx,
		"select ok, ingest_age_s::float8, users_age_s::float8 from gate.ingest_health limit 1",
	).Scan(&ok, &ia, &ua)
	if err != nil {
		h.Err = err
	} else {
		h = IngestHealth{Known: true, OK: ok != nil && *ok, IngestAgeS: ia, UsersAgeS: ua}
	}
	return &Policy{allow: allow, deny: deny}, h, nil
}

// ---- ストアと定期読み込み ----

type Store struct {
	p atomic.Pointer[Policy] // 最初の読み込みに成功するまで nil
}

func (s *Store) Get() *Policy { return s.p.Load() }

type throttle struct{ last time.Time }

func (t *throttle) ok(every time.Duration, now time.Time) bool {
	if t.last.IsZero() || now.Sub(t.last) >= every {
		t.last = now
		return true
	}
	return false
}

func fmtAge(p *float64) string {
	if p == nil {
		return "null"
	}
	return fmt.Sprintf("%.0f", *p)
}

// Run は interval ごとにDBを読み、成功したらポリシーを差し替える。
// 失敗したら、前回の値のまま動く（期限は、判定のたびにメモリ上で確認される）。
// 許可リストが空の結果は、全員を締め出す事故を避けるため、採用しない。
func (s *Store) Run(ctx context.Context, c DBConfig, interval time.Duration) {
	var (
		lastOK              time.Time
		lastAllow, lastDeny = -1, -1
		failT               throttle
		loadT               throttle
		staleT              throttle
		ingestT             throttle
		ingestBad           bool
	)
	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		lctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		p, h, err := c.Load(lctx)
		cancel()
		now := time.Now()

		switch {
		case err != nil:
			if failT.ok(5*time.Minute, now) {
				log.Printf("GATE_POLICY_LOAD_FAILED err=%v", err)
			}
		case len(p.allow) == 0:
			if failT.ok(5*time.Minute, now) {
				log.Printf("GATE_POLICY_REJECTED reason=empty_allowlist deny=%d", len(p.deny))
			}
		default:
			s.p.Store(p)
			lastOK = now
			if len(p.allow) != lastAllow || len(p.deny) != lastDeny || loadT.ok(10*time.Minute, now) {
				log.Printf("GATE_POLICY_LOADED allow=%d deny=%d", len(p.allow), len(p.deny))
				lastAllow, lastDeny = len(p.allow), len(p.deny)
			}
		}

		if !lastOK.IsZero() && now.Sub(lastOK) > 10*time.Minute && staleT.ok(5*time.Minute, now) {
			log.Printf("GATE_POLICY_STALE age_s=%d", int(now.Sub(lastOK).Seconds()))
		}

		// 取り込みの状態は、通知のためだけに使う（判定にも /gate/healthz にも影響させない）
		if err == nil {
			switch {
			case h.Err != nil:
				if ingestT.ok(5*time.Minute, now) {
					log.Printf("GATE_INGEST_HEALTH_UNREADABLE err=%v", h.Err)
				}
			case !h.OK:
				ingestBad = true
				if ingestT.ok(5*time.Minute, now) {
					log.Printf("GATE_INGEST_STALE ingest_age_s=%s users_age_s=%s",
						fmtAge(h.IngestAgeS), fmtAge(h.UsersAgeS))
				}
			case ingestBad:
				ingestBad = false
				ingestT.last = time.Time{}
				log.Printf("GATE_INGEST_RECOVERED")
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
