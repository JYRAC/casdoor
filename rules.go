package main

// Casdoor 用のルール。
//   1. 公開口の「IP制限の例外にする公開の読み取り」のルール（GATE_PUBLIC_RULES）。Casdoor は、今は、なし。
//   2. 内部口（A、B）の許可リスト。NetBird の内側から、サーバー側の通信だけを、完全一致で通す。
//
// 内部口は、公開口と違って、IP では相手を区別できない（NetBird の転送は、送信元が 127.0.0.1 に見える）。
// 区別は、NetBird の ACL（ポート単位、一方向）と、各 API の認証（client_secret、ベアラートークン、
// 管理者アプリの資格情報）で行う。ここでは、通すパスを、必要最小限に絞る。

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// ---- 公開口の例外（Casdoor は、今は、なし）----

type publicRule func(r *http.Request) bool

var publicRules = map[string]publicRule{}

// parseRules は、"name1,name2" を読む。未知の名前があれば、起動時に失敗させる。
func parseRules(s string) ([]publicRule, error) {
	var out []publicRule
	for _, name := range strings.Split(s, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		rule, ok := publicRules[name]
		if !ok {
			return nil, fmt.Errorf("未知のルール名 %q", name)
		}
		out = append(out, rule)
	}
	return out, nil
}

// ---- 内部口の許可リスト ----

// internalRule は、通してよいリクエストなら true を返す。
type internalRule func(r *http.Request) bool

// parseStrictQuery は、クエリを読む。同じキーの重複があれば、不一致にする。
func parseStrictQuery(r *http.Request) (url.Values, bool) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, false
	}
	for _, vs := range q {
		if len(vs) != 1 {
			return nil, false
		}
	}
	return q, true
}

// exactNoQuery: メソッドとパスが完全一致で、クエリが無い。
func exactNoQuery(method, p string) internalRule {
	return func(r *http.Request) bool {
		return r.Method == method && r.URL.Path == p && r.URL.RawQuery == ""
	}
}

// exactAnyQuery: メソッドとパスが完全一致（クエリは、何でもよい。OAuth のトークン取得は、クエリで値を渡す実装もあるため）。
func exactAnyQuery(method, p string) internalRule {
	return func(r *http.Request) bool {
		return r.Method == method && r.URL.Path == p
	}
}

// patternNoQuery: メソッドが一致し、パスが正規表現に一致し、クエリが無い。
func patternNoQuery(method string, re *regexp.Regexp) internalRule {
	return func(r *http.Request) bool {
		return r.Method == method && re.MatchString(r.URL.Path) && r.URL.RawQuery == ""
	}
}

// 管理者の組織（sync-client-secrets.yml の ORG=admin）のアプリだけを、対象にする。
var reAdminAppID = regexp.MustCompile(`^admin/[A-Za-z0-9_.-]{1,64}$`)

// adminAppQuery: メソッドとパスが完全一致で、クエリは id=admin/<アプリ名> の 1 つだけ。
func adminAppQuery(method, p string) internalRule {
	return func(r *http.Request) bool {
		if r.Method != method || r.URL.Path != p {
			return false
		}
		q, ok := parseStrictQuery(r)
		return ok && len(q) == 1 && reAdminAppID.MatchString(q.Get("id"))
	}
}

// アプリ単位の discovery と JWKS（/.well-known/<アプリ名>/...）。Casdoor は、アプリごとの URL も出す。
var (
	reAppDiscovery = regexp.MustCompile(`^/\.well-known/[A-Za-z0-9_-]{1,64}/openid-configuration$`)
	reAppJWKS      = regexp.MustCompile(`^/\.well-known/[A-Za-z0-9_-]{1,64}/jwks$`)
)

// 内部口 A: OIDC のサーバー側の通信だけ（Directus、Vikunja、Vaultwarden、OpenBao の管理者ログイン）。
//
//	discovery、JWKS、トークン（更新も、同じ POST）、userinfo。
//	userinfo は、Authorization ヘッダーだけ（URL にトークンを載せる形は、通さない）。
var internalARules = []internalRule{
	exactNoQuery(http.MethodGet, "/.well-known/openid-configuration"),
	patternNoQuery(http.MethodGet, reAppDiscovery),
	exactNoQuery(http.MethodGet, "/.well-known/jwks"),
	patternNoQuery(http.MethodGet, reAppJWKS),
	exactAnyQuery(http.MethodPost, "/api/login/oauth/access_token"),
	exactNoQuery(http.MethodGet, "/api/userinfo"),
}

// casdoor-sync(Google Workspace → Casdoor のユーザーとグループの同期)の対象の組織。
const syncOrg = "JYRAC"

var (
	// 同期するユーザーとグループの id(JYRAC/<Name>)。Name は、メールのローカル部(英数字で始まり、英数字、. _ - が続く)
	reSyncID = regexp.MustCompile(`^JYRAC/[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	reDigits = regexp.MustCompile(`^[0-9]{1,6}$`)
	// update-user の columns(列名のカンマ区切り)
	reColumns = regexp.MustCompile(`^[a-z_]{1,40}(,[a-z_]{1,40}){0,19}$`)
)

// syncListQuery: メソッドとパスが完全一致で、クエリは owner=JYRAC、p、pageSize の 3 つだけ。
func syncListQuery(method, p string) internalRule {
	return func(r *http.Request) bool {
		if r.Method != method || r.URL.Path != p {
			return false
		}
		q, ok := parseStrictQuery(r)
		return ok && len(q) == 3 && q.Get("owner") == syncOrg &&
			reDigits.MatchString(q.Get("p")) && reDigits.MatchString(q.Get("pageSize"))
	}
}

// syncIDQuery: メソッドとパスが完全一致で、クエリは id=JYRAC/<Name>。withColumns のときだけ、columns を足してよい。
func syncIDQuery(method, p string, withColumns bool) internalRule {
	return func(r *http.Request) bool {
		if r.Method != method || r.URL.Path != p {
			return false
		}
		q, ok := parseStrictQuery(r)
		if !ok || !reSyncID.MatchString(q.Get("id")) {
			return false
		}
		switch len(q) {
		case 1:
			return true
		case 2:
			return withColumns && reColumns.MatchString(q.Get("columns"))
		default:
			return false
		}
	}
}

// 内部口 B: 管理 API。Actions だけが、NetBird の ACL で届く。
//
//	sync-client-secrets.yml:  管理者の組織(admin)のアプリの、get-application と update-application。
//	casdoor-sync:             組織 JYRAC の、ユーザーとグループの、一覧、追加、更新だけ(削除は、通さない)。
//
// 通すのは、パスとクエリが完全一致のものだけ。本文は、見ない(各 API の認証で守る。Basic 認証の、アプリの資格情報)。
var internalBRules = []internalRule{
	adminAppQuery(http.MethodGet, "/api/get-application"),
	adminAppQuery(http.MethodPost, "/api/update-application"),

	// casdoor-sync
	exactNoQuery(http.MethodGet, "/api/health"),
	syncListQuery(http.MethodGet, "/api/get-users"),
	syncListQuery(http.MethodGet, "/api/get-groups"),
	exactNoQuery(http.MethodPost, "/api/add-user"),
	exactNoQuery(http.MethodPost, "/api/add-group"),
	syncIDQuery(http.MethodPost, "/api/update-user", true),
	syncIDQuery(http.MethodPost, "/api/update-group", false),
}
