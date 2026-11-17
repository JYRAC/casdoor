package main

// Casdoor 用のルール。
//   1. 公開口の「IP制限の例外にする公開の読み取り」のルール（GATE_PUBLIC_RULES）。Casdoor は、今は、なし。
//   2. 内部口（A、B）の許可リスト。NetBird の内側から、サーバー側の通信だけを、完全一致で通す。
//
// 内部口は、公開口と違って、IP では相手を区別できない（NetBird の転送は、送信元が 127.0.0.1 に見える）。
// 区別は、NetBird の ACL（ポート単位、一方向）と、各 API の認証（client_secret、ベアラートークン、
// 管理者アプリの資格情報）で行う。ここでは、通すパスを、必要最小限に絞る。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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

// ---- casdoor-sync(Google Workspace → Casdoor のユーザーとグループの同期)----
//
// casdoor-sync は、sync-client-secrets.yml と同じ管理者アプリの資格情報(admin-client)で呼ぶ。
// この資格情報は、Casdoor の認可では、全組織に届く。そこで、ゲートで、組織 JYRAC の、同期に必要な操作だけに絞る。
//   - 通すのは、パスとクエリが完全一致のものだけ(削除は、通さない)
//   - 書き込みは、本文も見る: owner が JYRAC、name が正しい書式、管理者の権限(isAdmin、isGlobalAdmin)を付けない、
//     所属先のグループ(groups)は JYRAC のものだけ
//   - update-user は、columns が必須で、同期が書く列だけ(owner、is_admin などは、書けない)

const syncOrg = "JYRAC"

var (
	reSyncName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	reSyncID   = regexp.MustCompile(`^JYRAC/[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	reDigits   = regexp.MustCompile(`^[0-9]{1,6}$`)
)

// 同期が、update-user で書く列。ここにないものは、書けない。
var syncUserColumns = map[string]bool{
	"email": true, "display_name": true, "is_forbidden": true, "properties": true, "groups": true,
}

const syncMaxBody = 1 << 20

// bodyJSON は、本文(1 MiB まで)を読み、JSON のオブジェクトとして返す。読んだあとは、本文を元に戻す。
func bodyJSON(r *http.Request) (map[string]any, bool) {
	if r.Body == nil {
		return nil, false
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, syncMaxBody+1))
	if err != nil || len(b) > syncMaxBody {
		return nil, false
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil || m == nil {
		return nil, false
	}
	return m, true
}

// groupsInOrg は、groups が、JYRAC のグループの id(JYRAC/<name>)の配列であること。
func groupsInOrg(v any) bool {
	if v == nil {
		return true
	}
	arr, ok := v.([]any)
	if !ok {
		return false
	}
	for _, x := range arr {
		s, ok := x.(string)
		if !ok || !reSyncID.MatchString(s) {
			return false
		}
	}
	return true
}

// syncBodyOK は、本文が、組織 JYRAC の、管理者でないオブジェクトであること。
// Casdoor の JSON の読み取りは、キーの大文字小文字を区別しないので、ここも区別しない(同名のキーが複数あれば、すべてを検査する)。
// idName が空でなければ、name は、それと一致すること。
func syncBodyOK(body map[string]any, idName string, user bool) bool {
	ownerSeen, nameSeen := false, false
	for k, v := range body {
		switch {
		case strings.EqualFold(k, "owner"):
			s, ok := v.(string)
			if !ok || s != syncOrg {
				return false
			}
			ownerSeen = true
		case strings.EqualFold(k, "name"):
			s, ok := v.(string)
			if !ok || !reSyncName.MatchString(s) || (idName != "" && s != idName) {
				return false
			}
			nameSeen = true
		case user && (strings.EqualFold(k, "isAdmin") || strings.EqualFold(k, "isGlobalAdmin")):
			if b, ok := v.(bool); !ok || b {
				return false
			}
		case user && strings.EqualFold(k, "groups"):
			if !groupsInOrg(v) {
				return false
			}
		}
	}
	return ownerSeen && nameSeen
}

// syncColumnsOK は、columns が、同期が書く列だけであること(空は、不可: 空だと、全列を更新する)。
func syncColumnsOK(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range strings.Split(s, ",") {
		if !syncUserColumns[c] {
			return false
		}
	}
	return true
}

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

// syncAdd: 追加。クエリは無し。本文を検査する。
func syncAdd(p string, user bool) internalRule {
	return func(r *http.Request) bool {
		if r.Method != http.MethodPost || r.URL.Path != p || r.URL.RawQuery != "" {
			return false
		}
		body, ok := bodyJSON(r)
		return ok && syncBodyOK(body, "", user)
	}
}

// syncUpdate: 更新。クエリは id=JYRAC/<name>(update-user は、これに columns が必須)。本文を検査する。
func syncUpdate(p string, user bool) internalRule {
	return func(r *http.Request) bool {
		if r.Method != http.MethodPost || r.URL.Path != p {
			return false
		}
		q, ok := parseStrictQuery(r)
		if !ok || !reSyncID.MatchString(q.Get("id")) {
			return false
		}
		if user {
			if len(q) != 2 || !syncColumnsOK(q.Get("columns")) {
				return false
			}
		} else if len(q) != 1 {
			return false
		}
		body, ok := bodyJSON(r)
		return ok && syncBodyOK(body, strings.TrimPrefix(q.Get("id"), syncOrg+"/"), user)
	}
}

// 内部口 B: 管理 API。Actions だけが、NetBird の ACL で届く。
//
//	sync-client-secrets.yml:  管理者の組織(admin)のアプリの、get-application と update-application。
//	casdoor-sync:             組織 JYRAC の、ユーザーとグループの、一覧、追加、更新だけ(削除は、通さない)。
//
// 通すのは、パスとクエリが完全一致のものだけ。casdoor-sync の書き込みは、本文も検査する(上)。
var internalBRules = []internalRule{
	adminAppQuery(http.MethodGet, "/api/get-application"),
	adminAppQuery(http.MethodPost, "/api/update-application"),

	// casdoor-sync
	exactNoQuery(http.MethodGet, "/api/health"),
	syncListQuery(http.MethodGet, "/api/get-users"),
	syncListQuery(http.MethodGet, "/api/get-groups"),
	syncAdd("/api/add-user", true),
	syncAdd("/api/add-group", false),
	syncUpdate("/api/update-user", true),
	syncUpdate("/api/update-group", false),
}
