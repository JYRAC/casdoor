#!/bin/sh
set -e
umask 077

# 固定ピアの 1 回限りの登録モード（使い捨ての別サービスで、NB_REGISTER_MODE=1 のときだけ）。Casdoor は起動しない。
if [ "${NB_REGISTER_MODE:-0}" = "1" ]; then
  exec /netbird-register.sh
fi

if [ -z "${OPENBAO_WRAPPED_TOKEN:-}" ]; then
  echo "OPENBAO_WRAPPED_TOKEN is not set" >&2
  exit 1
fi

# 段階 C1: Casdoor を NetBird に出す（固定のピア）。IP ゲートと、内部口は、まだ無い（C2 以降）。
# 公開側は、今までどおり Casdoor が、そのまま受ける（app.conf の httpport）。
#
# 接続先:
#   OPENBAO_NB_ADDR     OpenBao の NetBird 側の宛先。例 https://100.125.124.43:8210（IP 指定。名前は引けない）
#   NB_SETUP_KEY        NetBird の使い捨てキー（Actions がデプロイのたびに作って、Render に渡す）。
#                       これで、仮のピアとして参加して、OpenBao に出る。固定のピアの設定（IP が変わらない）は、
#                       OpenBao の kv/secrets/casdoor/config の netbird_config_b64 から受け取って、切り替える
#   OPENBAO_PUBLIC_ADDR 公開側の宛先（移行中の、一時的な代替。段階 4 で、公開側を閉じたら、不要）
PUBLIC_ADDR="${OPENBAO_PUBLIC_ADDR:-https://openbao.jyrac.stki.org}"
NB_ADDR="${OPENBAO_NB_ADDR:-}"
NB_SNI="${OPENBAO_NB_SERVER_NAME:-openbao.netbird.cloud}"

export BAO_CLIENT_TIMEOUT=30s

VIA=""

use_public() {
  unset HTTPS_PROXY HTTP_PROXY NO_PROXY https_proxy http_proxy no_proxy BAO_CACERT BAO_TLS_SERVER_NAME
  export BAO_ADDR="$PUBLIC_ADDR"
  VIA=public
}

# NetBird 経由: SOCKS5（127.0.0.1:1080）に通し、ピン留めした証明書で、この名前を確認する。
use_netbird() {
  export HTTPS_PROXY=socks5://127.0.0.1:1080 https_proxy=socks5://127.0.0.1:1080
  export NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost
  export BAO_CACERT=/etc/openbao/ca.crt
  export BAO_TLS_SERVER_NAME="$NB_SNI"
  export BAO_ADDR="$NB_ADDR"
  VIA=netbird
}

NB_OK=0
if [ -n "$NB_ADDR" ] && [ -n "${NB_SETUP_KEY:-}" ]; then
  if /netbird-up.sh; then
    NB_OK=1
    use_netbird
  else
    echo "NB: NetBird に接続できませんでした。公開側の OpenBao に接続します（移行中の、一時的な代替）" >&2
  fi
fi
# キーは、もう使わない。Casdoor 本体の環境に残さない。
unset NB_SETUP_KEY
[ -n "$VIA" ] || use_public

unwrap() {
  bao unwrap -field=token "$OPENBAO_WRAPPED_TOKEN" 2>/tmp/unwrap.err
}

REAL_TOKEN=$(unwrap) || REAL_TOKEN=""
if [ -z "$REAL_TOKEN" ] && [ "$VIA" = "netbird" ]; then
  echo "NB: NetBird 経由の unwrap に失敗しました: $(tail -n 3 /tmp/unwrap.err | tr '\n' ' ')" >&2
  echo "NB: 公開側の OpenBao で、もう一度試します（移行中の、一時的な代替）" >&2
  use_public
  REAL_TOKEN=$(unwrap) || REAL_TOKEN=""
fi
if [ -z "$REAL_TOKEN" ]; then
  echo "unwrap failed: $(tail -n 3 /tmp/unwrap.err | tr '\n' ' ')" >&2
  exit 1
fi

printf '%s' "$REAL_TOKEN" > /tmp/vault-token

# 内部口（NetBird 向け、TLS 1.3）の、証明書と秘密鍵（OpenBao から受け取る。unwrap と同じ経路を使う）。
# 受け取れないときは、内部口だけが開かない（ゲートが、ログに GATE_INTERNAL_DISABLED を出す）。
# 公開側の Casdoor は、そのまま動く。
mkdir -p /tmp/tls
BAO_TOKEN="$REAL_TOKEN" bao kv get -mount=kv -field=tls_cert_pem secrets/casdoor/config > /tmp/tls/cert.pem 2>/tmp/tls.err || true
BAO_TOKEN="$REAL_TOKEN" bao kv get -mount=kv -field=tls_key_pem secrets/casdoor/config > /tmp/tls/key.pem 2>>/tmp/tls.err || true
if [ -s /tmp/tls/cert.pem ] && [ -s /tmp/tls/key.pem ]; then
  chmod 600 /tmp/tls/key.pem
else
  rm -f /tmp/tls/cert.pem /tmp/tls/key.pem
  echo "OpenBao から tls_cert_pem / tls_key_pem を受け取れません。内部口は開きません: $(tail -n 2 /tmp/tls.err | tr '\n' ' ')" >&2
fi

# 固定のピアの設定を、OpenBao から受け取って、一時のピアから切り替える（unwrap と同じ経路を使う）。
# 受け取れない、または、切り替えに失敗したときは、一時のピアのまま続ける（OpenBao には出られるが、
# Casdoor は NetBird に出ない。C1 の段階では、利用者にも、他のアプリにも、影響しない）。
if [ "$NB_OK" = 1 ]; then
  NB_CFG=$(BAO_TOKEN="$REAL_TOKEN" bao kv get -mount=kv -field=netbird_config_b64 secrets/casdoor/config 2>/tmp/nbcfg.err) || NB_CFG=""
  if [ -n "$NB_CFG" ]; then
    NB_CONFIG_B64="$NB_CFG" /netbird-swap.sh || echo "NB: 固定のピアに切り替えられませんでした。Casdoor は NetBird に出ません" >&2
  else
    echo "NB: OpenBao から netbird_config_b64 を受け取れませんでした。Casdoor は NetBird に出ません: $(tail -n 2 /tmp/nbcfg.err | tr '\n' ' ')" >&2
  fi
  unset NB_CFG
fi

# 切り替えの直後は、SOCKS5（127.0.0.1:1080）や、OpenBao への経路が、まだ使えないことがある。
# Agent は、認証に失敗すると、待ち時間が倍々に増えて（数分）、起動が進まなくなるので、
# NetBird 経由で届くことを確認してから、Agent を起動する（最大で、約 3 分待つ）。
# 届かないときは、診断をログに出して、公開側の OpenBao で、Agent を起動する（移行中の、一時的な代替）。
if [ "$VIA" = "netbird" ]; then
  i=0
  REACH=0
  while [ "$i" -lt 20 ]; do
    if BAO_TOKEN="$REAL_TOKEN" BAO_CLIENT_TIMEOUT=8s bao token lookup >/dev/null 2>/tmp/reach.err; then
      REACH=1
      break
    fi
    i=$((i + 1))
    sleep 3
  done
  if [ "$REACH" = 1 ]; then
    echo "NB: NetBird 経由で OpenBao に届きました（確認 $((i + 1)) 回目）"
  else
    echo "NB: 約 3 分待っても、NetBird 経由で OpenBao に届きません: $(tail -n 2 /tmp/reach.err | tr '\n' ' ')" >&2
    NB_DAEMON_ADDR=unix:///tmp/nb/netbird.sock netbird status 2>&1 | head -n 15 | sed 's/^/NB:   /' >&2 || true
    tail -n 8 /tmp/nb/service.log 2>/dev/null | sed 's/^/NB:   /' >&2 || true
    echo "NB: 公開側の OpenBao で、Agent を起動します（移行中の、一時的な代替）" >&2
    use_public
  fi
fi

unset REAL_TOKEN OPENBAO_WRAPPED_TOKEN

# Agent の接続設定（vault ブロック）は、経路によって変わるので、ここで作って、agent.hcl の前に付ける。
{
  echo 'vault {'
  echo "  address = \"$BAO_ADDR\""
  if [ "$VIA" = "netbird" ]; then
    echo '  ca_cert         = "/etc/openbao/ca.crt"'
    echo "  tls_server_name = \"$NB_SNI\""
  fi
  echo '}'
  echo
  cat /etc/openbao/agent.hcl
} > /tmp/agent.hcl

echo "OPENBAO_VIA=$VIA addr=$BAO_ADDR"
exec bao agent -config=/tmp/agent.hcl
