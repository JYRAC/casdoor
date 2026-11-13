#!/bin/sh
# 固定ピアの「1 回限りの登録」モード。Render 上で、NB_REGISTER_MODE=1 のときだけ、entrypoint.sh から呼ばれる。
# Casdoor 本体は起動しない（なので、本番のサービスではなく、使い捨ての別サービスで実行すること）。
#
#   NB_SETUP_KEY       必須。one-off（使用回数 1）、Ephemeral オフ、自動グループ casdoor
#   NB_HOSTNAME        固定の名前。既定 casdoor
#
# 成功すると、ログに `NB_CONFIG_B64=...` を 1 行出す（秘密鍵入り）。その値を OpenBao の
# kv/secrets/casdoor/config の netbird_config_b64 に入れて、サービスをすぐ削除する（ログも消える）。
umask 077
export NB_USE_NETSTACK_MODE=true
export NB_CONFIG=/tmp/nb/config.json
export NB_DAEMON_ADDR=unix:///tmp/nb/netbird.sock
export NB_LOG_FILE=console

if [ -z "${NB_SETUP_KEY:-}" ]; then
  echo "NB_SETUP_KEY がありません" >&2
  exit 1
fi
HOST="${NB_HOSTNAME:-casdoor}"
mkdir -p /tmp/nb
chmod 700 /tmp/nb
mask() { sed "s|${NB_SETUP_KEY}|***|g"; }

netbird service run > /tmp/nb/service.log 2>&1 &

i=0
while [ "$i" -lt 30 ]; do
  netbird status >/dev/null 2>&1 && break
  i=$((i + 1)); sleep 1
done

if ! netbird up --setup-key "$NB_SETUP_KEY" --hostname "$HOST" > /tmp/nb/up.log 2>&1; then
  echo "NB: netbird up に失敗しました（キーの種別、使用回数、期限を確認）:" >&2
  tail -n 5 /tmp/nb/up.log | mask >&2
else
  i=0
  while [ "$i" -lt 40 ]; do
    netbird status 2>/dev/null | grep -qi "Management: Connected" && break
    i=$((i + 1)); sleep 1
  done
  if netbird status 2>/dev/null | grep -qi "Management: Connected" && [ -s "$NB_CONFIG" ]; then
    echo "NB: 登録しました hostname=$HOST ip=$(netbird status --ipv4 2>/dev/null || echo unknown)"
    echo "NB_CONFIG_B64=$(base64 "$NB_CONFIG" | tr -d '\n')"
    echo "NB: 上の NB_CONFIG_B64 の値を、OpenBao に入れて、このサービスを削除してください（ログに秘密鍵が出ています）"
  else
    echo "NB: 接続を確認できませんでした" >&2
    tail -n 5 /tmp/nb/service.log | mask >&2
  fi
fi

# Render が「起動した」と判断できるように、公開ポートを開けておく（中身は無い）
mkdir -p /tmp/empty
if command -v httpd >/dev/null 2>&1; then
  exec httpd -f -p "${PORT:-10000}" -h /tmp/empty
fi
exec sleep 3600
