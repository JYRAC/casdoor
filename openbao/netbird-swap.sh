#!/bin/sh
# 一時のピアから、OpenBao に置いた固定のピア（IP が変わらない）に、切り替える（段階 2）。
# 固定のピアは、NetBird の IP 宛ての通信を localhost へ転送して、127.0.0.1:8210 の S3 を NetBird に出す。
#   入力: 環境変数 NB_CONFIG_B64（登録済みのピア設定。base64）
#   成功したら 0。失敗したら、一時のピアに戻して 1（OpenBao への経路は、残す）。
export NB_USE_NETSTACK_MODE=true
export NB_CONFIG=/tmp/nb/config.json
export NB_DAEMON_ADDR=unix:///tmp/nb/netbird.sock
export NB_LOG_FILE=console
H="${NB_HOSTNAME:-casdoor}"

stop_nb() {
  if [ -s /tmp/nb/service.pid ]; then
    kill "$(cat /tmp/nb/service.pid)" 2>/dev/null
  fi
  i=0
  while netbird status >/dev/null 2>&1 && [ "$i" -lt 15 ]; do
    i=$((i + 1))
    sleep 1
  done
  rm -f /tmp/nb/netbird.sock
}

start_nb() { # $1: 転送（true/false）  $2: ホスト名
  if [ "$1" = true ]; then
    export NB_ENABLE_NETSTACK_LOCAL_FORWARDING=true
  else
    unset NB_ENABLE_NETSTACK_LOCAL_FORWARDING
  fi
  netbird service run > /tmp/nb/service.log 2>&1 &
  echo $! > /tmp/nb/service.pid
  i=0
  while [ "$i" -lt 30 ]; do
    netbird status >/dev/null 2>&1 && break
    i=$((i + 1))
    sleep 1
  done
  netbird up --hostname "$2" > /tmp/nb/up.log 2>&1 || return 1
  i=0
  while [ "$i" -lt 40 ]; do
    netbird status 2>/dev/null | grep -qi "Management: Connected" && return 0
    i=$((i + 1))
    sleep 1
  done
  return 1
}

if [ -z "${NB_CONFIG_B64:-}" ]; then
  echo "NB: NB_CONFIG_B64 がありません" >&2
  exit 1
fi

( umask 077; cp "$NB_CONFIG" /tmp/nb/boot-config.json ) 2>/dev/null
stop_nb

if ( umask 077; printf '%s' "$NB_CONFIG_B64" | base64 -d > "$NB_CONFIG" ) 2>/dev/null && [ -s "$NB_CONFIG" ] \
   && start_nb true "$H"; then
  echo "NB: connected (固定ピア) ip=$(netbird status --ipv4 2>/dev/null || echo unknown) hostname=$H"
  rm -f /tmp/nb/boot-config.json
  : > /tmp/nb/stable   # 公開側の /healthz が、固定のピアで出ているかを見るための、目印
  exit 0
fi

echo "NB: 固定ピアへの切り替えに失敗しました:" >&2
tail -n 5 /tmp/nb/up.log 2>/dev/null | sed 's/^/NB:   /' >&2
tail -n 5 /tmp/nb/service.log 2>/dev/null | sed 's/^/NB:   /' >&2
# 一時のピアに戻す（OpenBao への経路を残す）
stop_nb
if [ -s /tmp/nb/boot-config.json ]; then
  ( umask 077; cp /tmp/nb/boot-config.json "$NB_CONFIG" )
  start_nb false "${H}-boot" || echo "NB: 一時のピアへの復帰にも失敗しました" >&2
fi
exit 1
