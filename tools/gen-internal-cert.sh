#!/bin/sh
# C2 の準備: 内部口（A、B）の TLS 用の、自己署名のリーフ証明書を作る。
#   名前: auth.jyrac.stki.org（Casdoor の discovery、iss、Host を、公開ドメインのまま合わせるため）
#   鍵: ECDSA P-256、有効期間 365 日、CA ではない、serverAuth のみ
#
# 過去の不具合: `openssl req -addext basicConstraints=...` を使うと、basicConstraints が 2 つになり、
# Go（OpenBao）が duplicate extension で拒否した。ここでは、専用の設定ファイル（-config）だけで拡張を指定し、
# 最後に、各拡張が 1 個だけであることを確認する（確認に失敗したら、ファイルを残さずに終了する）。
#
# 使い方: tools/gen-internal-cert.sh [出力先ディレクトリ(既定 ./cert-out)] [名前(既定 auth.jyrac.stki.org)]
#   出力: cert.pem（公開情報。各クライアントにピン留めする）、key.pem（秘密。OpenBao の KV にだけ入れる）
set -eu
umask 077

OUT="${1:-./cert-out}"
NAME="${2:-auth.jyrac.stki.org}"
DAYS="${DAYS:-365}"

mkdir -p "$OUT"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/openssl.cnf" <<EOF
[req]
distinguished_name = dn
x509_extensions    = v3
prompt             = no

[dn]
CN = ${NAME}

[v3]
basicConstraints     = critical, CA:FALSE
keyUsage             = critical, digitalSignature
extendedKeyUsage     = serverAuth
subjectAltName       = DNS:${NAME}
subjectKeyIdentifier = hash
EOF

openssl ecparam -name prime256v1 -genkey -noout -out "$TMP/key.pem"
openssl req -new -x509 -key "$TMP/key.pem" -sha256 -days "$DAYS" -config "$TMP/openssl.cnf" -out "$TMP/cert.pem"

# 各拡張が、ちょうど 1 個であることを確認する
TEXT=$(openssl x509 -in "$TMP/cert.pem" -noout -text)
for ext in "X509v3 Basic Constraints" "X509v3 Key Usage" "X509v3 Extended Key Usage" \
           "X509v3 Subject Alternative Name" "X509v3 Subject Key Identifier"; do
  n=$(printf '%s\n' "$TEXT" | grep -c "^ *${ext}:" || true)
  if [ "$n" != "1" ]; then
    echo "拡張 '${ext}' が ${n} 個あります（1 個のはずです）。中止します" >&2
    exit 1
  fi
done
printf '%s\n' "$TEXT" | grep -q "CA:FALSE" || { echo "CA:FALSE ではありません。中止します" >&2; exit 1; }

# 鍵と証明書が対応していることを確認する
A=$(openssl x509 -in "$TMP/cert.pem" -noout -pubkey | openssl sha256)
B=$(openssl pkey -in "$TMP/key.pem" -pubout | openssl sha256)
[ "$A" = "$B" ] || { echo "鍵と証明書が対応していません。中止します" >&2; exit 1; }

cp "$TMP/cert.pem" "$OUT/cert.pem"
cp "$TMP/key.pem" "$OUT/key.pem"
chmod 600 "$OUT/key.pem"
echo "作成しました: $OUT/cert.pem（公開）、$OUT/key.pem（秘密）"
echo "SHA-256 フィンガープリント: $(openssl x509 -in "$OUT/cert.pem" -noout -fingerprint -sha256)"
echo "期限: $(openssl x509 -in "$OUT/cert.pem" -noout -enddate)"
