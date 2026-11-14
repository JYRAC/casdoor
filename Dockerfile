# Go製IPゲートをビルド
#   gate.go（ゲートと監視）、policy.go（許可リストの読み込み）、rules.go（Casdoor の例外と、内部口の許可リスト）、
#   internal.go（内部口 A、B）を、Goモジュールとしてビルドする。go.sum は、ビルド時に pgx の版から作る
#   （Goのチェックサムデータベースで改ざんを検証）。pgx の版を上げるときは PGX_VERSION を書き換える。
FROM golang:1.27-alpine AS gate-build
# 依存の pgx が、より新しいGoを求める場合に、必要な版を自動で取得する
ENV GOTOOLCHAIN=auto \
    CGO_ENABLED=0
ARG PGX_VERSION=v5.9.2
WORKDIR /src
COPY gate.go policy.go rules.go internal.go signed.go ./
RUN go mod init gate && \
    go get github.com/jackc/pgx/v5@${PGX_VERSION} && \
    go mod tidy && \
    go build -trimpath -ldflags="-s -w" -o /out/gate .

# NetBird クライアントを取得
FROM alpine:3.24 AS netbird-download
ARG NETBIRD_VERSION=0.81.5
RUN apk add --no-cache curl && \
    curl -fsSL -o /tmp/netbird.tar.gz \
      "https://github.com/netbirdio/netbird/releases/download/v${NETBIRD_VERSION}/netbird_${NETBIRD_VERSION}_linux_amd64.tar.gz" && \
    mkdir -p /tmp/netbird-bin && \
    tar -xzf /tmp/netbird.tar.gz -C /tmp/netbird-bin netbird

FROM casbin/casdoor:v4.26.0
COPY conf/app.conf /conf/app.conf

ARG BAO_VERSION=2.7.2
USER root
RUN curl -fsSL -o /tmp/bao.tar.gz \
      "https://github.com/openbao/openbao/releases/download/v${BAO_VERSION}/openbao_${BAO_VERSION}_linux_amd64.tar.gz" && \
    mkdir -p /tmp/bao-extract && \
    tar -xzf /tmp/bao.tar.gz -C /tmp/bao-extract && \
    mv /tmp/bao-extract/bao /usr/local/bin/bao && \
    chmod +x /usr/local/bin/bao && \
    rm -rf /tmp/bao.tar.gz /tmp/bao-extract

COPY --from=netbird-download /tmp/netbird-bin/netbird /usr/local/bin/netbird
COPY --from=gate-build /out/gate /app/gate
# NetBird と、ゲートの実行確認（ビルド時）
RUN chmod +x /usr/local/bin/netbird /app/gate && /usr/local/bin/netbird version

# ゲートが起動するアプリ（Casdoor）。秘密ではないので、コードと一緒に版管理する。
#   Casdoor は、ゲートの内側（127.0.0.1:3457。conf/app.conf の httpaddr と httpport）だけで待ち受ける。
#   公開ポート（$PORT）はゲートが受ける。$PORT は 8000 に固定する（Render の環境変数 PORT=8000）。
#   Render は、公開ポートを、初回の検出で記録していて、変わると「ポートが変わった」と判断して、デプロイを
#   再起動する。再起動では、使用済みのラップトークンと NetBird のキーで、起動に失敗する。
#   GATE_WAIT_READY_SEC: Casdoor が応答するまで、ゲートは公開ポートを開かない（Render が、準備前に切り替えない）。
#   内部口 A（OIDC のサーバー側の通信）と B（管理 API）は、NetBird の転送が届く 127.0.0.1 で、TLS 1.3 で待ち受ける。
#   証明書と鍵は、OpenBao の kv/secrets/casdoor/config（tls_cert_pem、tls_key_pem）から、entrypoint.sh が /tmp/tls/ に置く。
ENV GATE_CHILD_CMD='["/server"]' \
    GATE_UPSTREAM=127.0.0.1:3457 \
    GATE_UPSTREAM_HEALTH_PATH=/api/health \
    GATE_WAIT_READY_SEC=600 \
    GATE_INTERNAL_A_ADDR=127.0.0.1:8443 \
    GATE_INTERNAL_B_ADDR=127.0.0.1:8444 \
    GATE_INTERNAL_HOST=auth.jyrac.stki.org

# OpenBao の NetBird 向け証明書（公開情報）
COPY openbao/ca.crt /etc/openbao/ca.crt
COPY openbao/agent.hcl /etc/openbao/agent.hcl
COPY openbao/cert-once.hcl /etc/openbao/cert-once.hcl
COPY openbao/entrypoint.sh /entrypoint.sh
COPY openbao/netbird-up.sh /netbird-up.sh
COPY openbao/netbird-swap.sh /netbird-swap.sh
COPY openbao/netbird-register.sh /netbird-register.sh
RUN sed -i 's/\r$//' /entrypoint.sh /netbird-up.sh /netbird-swap.sh /netbird-register.sh && \
    chmod +x /entrypoint.sh /netbird-up.sh /netbird-swap.sh /netbird-register.sh

EXPOSE 8000
ENTRYPOINT ["/entrypoint.sh"]
