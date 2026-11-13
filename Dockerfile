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
# NetBird の実行確認（ビルド時）
RUN chmod +x /usr/local/bin/netbird && /usr/local/bin/netbird version

# OpenBao の NetBird 向け証明書（公開情報）
COPY openbao/ca.crt /etc/openbao/ca.crt
COPY openbao/agent.hcl /etc/openbao/agent.hcl
COPY openbao/entrypoint.sh /entrypoint.sh
COPY openbao/netbird-up.sh /netbird-up.sh
COPY openbao/netbird-swap.sh /netbird-swap.sh
COPY openbao/netbird-register.sh /netbird-register.sh
RUN sed -i 's/\r$//' /entrypoint.sh /netbird-up.sh /netbird-swap.sh /netbird-register.sh && \
    chmod +x /entrypoint.sh /netbird-up.sh /netbird-swap.sh /netbird-register.sh

EXPOSE 8000
ENTRYPOINT ["/entrypoint.sh"]
