# vault ブロック（接続先、証明書）は、entrypoint.sh が、経路に合わせて作って、この前に付ける。

auto_auth {
  method {
    type = "token_file"
    config = {
      token_file_path = "/tmp/vault-token"
    }
  }
}

env_template "dataSourceName" {
  contents = "{{ with secret \"database/creds/casdoor\" }}postgresql://{{ .Data.username }}.kuajmlczxracqobxkzee:{{ .Data.password }}@aws-0-us-west-2.pooler.supabase.com:6543/postgres?sslmode=require&binary_parameters=yes{{ end }}"
}

# ゲート専用の、読み取りだけのDB資格情報（Casdoor 本体のロールとは別）。
# GATE_ で始まる環境変数は、ゲートが Casdoor の子プロセスには渡さない。
env_template "GATE_DB_USER" {
  contents = "{{ with secret \"database/creds/gate-reader\" }}{{ .Data.username }}.kuajmlczxracqobxkzee{{ end }}"
}

env_template "GATE_DB_PASSWORD" {
  contents = "{{ with secret \"database/creds/gate-reader\" }}{{ .Data.password }}{{ end }}"
}

# Worker（pr.jyrac.stki.org）の、署名つき例外の秘密（signed.go）。Casdoor の client_secret とは、別の値。
# キーが無いときは "<no value>" になるが、短いので、ゲートは、例外を無効にして起動する。
env_template "GATE_SIGNED_SECRET" {
  contents = "{{ with secret \"kv/data/secrets/casdoor/config\" }}{{ index .Data.data \"gate_signed_secret\" }}{{ end }}"
}

# Casdoor 本体（/server）は、ゲートが起動する（Dockerfile の GATE_CHILD_CMD）。
# ゲートは、`env -u` を通して起動する。Agent が OpenBao に出るための設定（SOCKS5 のプロキシ、
# OpenBao 向けの BAO_*）を、ゲートと Casdoor に渡さないため。渡すと、Casdoor の外向きの通信
# （外部の IdP、ストレージ、メール、Webhook など）まで、NetBird の SOCKS5 に流れて、失敗する。
exec {
  command = [
    "/usr/bin/env",
    "-u", "HTTPS_PROXY", "-u", "HTTP_PROXY", "-u", "NO_PROXY",
    "-u", "https_proxy", "-u", "http_proxy", "-u", "no_proxy",
    "-u", "BAO_ADDR", "-u", "BAO_CACERT", "-u", "BAO_TLS_SERVER_NAME", "-u", "BAO_CLIENT_TIMEOUT",
    "/app/gate"
  ]
  restart_on_secret_changes = "always"
}
