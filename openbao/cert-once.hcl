# 内部口（A、B）の TLS 証明書を、OpenBao の PKI から、起動時に 1 回だけ発行する（entrypoint.sh が、
# vault ブロックを前に付けて、`timeout 60 bao agent -config=… -exit-after-auth` で実行する）。
# 出力は、/tmp/tls/pki/ の下。KV から受け取った自己署名（/tmp/tls/cert.pem、key.pem）とは、別の場所に置く
# （途中で失敗しても、戻り先の鍵を壊さないため）。bundle.pem は、葉に中間 CA を連結したもの。
# 名前は、ロール casdoor が許す auth.jyrac.stki.org だけ。TTL は 2160h（90 日）。

auto_auth {
  method {
    type = "token_file"
    config = {
      token_file_path = "/tmp/vault-token"
    }
  }
}

template_config {
  exit_on_retry_failure = true
}

template {
  destination = "/tmp/tls/pki/bundle.pem"
  perms       = "0600"
  contents    = <<EOC
{{ with pkiCert "pki_int/issue/casdoor" "common_name=auth.jyrac.stki.org" "ttl=2160h" }}{{ .Cert }}{{ .CA }}
{{ .Key | writeToFile "/tmp/tls/pki/key.pem" "" "" "0600" }}{{ end }}
EOC
}
