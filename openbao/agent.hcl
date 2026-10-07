vault {
  address = "https://openbao.jyrac.stki.org"
}

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

exec {
  command                   = ["/server"]
  restart_on_secret_changes = "always"
}
