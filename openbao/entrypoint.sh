#!/bin/sh
set -e

if [ -z "$OPENBAO_WRAPPED_TOKEN" ]; then
  echo "OPENBAO_WRAPPED_TOKEN is not set" >&2
  exit 1
fi

REAL_TOKEN=$(bao unwrap -address="https://openbao.jyrac.stki.org" -field=token "$OPENBAO_WRAPPED_TOKEN")

if [ -z "$REAL_TOKEN" ]; then
  echo "unwrap failed" >&2
  exit 1
fi

echo "$REAL_TOKEN" > /tmp/vault-token

exec bao agent -config=/etc/openbao/agent.hcl
