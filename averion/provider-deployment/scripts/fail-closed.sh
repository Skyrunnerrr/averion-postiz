#!/bin/sh
# Provider readiness. Exits non-zero unless the injected profile matches the
# frozen flags and the encryption key is present. Does not print secret values.
set -eu

fail() {
  echo "READINESS_FAIL_CLOSED $1" >&2
  exit 1
}

is_true() {
  [ "$1" = "true" ]
}

is_false() {
  [ "$1" = "false" ]
}

key_ok() {
  key=$1
  if printf '%s' "$key" | grep -Eq '^[0-9a-fA-F]{64}$'; then
    return 0
  fi
  bytes=$(printf '%s' "$key" | base64 -d 2>/dev/null | wc -c | tr -d ' ')
  [ "$bytes" = "32" ]
}

reject_placeholder() {
  name=$1
  value=$2
  if [ -z "$value" ]; then
    fail "missing $name"
  fi
  case $value in
    *postiz-password*|*changeme*|*change-me*|sk-proj-*|sk_live_*|random\ string\ that\ is\ unique\ to\ every\ install*)
      fail "placeholder $name"
      ;;
  esac
}

fail_closed_check() {
  root=$1
  flags=$root/config/provider.flags.env
  nginx=$root/ingress/nginx.provider.conf
  matrix=$root/ingress/ingress-matrix.json
  allow=$root/egress/allowlist.txt
  [ -f "$flags" ] || fail "flags file missing"
  [ -f "$nginx" ] || fail "nginx config missing"
  [ -f "$matrix" ] || fail "ingress matrix missing"
  [ -f "$allow" ] || fail "egress allowlist missing"

  # Required profile is exact. A runtime override that opens a write gate fails.
  is_true "${AVERION_PROVIDER_PROFILE:-}" || fail "AVERION_PROVIDER_PROFILE"
  is_true "${TOKEN_ENCRYPTION_REQUIRED:-}" || fail "TOKEN_ENCRYPTION_REQUIRED"
  is_true "${MCP_WRITE_DISABLED:-}" || fail "MCP_WRITE_DISABLED"
  is_true "${PUBLIC_API_WRITE_DISABLED:-}" || fail "PUBLIC_API_WRITE_DISABLED"
  is_false "${ORG_API_KEY_BROWSER_EXPOSURE:-}" || fail "ORG_API_KEY_BROWSER_EXPOSURE"
  is_false "${AUTOPOST_ENABLED:-}" || fail "AUTOPOST_ENABLED"
  is_true "${DISABLE_REGISTRATION:-}" || fail "DISABLE_REGISTRATION"
  if [ -n "${OPENAI_API_KEY:-}" ]; then
    fail "OPENAI_API_KEY must be empty"
  fi

  key_ok "${TOKEN_ENCRYPTION_KEY:-}" || fail "TOKEN_ENCRYPTION_KEY"
  reject_placeholder JWT_SECRET "${JWT_SECRET:-}"
  reject_placeholder DATABASE_URL "${DATABASE_URL:-}"
  reject_placeholder REDIS_URL "${REDIS_URL:-}"
  case ${DATABASE_URL} in
    postgresql://*) ;;
    *) fail "DATABASE_URL scheme" ;;
  esac
  case ${REDIS_URL} in
    redis://*) ;;
    *) fail "REDIS_URL scheme" ;;
  esac
  reject_placeholder FACEBOOK_APP_ID "${FACEBOOK_APP_ID:-}"
  reject_placeholder FACEBOOK_APP_SECRET "${FACEBOOK_APP_SECRET:-}"
  reject_placeholder INSTAGRAM_APP_ID "${INSTAGRAM_APP_ID:-}"
  reject_placeholder INSTAGRAM_APP_SECRET "${INSTAGRAM_APP_SECRET:-}"
  reject_placeholder THREADS_APP_ID "${THREADS_APP_ID:-}"
  reject_placeholder THREADS_APP_SECRET "${THREADS_APP_SECRET:-}"

  grep -q 'AVERION_PROVIDER_PROFILE=true' "$flags" || fail "flags profile"
  grep -q 'AUTOPOST_ENABLED=false' "$flags" || fail "flags autopost"
  grep -q 'ORG_API_KEY_BROWSER_EXPOSURE=false' "$flags" || fail "flags api key"
  if grep -q 'TOKEN_ENCRYPTION_KEY=' "$flags"; then
    fail "flags file must not carry the encryption key"
  fi

  if grep -q 'proxy_pass' "$nginx"; then
    fail "nginx proxy_pass"
  fi
  if grep -q 'latest' "$nginx"; then
    fail "nginx mutable tag"
  fi
  for path in \
    /integrations/social/facebook \
    /integrations/social/instagram \
    /integrations/social/instagram-standalone \
    /integrations/social/threads
  do
    grep -q "location = $path" "$nginx" || fail "missing callback $path"
  done
  grep -q 'return 403' "$nginx" || fail "nginx default deny"
  if [ "$(grep -c 'location = /integrations/social/' "$nginx")" -ne 4 ]; then
    fail "callback location count"
  fi

  if grep -Eq '"class": "[^"]+"' "$matrix"; then
    bad=$(grep -Eo '"class": "[^"]+"' "$matrix" | grep -Ev '"class": "(PUBLIC_REQUIRED|PRIVATE_SERVICE|OPS_ONLY|DENY)"' || true)
    if [ -n "$bad" ]; then
      fail "uncategorized class"
    fi
  else
    fail "matrix has no classes"
  fi
  grep -q '"defaultClass": "DENY"' "$matrix" || fail "matrix default"

  expected='api.instagram.com
graph.facebook.com
graph.instagram.com
graph.threads.net
www.facebook.com
www.instagram.com
www.threads.net'
  actual=$(grep -v '^$' "$allow" | sort)
  if [ "$actual" != "$expected" ]; then
    fail "egress allowlist"
  fi
}
