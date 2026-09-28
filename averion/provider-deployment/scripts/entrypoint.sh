#!/bin/sh
set -eu
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
root=$(CDPATH= cd -- "$here/.." && pwd)
# shellcheck disable=SC1091
. "$root/scripts/fail-closed.sh"
fail_closed_check "$root"
if [ "${AVERION_FAIL_CLOSED_ONLY:-}" = "1" ]; then
  echo "READINESS_FAIL_CLOSED pass"
  exit 0
fi
if [ "$root" = "/averion" ]; then
  cmp -s /etc/nginx/nginx.conf "$root/ingress/nginx.provider.conf" || {
    echo "READINESS_FAIL_CLOSED nginx config drift" >&2
    exit 1
  }
fi
exec nginx -g 'daemon off;' -c /etc/nginx/nginx.conf
