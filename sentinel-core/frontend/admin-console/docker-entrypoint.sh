#!/bin/sh
set -e

RUNTIME_CONFIG_PATH="/usr/share/nginx/html/runtime-config.js"

cat <<EOF > "$RUNTIME_CONFIG_PATH"
window.__SENTINEL__ = {
  apiUrl: "${SENTINEL_API_URL:-}",
  env: "${SENTINEL_ENV:-production}",
  demoAuth: "${SENTINEL_DEMO_AUTH:-false}",
  appName: "${SENTINEL_APP_NAME:-SENTINEL}",
  supportEmail: "${SENTINEL_SUPPORT_EMAIL:-security@sentinel.local}"
}
EOF

if [ -n "$SENTINEL_API_PROXY" ]; then
  envsubst '$SENTINEL_API_PROXY' < /etc/nginx/templates/nginx-proxy.conf > /etc/nginx/conf.d/default.conf
else
  cp /etc/nginx/templates/nginx.conf /etc/nginx/conf.d/default.conf
fi

exec nginx -g "daemon off;"
