#!/bin/sh
set -e

RUNTIME_CONFIG_PATH="/usr/share/nginx/html/runtime-config.js"

cat <<EOF > "$RUNTIME_CONFIG_PATH"
window.__DRAGON_SCALE__ = {
  apiUrl: "${DRAGON_SCALE_API_URL:-}",
  env: "${DRAGON_SCALE_ENV:-production}",
  demoAuth: "${DRAGON_SCALE_DEMO_AUTH:-false}",
  appName: "${DRAGON_SCALE_APP_NAME:-DRAGON_SCALE}",
  supportEmail: "${DRAGON_SCALE_SUPPORT_EMAIL:-security@dragon-scale.local}"
}
EOF

if [ -n "$DRAGON_SCALE_API_PROXY" ]; then
  envsubst '$DRAGON_SCALE_API_PROXY' < /etc/nginx/templates/nginx-proxy.conf > /etc/nginx/conf.d/default.conf
else
  cp /etc/nginx/templates/nginx.conf /etc/nginx/conf.d/default.conf
fi

exec nginx -g "daemon off;"
