FROM node:24-bookworm-slim

ARG XRAY_DOWNLOAD_URL="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl openssl unzip \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/xray-manager

COPY package.json ./
COPY server.js ./
COPY public ./public
COPY bin ./bin

RUN mkdir -p /opt/xray-codex \
  && curl -fsSL "$XRAY_DOWNLOAD_URL" -o /tmp/xray.zip \
  && unzip -q /tmp/xray.zip -d /opt/xray-codex \
  && chmod +x /opt/xray-codex/xray \
  && rm -f /tmp/xray.zip \
  && mkdir -p /etc/xray-manager /etc/xray-codex /var/lib/xray-manager /var/log/xray-codex /var/backups/xray-codex

ENV NODE_ENV=production \
  MANAGER_MODE=docker \
  PUBLIC_IP=127.0.0.1 \
  XRAY_BIN=/opt/xray-codex/xray \
  XRAY_CONFIG=/etc/xray-codex/config.json \
  STATE_PATH=/var/lib/xray-manager/state.json \
  SECRETS_PATH=/etc/xray-manager/secrets.json \
  CREDENTIALS_PATH=/etc/xray-manager/credentials.txt \
  SESSION_PATH=/var/lib/xray-manager/sessions.json

EXPOSE 80 443 10808

VOLUME ["/etc/xray-manager", "/etc/xray-codex", "/var/lib/xray-manager", "/var/log/xray-codex", "/var/backups/xray-codex"]

CMD ["node", "server.js"]
