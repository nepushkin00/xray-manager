#!/usr/bin/env bash
set -euo pipefail

certbot certonly \
  --non-interactive \
  --agree-tos \
  --register-unsafely-without-email \
  --preferred-profile shortlived \
  --webroot \
  --webroot-path /var/lib/xray-manager/acme-challenge \
  --ip-address 85.155.96.187 \
  --deploy-hook 'systemctl restart xray-manager.service'

systemctl restart xray-manager.service
