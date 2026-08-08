#!/usr/bin/with-contenv sh

set -e

echo "Starting BeSmart Companion..."

mkdir -p /var/lib/tailscale

tailscaled \
  --tun=userspace-networking \
  --state=/var/lib/tailscale/tailscaled.state \
  --socket=/var/run/tailscale/tailscaled.sock &

sleep 3

echo "Starting BeSmart API..."

exec python3 /app/app.py
