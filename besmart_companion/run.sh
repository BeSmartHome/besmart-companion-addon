#!/bin/sh

set -e

echo "Starting BeSmart Companion..."

mkdir -p /data/tailscale
mkdir -p /var/run/tailscale

tailscaled \
  --tun=userspace-networking \
  --state=/data/tailscale/tailscaled.state \
  --socket=/var/run/tailscale/tailscaled.sock &

sleep 3

echo "Starting BeSmart API on port 8765..."

exec python3 /app/app.py
