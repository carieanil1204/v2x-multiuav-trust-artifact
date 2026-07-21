#!/usr/bin/env bash
set -euo pipefail

echo "===== LISTENING PORTS ====="
ss -ltnp | grep -E ':6666|:9997|:9998|:9996|:9995|:9999' || true

missing=0
for port in 6666 9997 9998 9996 9999 9995; do
  if ! ss -ltnp | grep -q ":$port "; then
    echo "MISSING_PORT=$port"
    missing=1
  fi
done

if [[ "$missing" -ne 0 ]]; then
  echo "ERROR: Required pipeline ports are missing. Do not run NS-3."
  exit 2
fi

echo "PIPELINE_PORT_CHECK=PASS"
