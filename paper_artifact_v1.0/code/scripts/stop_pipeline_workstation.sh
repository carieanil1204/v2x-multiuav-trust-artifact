#!/usr/bin/env bash
set -euo pipefail

ROOT="$HOME/research/projects/v2x-multiuav-trust"
LOG_DIR="$ROOT/logs"

for f in cloud coordinator edge_z1 edge_z2 bridge_z1 bridge_z2; do
  pidfile="$LOG_DIR/$f.pid"
  if [ -f "$pidfile" ]; then
    pid=$(cat "$pidfile")
    if kill -0 "$pid" 2>/dev/null; then
      echo "Stopping $f pid=$pid"
      kill "$pid" || true
    fi
    rm -f "$pidfile"
  fi
done

sleep 1

pkill -f ai_cloud_llm_v85_zoneaware.py || true
pkill -f trust_coordinator_v2_handover_defense.py || true
pkill -f edge_ai_server_v91_handover_defense.py || true
pkill -f edge_cloud_bridge_v8_handover_passthrough.py || true

echo "Pipeline stopped."
