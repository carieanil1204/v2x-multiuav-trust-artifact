#!/usr/bin/env bash
set -euo pipefail

ROOT="$HOME/research/projects/v2x-multiuav-trust"

# [HYBRID-VEREMI-LAUNCH]
# Default is shadow mode: compute/log p_veremi but do not affect decisions.
export VEREMI_EVIDENCE_ENABLE="${VEREMI_EVIDENCE_ENABLE:-1}"
export VEREMI_EVIDENCE_MODE="${VEREMI_EVIDENCE_MODE:-shadow}"
export VEREMI_MIN_VIOLATIONS="${VEREMI_MIN_VIOLATIONS:-2}"
export VEREMI_TS_SLACK="${VEREMI_TS_SLACK:-0.05}"
export VEREMI_POS_TOL="${VEREMI_POS_TOL:-15.0}"
export VEREMI_SPEED_TOL="${VEREMI_SPEED_TOL:-8.0}"
export VEREMI_MAX_GAP="${VEREMI_MAX_GAP:-3.0}"
export VEREMI_MAX_SPEED="${VEREMI_MAX_SPEED:-35.0}"

LOG_DIR="$ROOT/logs"
LEDGER_DIR="$ROOT/ledgers"
TRACE_DIR="$LOG_DIR/traces"

mkdir -p "$LOG_DIR" "$LEDGER_DIR" "$TRACE_DIR"

echo "============================================================"
echo " Launching V2X Multi-UAV Handover Defense Pipeline"
echo " Workstation mode: local NS-3 + local Edge + local Cloud LLM"
echo " Ollama model: llama3:latest"
echo "============================================================"

echo
echo "[CHECK] Ollama availability"
if ! command -v ollama >/dev/null 2>&1; then
  echo "[ERROR] ollama command not found."
  exit 1
fi

if ! ollama list | grep -q "llama3:latest"; then
  echo "[ERROR] llama3:latest model not found."
  echo "Run: ollama pull llama3:latest"
  exit 1
fi

echo "[OK] Ollama found and llama3:latest available"

echo
echo "[1/6] Starting local Cloud LLM on 127.0.0.1:6666"
LEDGER_PATH="$LEDGER_DIR/blockchain_ledger.jsonl" \
TRACE_DIR="$TRACE_DIR" \
OLLAMA_MODEL="llama3:latest" \
OLLAMA_HOST="127.0.0.1:11434" \
python3 -u "$ROOT/pipeline/cloud/ai_cloud_llm_v85_zoneaware.py" --port 6666 \
  > "$LOG_DIR/cloud.log" 2>&1 &

echo $! > "$LOG_DIR/cloud.pid"
sleep 2

echo "[2/6] Starting Trust Coordinator on 127.0.0.1:9997"
ZONE1_EDGE_HOST=127.0.0.1 \
ZONE1_EDGE_PORT=9999 \
ZONE2_EDGE_HOST=127.0.0.1 \
ZONE2_EDGE_PORT=9995 \
TRACE_DIR="$TRACE_DIR" \
python3 -u "$ROOT/pipeline/coordinator/trust_coordinator_v2_handover_defense.py" --port 9997 \
  > "$LOG_DIR/coordinator.log" 2>&1 &

echo $! > "$LOG_DIR/coordinator.pid"
sleep 2

echo "[3/6] Starting Edge AI Zone 1 on 127.0.0.1:9999"
ZONE_ID=1 \
DISABLE_LLM_DECISION=1 \
LEARNING_RATE=0 \
COORDINATOR_HOST=127.0.0.1 \
COORDINATOR_PORT=9997 \
HANDOVER_SAFEWIN_DECAY=0.30 \
POST_HANDOVER_K=8 \
POST_HANDOVER_REP_FACTOR=0.25 \
POST_HANDOVER_DISABLE_UPGRADE=1 \
python3 -u "$ROOT/pipeline/edge/edge_ai_server_v91_handover_defense_hybrid_veremi.py" \
  --port 9999 \
  --zone-id 1 \
  --coordinator-host 127.0.0.1 \
  --coordinator-port 9997 \
  > "$LOG_DIR/edge_z1.log" 2>&1 &

echo $! > "$LOG_DIR/edge_z1.pid"
sleep 2

echo "[4/6] Starting Edge AI Zone 2 on 127.0.0.1:9995"
ZONE_ID=2 \
DISABLE_LLM_DECISION=1 \
LEARNING_RATE=0 \
COORDINATOR_HOST=127.0.0.1 \
COORDINATOR_PORT=9997 \
HANDOVER_SAFEWIN_DECAY=0.30 \
POST_HANDOVER_K=8 \
POST_HANDOVER_REP_FACTOR=0.25 \
POST_HANDOVER_DISABLE_UPGRADE=1 \
python3 -u "$ROOT/pipeline/edge/edge_ai_server_v91_handover_defense_hybrid_veremi.py" \
  --port 9995 \
  --zone-id 2 \
  --coordinator-host 127.0.0.1 \
  --coordinator-port 9997 \
  > "$LOG_DIR/edge_z2.log" 2>&1 &

echo $! > "$LOG_DIR/edge_z2.pid"
sleep 2

echo "[5/6] Starting Bridge Zone 1 on 127.0.0.1:9998"
ZONE_ID=1 \
DISABLE_LLM_DECISION=1 \
LEARNING_RATE=0 \
EDGE_HOST=127.0.0.1 \
EDGE_PORT=9999 \
CLOUD_HOST=127.0.0.1 \
CLOUD_PORT=6666 \
BRIDGE_PORT=9998 \
python3 -u "$ROOT/pipeline/bridge/edge_cloud_bridge_v8_handover_passthrough.py" \
  > "$LOG_DIR/bridge_z1.log" 2>&1 &

echo $! > "$LOG_DIR/bridge_z1.pid"
sleep 2

echo "[6/6] Starting Bridge Zone 2 on 127.0.0.1:9996"
ZONE_ID=2 \
DISABLE_LLM_DECISION=1 \
LEARNING_RATE=0 \
EDGE_HOST=127.0.0.1 \
EDGE_PORT=9995 \
CLOUD_HOST=127.0.0.1 \
CLOUD_PORT=6666 \
BRIDGE_PORT=9996 \
python3 -u "$ROOT/pipeline/bridge/edge_cloud_bridge_v8_handover_passthrough.py" \
  > "$LOG_DIR/bridge_z2.log" 2>&1 &

echo $! > "$LOG_DIR/bridge_z2.pid"
sleep 2

echo
echo "============================================================"
echo " Pipeline started"
echo "============================================================"
echo "Cloud LLM       : 127.0.0.1:6666"
echo "Coordinator     : 127.0.0.1:9997"
echo "Edge Zone 1     : 127.0.0.1:9999"
echo "Bridge Zone 1   : 127.0.0.1:9998"
echo "Edge Zone 2     : 127.0.0.1:9995"
echo "Bridge Zone 2   : 127.0.0.1:9996"
echo "Ollama          : 127.0.0.1:11434"
echo "Model           : llama3:latest"
echo

echo "[PORT CHECK]"
ss -ltnp | egrep ':6666|:9997|:9999|:9998|:9995|:9996|:11434' || true

echo
echo "[LOG CHECK]"
echo "tail -n 40 logs/cloud.log"
echo "tail -n 40 logs/bridge_z1.log"
echo "tail -n 40 logs/edge_z1.log"
echo "tail -n 40 logs/edge_z2.log"
