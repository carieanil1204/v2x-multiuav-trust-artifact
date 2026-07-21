#!/usr/bin/env bash
set -e

cd ~/research/projects/v2x-multiuav-trust

CKPT_DIR="$1"

cp -a "$CKPT_DIR/edge_ai_server_v91_handover_defense.py" pipeline/edge/
cp -a "$CKPT_DIR/ai_cloud_llm_v85_zoneaware.py" pipeline/cloud/
cp -a "$CKPT_DIR/trust_coordinator_v2_handover_defense.py" pipeline/coordinator/
cp -a "$CKPT_DIR/edge_cloud_bridge_v8_handover_passthrough.py" pipeline/bridge/
cp -a "$CKPT_DIR/launch_pipeline_workstation.sh" scripts/
cp -a "$CKPT_DIR/stop_pipeline_workstation.sh" scripts/
cp -a "$CKPT_DIR/baseline_a_full_veremi_style.py" scripts/
cp -a "$CKPT_DIR/unified_v91_multiuav_handover_defense.cc" ns-allinone-3.41/ns-3.41/scratch/

echo "Restored from $CKPT_DIR"
