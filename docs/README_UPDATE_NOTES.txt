Updated handover-defense files
==============================

These files are updated copies. Do not overwrite your stable HPC code until you take a backup.

Main changes
------------
1. NS-3 C++: unified_v91_multiuav_handover_defense.cc
   - Multi-zone handover trigger support: Zone i -> Zone i+1.
   - Handover defense activates at the real handover trigger point, not only at physical zone exit.
   - Adds post-handover probation knobs:
       --PostHandoverProbationPkts
       --PostHandoverCreditFactor
       --PostHandoverDisableUpgrade
   - CUSUM resets/activates at handover transition.
   - Ledger rows now include zone_id, handover, post_handover_pkt, reason.

2. Edge AI: edge_ai_server_v91_handover_defense.py
   - Applies HANDOVER_SAFEWIN_DECAY when TRUST_HANDOVER_LOAD is received.
   - Tracks first POST_HANDOVER_K packets after handover.
   - Reduces reputation discount during probation using POST_HANDOVER_REP_FACTOR.
   - Logs raw vs decayed safe_wins.

3. Trust coordinator: trust_coordinator_v2_handover_defense.py
   - Adds handover_defense metadata to routed payloads.
   - Keeps coordinator as live handover router; blockchain is still audit/global memory.

4. Cloud: ai_cloud_llm_v85_zoneaware.py
   - Adds zone/time-aware SAFE reputation helper.
   - Supports decaying other-zone or older SAFE history.
   - Reduces ledger credit during post-handover requests when fields are present.

5. Bridge: edge_cloud_bridge_v8_handover_passthrough.py
   - Version-tagged passthrough copy. No major logic changes.

6. Config: experiment_multiuav_handover_defense.conf
   - Points to updated scripts.
   - Adds environment and NS-3 command parameters for handover defense.

Recommended install on HPC
--------------------------
cd ~/ns3-hpc-workspace/ns-3-dev
mkdir -p backup_before_handover_defense_$(date +%Y%m%d_%H%M%S)
cp scratch/unified_v90_multiuav_bayes.cc backup_before_handover_defense_*/ 2>/dev/null || true
cp scratch/edge_ai_server_v90_multiuav.py backup_before_handover_defense_*/ 2>/dev/null || true
cp scratch/trust_coordinator.py backup_before_handover_defense_*/ 2>/dev/null || true
cp scratch/ai_cloud_llm_v84_adaptive.py backup_before_handover_defense_*/ 2>/dev/null || true
cp scratch/edge_cloud_bridge_v7_multizone.py backup_before_handover_defense_*/ 2>/dev/null || true
cp scripts/experiment_multiuav.conf backup_before_handover_defense_*/ 2>/dev/null || true

Copy files into HPC paths:
- unified_v91_multiuav_handover_defense.cc -> scratch/unified_v91_multiuav_handover_defense.cc
- edge_ai_server_v91_handover_defense.py -> scratch/edge_ai_server_v91_handover_defense.py
- trust_coordinator_v2_handover_defense.py -> scratch/trust_coordinator_v2_handover_defense.py
- ai_cloud_llm_v85_zoneaware.py -> scratch/ai_cloud_llm_v85_zoneaware.py
- edge_cloud_bridge_v8_handover_passthrough.py -> scratch/edge_cloud_bridge_v8_handover_passthrough.py
- experiment_multiuav_handover_defense.conf -> scripts/experiment_multiuav_handover_defense.conf

Then build/test the C++ target before running experiments.
