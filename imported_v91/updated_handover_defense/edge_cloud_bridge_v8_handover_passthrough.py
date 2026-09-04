#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
# edge_cloud_bridge_v7_multizone.py -- V2X Bridge (Multi-Zone Extension)
#
# Changes over v6_triggers_FG:
#   [MZ-1]  ZONE_ID env var (default 1). Appended to every CALIBRATE batch
#           payload so the cloud can tag weight deltas per zone.
#   [MZ-2]  TRUST_HANDOVER_TRIGGER passthrough.
#           NS3 sends TRUST_HANDOVER_TRIGGER to the bridge:BRIDGE_PORT.
#           The bridge forwards it verbatim to edge:EDGE_PORT (same forward
#           path used for TELEM). The edge then calls send_trust_handover().
#           No bridge state is modified; the bridge is a transparent proxy
#           for this message type exactly as it is for TELEM.
#   [MZ-3]  ZONE_ID extracted from TELEM messages (new optional field added
#           by NS3 v90+). Stored in per-CID state for batch tagging.
#           Falls back to bridge ZONE_ID if not present in message.
#   [MZ-4]  zone_id added to zone_context in CALIBRATE batch.
#   [MZ-5]  Startup banner and VERSION updated.
#
# All v6 logic is completely preserved — this file is a strict superset.
# Single-UAV experiments (ZONE_ID=1, no TRUST_HANDOVER_TRIGGER messages)
# behave identically to v6.
# =============================================================================

import socket
import struct
import threading
import time
import os
from collections import defaultdict, deque
try:
    from decision_tracer import DecisionTracer, make_trace_id
except Exception:
    DecisionTracer = None
    def make_trace_id(cid, sim_time):
        try:
            return "CID%d-T%d" % (int(cid), int(float(sim_time or 0.0) * 1000.0))
        except Exception:
            return None

TRACER = DecisionTracer("bridge") if DecisionTracer is not None else None

def trace_event(stage, cid=None, sim_time=None, trace_id=None,
                event_level="detail", **kwargs):
    try:
        if TRACER is None:
            return
        if trace_id is None and cid is not None and sim_time is not None:
            trace_id = make_trace_id(cid, sim_time)
        TRACER.event(stage, cid=cid, sim_time=sim_time, trace_id=trace_id,
                     event_level=event_level, **kwargs)
    except Exception:
        pass

# =============================================================================
# CONFIG
# =============================================================================
EDGE_HOST      = os.environ.get("EDGE_HOST",      "127.0.0.1")
EDGE_PORT      = int(os.environ.get("EDGE_PORT",  9999))
CLOUD_HOST     = os.environ.get("CLOUD_HOST",     "172.16.10.220")
CLOUD_PORT     = int(os.environ.get("CLOUD_PORT", 6666))
BRIDGE_PORT    = int(os.environ.get("BRIDGE_PORT",9998))
LEGACY_WIRE_ALIASES = int(os.environ.get("LEGACY_WIRE_ALIASES", 0))
MAX_CLIENTS    = 150
VERSION        = "v8-handover-passthrough"

# [MZ-1] Zone identity for this bridge instance
ZONE_ID = int(os.environ.get("ZONE_ID", 1))

# Calibration policy (unchanged from v6)
MIN_EVIDENCE_PKTS    = int(os.environ.get("MIN_EVIDENCE_PKTS",   3))
CALIB_BATCH_SIZE     = int(os.environ.get("CALIB_BATCH_SIZE",    4))
CALIB_WINDOW_S       = float(os.environ.get("CALIB_WINDOW_S",    30.0))
CALIB_WINDOW_GHOST_S = float(os.environ.get("CALIB_WINDOW_GHOST_S", 60.0))
CALIB_SEP_THRESHOLD  = float(os.environ.get("CALIB_SEP_THRESHOLD", 1.0))
CALIB_RATE_FLOOR_S   = float(os.environ.get("CALIB_RATE_FLOOR_S", 5.0))

CALIB_INIT_DELAY_S   = float(os.environ.get("CALIB_INIT_DELAY_S", 8.0))
CALIB_HEARTBEAT_S    = float(os.environ.get("CALIB_HEARTBEAT_S",  30.0))

ZONE_SPEED_LIMIT_MS  = float(os.environ.get("ZONE_SPEED_LIMIT_MS", 20.0))
OLLAMA_CAP_QPS       = float(os.environ.get("OLLAMA_CAP_QPS",    1.25))
SPIKE_MULTIPLIER     = float(os.environ.get("SPIKE_MULTIPLIER",   1.5))
SPIKE_HISTORY        = int(os.environ.get("SPIKE_HISTORY",        10))

# =============================================================================
# PER-CID STATE TRACKER  (unchanged from v6)
# =============================================================================
_state_lock     = threading.Lock()
cid_spd_hist    = defaultdict(lambda: deque(maxlen=20))
cid_px_hist     = defaultdict(lambda: deque(maxlen=20))
cid_edge_susp_hist = defaultdict(lambda: deque(maxlen=20))
cid_safe_wins   = defaultdict(int)
cid_vclass      = defaultdict(int)
cid_pkt_count   = defaultdict(int)
cid_ban_count   = defaultdict(int)
cid_shadow      = defaultdict(int)
cid_sim_ts      = defaultdict(float)
cid_ts_hist     = defaultdict(lambda: deque(maxlen=60))
cid_hdg_hist    = defaultdict(lambda: deque(maxlen=60))
cid_lan_hist    = defaultdict(lambda: deque(maxlen=60))
cid_verdict_hist= defaultdict(lambda: deque(maxlen=60))
cid_entry_simts = defaultdict(float)
cid_nash_eu_hist= defaultdict(lambda: deque(maxlen=20))
# [MZ-3] Per-CID zone_id (from TELEM ZONE_ID field, fallback to bridge ZONE_ID)
cid_zone_id     = defaultdict(lambda: ZONE_ID)

# Batch accumulator
_batch_lock     = threading.Lock()
_calib_batch    = []
_last_calib_ts  = [0.0]

# Trigger F/G state
_zone_first_pkt_wall_ts = [0.0]
_trigger_f_fired        = [False]
_trigger_g_thread       = [None]
_last_g_sim_ts          = [0.0]
CALIB_HEARTBEAT_SIM_S   = float(os.environ.get('CALIB_HEARTBEAT_SIM_S', 30.0))
_last_calib_wall_ts     = [0.0]

# Trigger C/D state
_rolling_mean_p_edge   = [0.0]
_rolling_p_history     = []
_last_dominant_feature = [""]
_last_dominant_count   = [0]

# =============================================================================
# TCP FRAMING  (unchanged from v6)
# =============================================================================
def recv_framed(conn):
    try:
        raw = b""
        while len(raw) < 4:
            chunk = conn.recv(4 - len(raw))
            if not chunk: return None
            raw += chunk
        length = struct.unpack("!I", raw)[0]
        if length == 0 or length > 65536: return None
        data = b""
        while len(data) < length:
            chunk = conn.recv(length - len(data))
            if not chunk: return None
            data += chunk
        return data.decode("utf-8", errors="replace").strip()
    except Exception:
        return None

def send_framed(conn, msg):
    try:
        enc = msg.encode("utf-8")
        conn.sendall(struct.pack("!I", len(enc)) + enc)
        return True
    except Exception:
        return False

def recv_framed_cloud(conn):
    try:
        raw = b""
        while len(raw) < 4:
            chunk = conn.recv(4 - len(raw))
            if not chunk: return None
            raw += chunk
        length = struct.unpack(">I", raw)[0]
        if length == 0 or length > 65536: return None
        data = b""
        while len(data) < length:
            chunk = conn.recv(length - len(data))
            if not chunk: return None
            data += chunk
        return data.decode("utf-8", errors="replace").strip()
    except Exception:
        return None

def send_framed_cloud(conn, msg):
    try:
        enc = msg.encode("utf-8")
        conn.sendall(struct.pack(">I", len(enc)) + enc)
        return True
    except Exception:
        return False

# =============================================================================
# PARSE HELPERS  (unchanged from v6)
# =============================================================================
def parse_kv(msg):
    d = {}
    for part in msg.strip().split():
        if ":" in part:
            k, v = part.split(":", 1)
            d[k.upper()] = v
    return d

def get_float(d, key, default=0.0):
    try:    return float(d.get(key, default))
    except: return default

def get_int(d, key, default=0):
    try:    return int(d.get(key, default))
    except: return default

# =============================================================================
# FORWARD TO EDGE  (unchanged from v6)
# =============================================================================
def forward_to_edge(msg, trace_id=None, cid=None, sim_time=None,
                    origin_stage="forward_to_edge"):
    trace_event("edge_forward_start", cid=cid, sim_time=sim_time,
                trace_id=trace_id, event_level="detail",
                origin_stage=origin_stage,
                target_host=EDGE_HOST, target_port=EDGE_PORT,
                message=msg[:512])
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((EDGE_HOST, EDGE_PORT))
        enc = msg.encode("utf-8")
        s.sendall(struct.pack("!I", len(enc)) + enc)
        raw = b""
        while len(raw) < 4:
            chunk = s.recv(4 - len(raw))
            if not chunk: break
            raw += chunk
        if len(raw) == 4:
            length = struct.unpack("!I", raw)[0]
            data   = b""
            while len(data) < length:
                chunk = s.recv(length - len(data))
                if not chunk: break
                data += chunk
            s.close()
            return data.decode("utf-8", errors="replace").strip()
        s.close()
    except Exception as e:
        print("[BRIDGE-Z%d] Edge forward error: %s" % (ZONE_ID, e))
    return None

# =============================================================================
# UPDATE PER-CID STATE  (unchanged from v6)
# =============================================================================
def update_cid_state(cid, spd, px, sim_ts, safe_wins, vclass,
                     ts_delta=None, hdg=None, lan=None, verdict=None,
                     zone_id=None):
    with _state_lock:
        cid_spd_hist[cid].append(spd)
        cid_px_hist[cid].append(px)
        if ts_delta is not None: cid_ts_hist[cid].append(ts_delta)
        if hdg is not None:      cid_hdg_hist[cid].append(hdg)
        if lan is not None:      cid_lan_hist[cid].append(int(lan))
        if verdict is not None:  cid_verdict_hist[cid].append(verdict)
        if cid_pkt_count[cid] == 0:
            cid_entry_simts[cid] = sim_ts
        cid_safe_wins[cid]  = safe_wins
        cid_vclass[cid]     = vclass
        cid_pkt_count[cid] += 1
        cid_sim_ts[cid]     = sim_ts
        # [MZ-3] Track zone_id from TELEM if provided
        if zone_id is not None:
            cid_zone_id[cid] = zone_id

def update_cid_edge_suspicion(cid, edge_susp, verdict):
    with _state_lock:
        cid_edge_susp_hist[cid].append(edge_susp)
        if verdict in ("WARN", "BAN"):
            cid_shadow[cid] += 1
        if verdict == "BAN":
            cid_ban_count[cid] += 1

# =============================================================================
# RICH SUMMARY + SEPARABILITY  (unchanged from v6)
# =============================================================================
def _fisher_sep(warn_vals, safe_vals):
    import math
    if len(warn_vals) < 2 or len(safe_vals) < 2: return 0.0
    mu_w  = sum(warn_vals) / len(warn_vals)
    mu_s  = sum(safe_vals) / len(safe_vals)
    var_w = sum((x - mu_w)**2 for x in warn_vals) / len(warn_vals)
    var_s = sum((x - mu_s)**2 for x in safe_vals) / len(safe_vals)
    pooled = (var_w + var_s) / 2.0 + 1e-9
    import math as _m
    return abs(mu_w - mu_s) / _m.sqrt(pooled)

def compute_rich_summary(cid):
    import math, statistics
    with _state_lock:
        spd_list  = list(cid_spd_hist[cid])
        px_list   = list(cid_px_hist[cid])
        ts_list   = list(cid_ts_hist[cid])
        hdg_list  = list(cid_hdg_hist[cid])
        lan_list  = list(cid_lan_hist[cid])
        verd_list = list(cid_verdict_hist[cid])
        susp_list = list(cid_edge_susp_hist[cid])
        pkt_count = cid_pkt_count[cid]
        safe_wins = cid_safe_wins[cid]
        shadow    = cid_shadow[cid]
        sim_ts    = cid_sim_ts[cid]
        entry_ts  = cid_entry_simts.get(cid, sim_ts)
    if pkt_count < 2: return None
    with _state_lock:
        all_spds = [s for cid_s in cid_spd_hist.values() for s in cid_s]
    zone_mean_spd = sum(all_spds) / len(all_spds) if all_spds else ZONE_SPEED_LIMIT_MS
    zone_std_spd  = statistics.stdev(all_spds) if len(all_spds) > 2 else 1.0
    spd_mean = sum(spd_list) / len(spd_list) if spd_list else 0.0
    spd_std  = statistics.stdev(spd_list) if len(spd_list) > 2 else 0.0
    spd_z    = (spd_mean - zone_mean_spd) / max(zone_std_spd, 0.1)
    spd_var_ratio = (spd_std / max(zone_std_spd, 0.1)) if zone_std_spd > 0 else 1.0
    ts_mean  = sum(ts_list) / len(ts_list) if ts_list else 0.0
    ts_std   = statistics.stdev(ts_list) if len(ts_list) > 2 else 0.0
    ts_trend = 0.0
    if len(ts_list) >= 4:
        mid = len(ts_list) // 2
        ts_trend = (sum(ts_list[mid:]) / len(ts_list[mid:])
                  - sum(ts_list[:mid])  / len(ts_list[:mid]))
    px_range     = (max(px_list) - min(px_list)) if len(px_list) >= 2 else 0.0
    frozen_count = sum(1 for i in range(1, len(px_list))
                       if abs(px_list[i] - px_list[i-1]) < 0.5)
    px_frozen    = frozen_count / max(len(px_list) - 1, 1)
    hdg_var      = statistics.variance(hdg_list) if len(hdg_list) > 2 else 0.0
    with _state_lock:
        all_hdg_vars = []
        for c, h in cid_hdg_hist.items():
            if len(h) > 2:
                try: all_hdg_vars.append(statistics.variance(h))
                except: pass
    zone_hdg_var   = sum(all_hdg_vars) / len(all_hdg_vars) if all_hdg_vars else 0.1
    hdg_var_excess = hdg_var - zone_hdg_var
    lane_changes   = sum(1 for i in range(1, len(lan_list))
                         if lan_list[i] != lan_list[i-1])
    lane_cr        = lane_changes / max(len(lan_list) - 1, 1)
    if lan_list:
        most_common  = max(set(lan_list), key=lan_list.count)
        lane_consist = lan_list.count(most_common) / len(lan_list)
    else:
        lane_consist = 1.0
    arr_jitter = 0.08
    if ts_std > 0:
        arr_jitter = min(ts_std / max(abs(ts_mean), 0.01), 1.0)
    disruption = round(min(1.0,
        0.35 * min(lane_cr / 0.1, 1.0) +
        0.35 * px_frozen +
        0.20 * min(abs(ts_mean) / 0.5, 1.0) +
        0.10 * max(0.0, 1.0 - spd_var_ratio)
    ), 3)
    avg_susp     = sum(susp_list) / len(susp_list) if susp_list else 0.0
    warn_count   = verd_list.count("WARN")
    ban_count    = verd_list.count("BAN")
    last_verdict = verd_list[-1] if verd_list else "SAFE"
    with _state_lock:
        nash_eu_list = list(cid_nash_eu_hist[cid])
    nash_eu_gap_mean = round(sum(nash_eu_list) / len(nash_eu_list), 4) if nash_eu_list else 0.0
    return {
        "n_pkts":              pkt_count,
        "ts_delta_mean":       round(ts_mean, 4),
        "ts_delta_std":        round(ts_std, 4),
        "ts_delta_trend":      round(ts_trend, 4),
        "spd_z_mean":          round(spd_z, 3),
        "spd_variance_ratio":  round(spd_var_ratio, 3),
        "px_frozen_ratio":     round(px_frozen, 3),
        "px_range":            round(px_range, 2),
        "hdg_var_excess":      round(hdg_var_excess, 4),
        "lane_change_rate":    round(lane_cr, 3),
        "lane_consistency":    round(lane_consist, 3),
        "inter_arrival_jitter":round(arr_jitter, 4),
        "disruption_score":    disruption,
        "edge_verdict":        last_verdict,
        "p_edge":              round(avg_susp, 3),
        "warn_count":          warn_count,
        "ban_count_local":     ban_count,
        "safe_wins":           safe_wins,
        "shadow":              shadow,
        "nash_eu_gap_mean":    nash_eu_gap_mean,
    }

def compute_separability(batch):
    warn = [s for s in batch if s.get("edge_verdict") in ("WARN", "BAN")]
    safe = [s for s in batch if s.get("edge_verdict") == "SAFE"]
    if not warn or not safe: return {"max_separation": 0.0}
    features = ["ts_delta_mean", "ts_delta_std", "spd_z_mean",
                "spd_variance_ratio", "px_frozen_ratio", "hdg_var_excess",
                "lane_change_rate", "inter_arrival_jitter"]
    scores = {}
    for f in features:
        w_vals = [s[f] for s in warn if f in s]
        s_vals = [s[f] for s in safe if f in s]
        scores[f] = round(_fisher_sep(w_vals, s_vals), 3)
    scores["max_separation"] = round(max(scores.values()), 3)
    return scores

def build_zone_context():
    with _state_lock:
        all_spds = [s for h in cid_spd_hist.values() for s in h]
        all_lane_crs = []
        for cid, lh in cid_lan_hist.items():
            lh = list(lh)
            if len(lh) > 1:
                lc = sum(1 for i in range(1, len(lh)) if lh[i] != lh[i-1])
                all_lane_crs.append(lc / len(lh))
        n_active = len([c for c, n in cid_pkt_count.items() if n > 0])
    mean_spd = sum(all_spds) / len(all_spds) if all_spds else ZONE_SPEED_LIMIT_MS
    std_spd  = 0.0
    try:
        import statistics
        std_spd = statistics.stdev(all_spds) if len(all_spds) > 2 else 1.0
    except: pass
    mean_lcr = sum(all_lane_crs) / len(all_lane_crs) if all_lane_crs else 0.03
    return {
        "zone_id":        ZONE_ID,   # [MZ-4]
        "speed_limit_ms": ZONE_SPEED_LIMIT_MS,
        "n_active_cars":  n_active,
        "zone_mean_spd":  round(mean_spd, 2),
        "zone_std_spd":   round(std_spd, 2),
        "zone_mean_lane_cr": round(mean_lcr, 3),
    }

def _batch_has_warn_and_safe(batch):
    has_warn = any(s.get("edge_verdict") in ("WARN", "BAN") for s in batch)
    has_safe = any(s.get("edge_verdict") == "SAFE"           for s in batch)
    return has_warn and has_safe

# =============================================================================
# TRIGGER F  (unchanged from v6)
# =============================================================================
def _trigger_f_fire(sim_ts):
    if _trigger_f_fired[0]: return
    with _state_lock:
        active_cids = [c for c, n in cid_pkt_count.items() if n >= 2]
    if not active_cids:
        print("[BRIDGE-Z%d-CALIB] Trigger F: no cars with >=2 pkts — deferring" % ZONE_ID)
        return
    summaries = [compute_rich_summary(c) for c in active_cids]
    summaries  = [s for s in summaries if s]
    if not summaries: return
    _trigger_f_fired[0] = True
    print("[BRIDGE-Z%d-CALIB] Trigger F: zone-entry baseline n=%d sim_ts=%.1f"
          % (ZONE_ID, len(summaries), sim_ts))
    threading.Thread(target=send_calibration_batch,
                     args=(summaries, sim_ts, "F_zone_entry_baseline"),
                     kwargs={"skip_balance_gate": True},
                     daemon=True).start()

# =============================================================================
# TRIGGER G  (unchanged from v6)
# =============================================================================
def _trigger_g_loop():
    while True:
        time.sleep(CALIB_HEARTBEAT_S)
        with _state_lock:
            active_cids  = [c for c, n in cid_pkt_count.items() if n >= MIN_EVIDENCE_PKTS]
            last_sim_ts  = max(cid_sim_ts.values()) if cid_sim_ts else 0.0
        if not active_cids: continue
        if last_sim_ts - _last_g_sim_ts[0] < CALIB_HEARTBEAT_SIM_S: continue
        summaries = [compute_rich_summary(c) for c in active_cids]
        summaries  = [s for s in summaries if s]
        if not summaries: continue
        has_warn = any(s.get("edge_verdict") in ("WARN","BAN") for s in summaries)
        has_safe = any(s.get("edge_verdict") == "SAFE"          for s in summaries)
        if has_warn and has_safe:
            reason  = "G_heartbeat_balanced"
            skip_bg = False
            print("[BRIDGE-Z%d-CALIB] Trigger G: heartbeat balanced n=%d"
                  % (ZONE_ID, len(summaries)))
        elif has_safe and not has_warn:
            reason  = "G_heartbeat_safe_only"
            skip_bg = True
            print("[BRIDGE-Z%d-CALIB] Trigger G: heartbeat SAFE-only n=%d"
                  % (ZONE_ID, len(summaries)))
        else:
            print("[BRIDGE-Z%d-CALIB] Trigger G: all-WARN zone — skipping" % ZONE_ID)
            continue
        _last_g_sim_ts[0] = last_sim_ts
        threading.Thread(target=send_calibration_batch,
                         args=(summaries, last_sim_ts, reason),
                         kwargs={"skip_balance_gate": skip_bg},
                         daemon=True).start()

def _start_trigger_g():
    t = threading.Thread(target=_trigger_g_loop, daemon=True)
    t.start()
    _trigger_g_thread[0] = t
    print("[BRIDGE-Z%d-CALIB] Trigger G heartbeat started (every %.0fs)"
          % (ZONE_ID, CALIB_HEARTBEAT_S))

# =============================================================================
# TRIGGERS A-E  (unchanged from v6)
# =============================================================================
def _adaptive_batch_size(n_active):
    import math
    car_per_s = max(0.01, n_active / 33.1)
    needed    = math.ceil(car_per_s / (OLLAMA_CAP_QPS * 0.75))
    return max(CALIB_BATCH_SIZE, needed)

def _compute_zone_mean_p_edge():
    with _state_lock:
        vals = [list(h)[-1] for h in cid_edge_susp_hist.values() if len(h) > 0]
    return sum(vals) / len(vals) if vals else 0.0

def _check_trigger_c():
    current = _compute_zone_mean_p_edge()
    if len(_rolling_p_history) >= 3:
        rolling_avg = sum(_rolling_p_history[-SPIKE_HISTORY:]) / \
                      len(_rolling_p_history[-SPIKE_HISTORY:])
        if rolling_avg > 0.05 and current > SPIKE_MULTIPLIER * rolling_avg:
            print("[BRIDGE-Z%d-CALIB] Trigger C: spike %.3f > %.1fx avg=%.3f"
                  % (ZONE_ID, current, SPIKE_MULTIPLIER, rolling_avg))
            return True
    return False

def _check_trigger_d(new_dominant):
    if not new_dominant or new_dominant == "unknown": return False
    if _last_dominant_feature[0] and _last_dominant_feature[0] != new_dominant:
        print("[BRIDGE-Z%d-CALIB] Trigger D: dominant shifted %s -> %s"
              % (ZONE_ID, _last_dominant_feature[0], new_dominant))
        _last_dominant_feature[0] = new_dominant
        return True
    _last_dominant_feature[0] = new_dominant
    return False

def try_add_to_calib_batch(cid, sim_ts):
    import time as _time
    with _state_lock:
        n        = cid_pkt_count[cid]
        n_active = len([c for c, cnt in cid_pkt_count.items() if cnt > 0])
    if n < MIN_EVIDENCE_PKTS: return
    wall_now = _time.time()
    if not _trigger_f_fired[0] and _zone_first_pkt_wall_ts[0] > 0:
        elapsed_since_first = wall_now - _zone_first_pkt_wall_ts[0]
        if elapsed_since_first >= CALIB_INIT_DELAY_S:
            _trigger_f_fire(sim_ts)
    summary = compute_rich_summary(cid)
    if summary is None: return
    fire        = False
    fire_reason = ""
    now         = sim_ts
    window_s    = CALIB_WINDOW_GHOST_S if n_active < 5 else CALIB_WINDOW_S
    batch_size  = _adaptive_batch_size(n_active)
    with _batch_lock:
        if any(s.get("_cid") == cid for s in _calib_batch): return
        summary["_cid"] = cid
        _calib_batch.append(summary)
        current_batch = list(_calib_batch)
        n_batch       = len(current_batch)
        time_since    = now - _last_calib_ts[0]
    if n_batch >= batch_size:
        fire = True; fire_reason = "A_batch_full(n=%d)" % n_batch
    elif time_since >= window_s and n_batch >= 2:
        if _batch_has_warn_and_safe(current_batch):
            fire = True; fire_reason = "B_window(%.0fs)" % time_since
        else:
            print("[BRIDGE-Z%d-CALIB] Trigger B: window elapsed but not balanced"
                  % ZONE_ID)
    elif _check_trigger_c():
        if _batch_has_warn_and_safe(current_batch):
            fire = True; fire_reason = "C_spike"
        else:
            print("[BRIDGE-Z%d-CALIB] Trigger C fired but not balanced" % ZONE_ID)
    if fire:
        batch_copy = list(current_batch)
        threading.Thread(target=send_calibration_batch,
                         args=(batch_copy, now, fire_reason),
                         daemon=True).start()
        with _batch_lock:
            _calib_batch.clear()
            _last_calib_ts[0] = now
        _rolling_p_history.append(_compute_zone_mean_p_edge())
        if len(_rolling_p_history) > SPIKE_HISTORY * 2:
            _rolling_p_history.pop(0)

# =============================================================================
# SEND CALIBRATION BATCH TO CLOUD  [MZ-4] zone_id added to payload
# =============================================================================
def send_calibration_batch(batch, sim_ts, fire_reason="unknown",
                            skip_balance_gate=False):
    import json, time as _time
    if not batch: return
    wall_now = _time.time()
    elapsed  = wall_now - _last_calib_wall_ts[0]
    if elapsed < CALIB_RATE_FLOOR_S:
        print("[BRIDGE-Z%d-CALIB] Trigger E: rate floor %.1fs, only %.1fs elapsed [%s]"
              % (ZONE_ID, CALIB_RATE_FLOOR_S, elapsed, fire_reason))
        return
    _last_calib_wall_ts[0] = wall_now
    if not skip_balance_gate:
        sep     = compute_separability(batch)
        max_sep = sep.get("max_separation", 0.0)
        if max_sep < CALIB_SEP_THRESHOLD:
            print("[BRIDGE-Z%d-CALIB] sep=%.2f < %.2f — skipping [%s]"
                  % (ZONE_ID, max_sep, CALIB_SEP_THRESHOLD, fire_reason))
            return
    else:
        sep = compute_separability(batch)
    if not skip_balance_gate and not _batch_has_warn_and_safe(batch):
        print("[BRIDGE-Z%d-CALIB] Batch not balanced — skipping [%s]"
              % (ZONE_ID, fire_reason))
        return
    clean_batch = [{k: v for k, v in s.items() if k != "_cid"} for s in batch]
    zone_ctx    = build_zone_context()   # already includes zone_id [MZ-4]
    payload = json.dumps({
        "msg_type":          "CALIBRATE",
        "sim_ts":            sim_ts,
        "fire_reason":       fire_reason,
        "zone_id":           ZONE_ID,    # [MZ-4] top-level zone tag
        "zone_context":      zone_ctx,
        "vehicle_summaries": clean_batch,
        "separability":      sep,
    })
    n_warn = sum(1 for s in clean_batch if s.get("edge_verdict") in ("WARN","BAN"))
    n_safe = sum(1 for s in clean_batch if s.get("edge_verdict") == "SAFE")
    print("[BRIDGE-Z%d-CALIB] CALIBRATE n=%d (W=%d S=%d) sep=%.2f reason=%s"
          % (ZONE_ID, len(clean_batch), n_warn, n_safe,
             sep.get("max_separation", 0), fire_reason))
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(35.0)
        s.connect((CLOUD_HOST, CLOUD_PORT))
        send_framed_cloud(s, payload)
        resp = recv_framed_cloud(s)
        s.close()
    except Exception as e:
        print("[BRIDGE-Z%d-CALIB] Cloud error: %s" % (ZONE_ID, e))
        return
    if not resp:
        print("[BRIDGE-Z%d-CALIB] Empty cloud response" % ZONE_ID)
        return
    if resp.startswith("CALIBRATION_ERROR"):
        print("[BRIDGE-Z%d-CALIB] Cloud returned CALIBRATION_ERROR: %s"
              % (ZONE_ID, resp))
        return
    if resp.startswith("CALIBRATION_RESULT"):
        try:
            import json as _j
            data = _j.loads(resp[len("CALIBRATION_RESULT"):].strip())
        except Exception as e:
            print("[BRIDGE-Z%d-CALIB] Rejecting malformed CALIBRATION_RESULT: %s"
                  % (ZONE_ID, e))
            return
        if data.get("msg_type") != "CALIBRATION_RESULT":
            print("[BRIDGE-Z%d-CALIB] Rejecting: wrong msg_type=%s"
                  % (ZONE_ID, str(data.get("msg_type"))))
            return
        if not bool(data.get("llm_used", False)):
            print("[BRIDGE-Z%d-CALIB] Rejecting calibration: llm_used=false" % ZONE_ID)
            return
        print("[BRIDGE-Z%d-CALIB] Got LLM-backed CALIBRATION_RESULT [%s] — forwarding to edge"
              % (ZONE_ID, fire_reason))
        _forward_calibration_to_edge(resp, sim_ts)
        try:
            new_dominant = data.get("attack_type_detected", "")
            if _check_trigger_d(new_dominant):
                print("[BRIDGE-Z%d-CALIB] Trigger D: dominant changed" % ZONE_ID)
        except Exception:
            pass
        return
    print("[BRIDGE-Z%d-CALIB] Unexpected cloud response: %s"
          % (ZONE_ID, str(resp)[:120]))

def _forward_calibration_to_edge(calib_result_msg, sim_ts):
    try:
        resp = forward_to_edge(calib_result_msg, cid=None, sim_time=sim_ts,
                               origin_stage="calibration_result")
        if resp:
            print("[BRIDGE-Z%d-CALIB] Edge accepted calibration: %s"
                  % (ZONE_ID, resp[:80]))
    except Exception as e:
        print("[BRIDGE-Z%d-CALIB] Edge calibration forward error: %s" % (ZONE_ID, e))

# =============================================================================
# HANDLE INCOMING CONNECTION  [MZ-2][MZ-3] multi-zone additions
# =============================================================================
def handle_client(conn, addr):
    try:
        conn.settimeout(10.0)
        trace_event("connection_accepted", event_level="detail",
                    remote_addr=str(addr))
        msg = recv_framed(conn)
        if msg is None:
            trace_event("empty_request", event_level="detail", remote_addr=str(addr))
            return

        # ------------------------------------------------------------------
        # RESET  (unchanged)
        # ------------------------------------------------------------------
        if msg.strip() == "RESET":
            trace_event("reset_received", event_level="info", remote_addr=str(addr))
            resp = forward_to_edge("RESET", origin_stage="reset")
            with _state_lock:
                cid_spd_hist.clear();  cid_px_hist.clear()
                cid_edge_susp_hist.clear(); cid_safe_wins.clear()
                cid_vclass.clear();    cid_pkt_count.clear()
                cid_ban_count.clear(); cid_shadow.clear()
                cid_sim_ts.clear();    cid_ts_hist.clear()
                cid_hdg_hist.clear();  cid_lan_hist.clear()
                cid_verdict_hist.clear(); cid_nash_eu_hist.clear()
                cid_entry_simts.clear()
                cid_zone_id.clear()    # [MZ-3]
            with _batch_lock:
                _calib_batch.clear()
                _last_calib_ts[0] = 0.0
            _last_calib_wall_ts[0]     = 0.0
            _trigger_f_fired[0]        = False
            _zone_first_pkt_wall_ts[0] = 0.0
            _last_g_sim_ts[0]          = 0.0
            del _rolling_p_history[:]
            _last_dominant_feature[0]  = ""
            _last_dominant_count[0]    = 0
            print("[BRIDGE-Z%d] RESET -- all state cleared (v7 multizone)"
                  % ZONE_ID)
            reset_resp = resp if resp else "RESET_OK banned_cleared"
            trace_event("reset_completed", event_level="info", response=reset_resp)
            send_framed(conn, reset_resp)
            return

        # ------------------------------------------------------------------
        # [MZ-2]  TRUST_HANDOVER_TRIGGER passthrough
        # Forward verbatim to edge AI — the edge handles coordinator routing.
        # Return the edge's ACK directly to the caller (NS3).
        # ------------------------------------------------------------------
        if msg.startswith("TRUST_HANDOVER_TRIGGER"):
            # Extract CID for logging
            cid_val = -1
            for part in msg.split():
                if part.upper().startswith("CID:"):
                    try: cid_val = int(part.split(":")[1])
                    except: pass
                    break
            print("[BRIDGE-Z%d] TRUST_HANDOVER_TRIGGER  CID:%-4d — forwarding to edge"
                  % (ZONE_ID, cid_val))
            trace_event("handover_trigger_forward", cid=cid_val,
                        event_level="info", raw=msg[:200])
            resp = forward_to_edge(msg, cid=cid_val,
                                   origin_stage="handover_trigger_proxy")
            send_framed(conn, resp if resp else "HANDOVER_TRIGGER_ACK CID:%d" % cid_val)
            return

        # ------------------------------------------------------------------
        # TELEM  [MZ-3] extract optional ZONE_ID field
        # ------------------------------------------------------------------
        if msg.startswith("TELEM"):
            d      = parse_kv(msg)
            cid    = get_int(d,   "CID",      -1)
            spd    = get_float(d, "SPD",      0.0)
            px     = get_float(d, "PX",       0.0)
            py     = get_float(d, "PY",       0.0)
            hdg    = get_float(d, "HDG",      0.0)
            sim_ts = get_float(d, "SIMNOW",   0.0)
            sw     = get_int(d,   "SAFE_WINS",0)
            vc     = get_int(d,   "CLASS",    0)
            # [MZ-3] ZONE_ID from NS3 message if available, else fall back
            telem_zone_id = get_int(d, "ZONE_ID", ZONE_ID)
            trace_id = make_trace_id(cid, sim_ts)

            trace_event("telem_received", cid=cid, sim_time=sim_ts,
                        trace_id=trace_id, event_level="info",
                        remote_addr=str(addr), spd=spd, px=px, py=py,
                        hdg=hdg, safe_wins=sw, vehicle_class=vc,
                        zone_id=telem_zone_id, raw=msg[:512])

            if _zone_first_pkt_wall_ts[0] == 0.0:
                _zone_first_pkt_wall_ts[0] = time.time()
                print("[BRIDGE-Z%d-CALIB] First packet — Trigger F armed (fires in %.0fs)"
                      % (ZONE_ID, CALIB_INIT_DELAY_S))

            ts_raw   = get_float(d, "TS",  sim_ts)
            lan      = get_float(d, "LAN", 0.0)
            ts_delta = ts_raw - sim_ts
            update_cid_state(cid, spd, px, sim_ts, sw, vc,
                             ts_delta=ts_delta, hdg=hdg, lan=lan,
                             zone_id=telem_zone_id)

            resp = forward_to_edge(msg, trace_id=trace_id, cid=cid,
                                   sim_time=sim_ts, origin_stage="telem_proxy")
            if resp is None:
                trace_event("edge_unreachable", cid=cid, sim_time=sim_ts,
                            trace_id=trace_id, event_level="info")
                send_framed(conn, "ERROR edge_unreachable")
                return

            parts     = resp.split()
            verdict   = parts[0] if parts else "SAFE"
            edge_susp = 0.0
            for p in parts:
                if p.startswith("SUSP:"):
                    try: edge_susp = float(p.split(":")[1])
                    except: pass
                    break
            else:
                for p in parts:
                    if p.startswith("CONF:"):
                        try: edge_susp = float(p.split(":")[1])
                        except: pass
                        break

            update_cid_edge_suspicion(cid, edge_susp, verdict)
            with _state_lock:
                cid_verdict_hist[cid].append(verdict)

            send_framed(conn, resp)

            with _state_lock:
                pkt_count_now = cid_pkt_count[cid]

            if pkt_count_now >= MIN_EVIDENCE_PKTS:
                threading.Thread(target=try_add_to_calib_batch,
                                 args=(cid, sim_ts),
                                 daemon=True).start()
            return

        # Unknown — forward as-is (unchanged)
        resp = forward_to_edge(msg, origin_stage="unknown_forward")
        send_framed(conn, resp if resp else "ERROR unknown_forwarded")

    except Exception as e:
        print("[BRIDGE-Z%d] Handler error %s: %s" % (ZONE_ID, str(addr), str(e)))
    finally:
        try: conn.close()
        except: pass

# =============================================================================
# MAIN  [MZ-5] updated banner
# =============================================================================
def main():
    print("=" * 64)
    print(" V2X EDGE-CLOUD BRIDGE %s  --  Zone %d" % (VERSION, ZONE_ID))
    print("=" * 64)
    print("[BRIDGE-Z%d] Edge   : %s:%d" % (ZONE_ID, EDGE_HOST, EDGE_PORT))
    print("[BRIDGE-Z%d] Cloud  : %s:%d" % (ZONE_ID, CLOUD_HOST, CLOUD_PORT))
    print("[BRIDGE-Z%d] Listen : 0.0.0.0:%d" % (ZONE_ID, BRIDGE_PORT))
    print("[BRIDGE-Z%d] Trigger F: zone-entry baseline at %.0fs" % (ZONE_ID, CALIB_INIT_DELAY_S))
    print("[BRIDGE-Z%d] Trigger G: heartbeat every %.0fs" % (ZONE_ID, CALIB_HEARTBEAT_S))
    print("[BRIDGE-Z%d] Multi-zone: TRUST_HANDOVER_TRIGGER passthrough enabled" % ZONE_ID)
    print()

    trace_event("startup", event_level="info", version=VERSION,
                zone_id=ZONE_ID, edge_host=EDGE_HOST, edge_port=EDGE_PORT,
                cloud_host=CLOUD_HOST, cloud_port=CLOUD_PORT,
                bridge_port=BRIDGE_PORT)

    try:
        s = socket.socket(); s.settimeout(3)
        s.connect((EDGE_HOST, EDGE_PORT)); s.close()
        print("[BRIDGE-Z%d] Edge server reachable OK" % ZONE_ID)
    except Exception:
        print("[BRIDGE-Z%d] WARNING: Edge not reachable on %s:%d"
              % (ZONE_ID, EDGE_HOST, EDGE_PORT))

    try:
        s = socket.socket(); s.settimeout(5)
        s.connect((CLOUD_HOST, CLOUD_PORT)); s.close()
        print("[BRIDGE-Z%d] Cloud server reachable OK" % ZONE_ID)
    except Exception:
        print("[BRIDGE-Z%d] WARNING: Cloud not reachable on %s:%d"
              % (ZONE_ID, CLOUD_HOST, CLOUD_PORT))

    _start_trigger_g()

    print("[BRIDGE-Z%d] Ready -- listening on port %d\n" % (ZONE_ID, BRIDGE_PORT))

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", BRIDGE_PORT))
    srv.listen(MAX_CLIENTS)

    try:
        while True:
            try:
                conn, addr = srv.accept()
                threading.Thread(target=handle_client,
                                 args=(conn, addr),
                                 daemon=True).start()
            except KeyboardInterrupt:
                print("[BRIDGE-Z%d] Shutting down..." % ZONE_ID)
                break
            except Exception as e:
                print("[BRIDGE-Z%d] Accept error: %s" % (ZONE_ID, e))
    finally:
        srv.close()


if __name__ == "__main__":
    main()
