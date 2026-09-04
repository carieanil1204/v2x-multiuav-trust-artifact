#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
# trust_coordinator.py  --  Multi-UAV Cross-Zone Trust Coordinator
# V2X Hierarchical Trust | Multi-UAV Extension (v90+)
#
# Role:
#   Central routing hub for trust-state transfers between UAV zones.
#   The coordinator is the ONLY component that knows the full zone topology.
#   Edge AI servers are topology-agnostic — they only talk to the coordinator.
#
# Core responsibilities:
#   1. Receive TRUST_HANDOVER from an edge when a vehicle approaches a zone
#      boundary and forward as TRUST_HANDOVER_LOAD to the target zone edge.
#   2. Track vehicles currently in the overlap region (dual-zone scoring)
#      and log consensus agreement / disagreement between zones.
#   3. Monitor zone health via periodic TCP ping; flag stale / offline zones.
#   4. Support TRUST_EXPORT_REQ so a restarted edge can recover in-transit
#      vehicle state without losing Bayesian (alpha, beta) continuity.
#   5. Respond to RESET to clear all in-memory state before a new experiment.
#
# Architecture:
#   NS3 UAVApp  -->  TRUST_HANDOVER  -->  Bridge/Edge Z1
#   Edge Z1     -->  TRUST_HANDOVER  -->  Coordinator:9997
#   Coordinator -->  TRUST_HANDOVER_LOAD  -->  Edge Z2 (target zone)
#   Edge Z2     -->  TRUST_HANDOVER_ACK (optional)  -->  Coordinator
#
# Message types handled (inbound):
#   TRUST_HANDOVER      -- from any edge: route trust state to target zone
#   TRUST_EXPORT_REQ    -- from any edge: return last known state for a CID
#   OVERLAP_SCORE       -- from any edge: log dual-zone scoring for consensus
#   ZONE_STATUS         -- diagnostic: return which zones are online
#   RESET               -- clear all state (called by launch_pipeline at startup)
#
# Message types sent (outbound to edges):
#   TRUST_HANDOVER_LOAD -- trust state pre-load for an incoming vehicle
#
# TCP framing: big-endian 4-byte length prefix  (matches edge AI + bridge)
# All config is env-var overridable. All state is in-memory; RESET clears it.
#
# CHANGELOG:
#   v1.0  2025-05  Initial implementation for multi-UAV paper extension
# =============================================================================

import socket
import struct
import threading
import time
import os
import json
import argparse
import signal
import datetime
from collections import defaultdict, deque

# =============================================================================
# CONFIG BLOCK -- all tunable via environment variables
# =============================================================================

COORD_HOST = os.environ.get("COORD_HOST", "0.0.0.0")
COORD_PORT = int(os.environ.get("COORD_PORT", 9997))

# Zone registry defaults (2 zones on the same HPC host, different ports).
# Override with ZONE{N}_EDGE_HOST / ZONE{N}_EDGE_PORT.
# Additional zones 3..MAX_ZONES are auto-discovered if ZONE{N}_EDGE_HOST is set.
_DEFAULT_ZONES = {
    1: (os.environ.get("ZONE1_EDGE_HOST", "127.0.0.1"),
        int(os.environ.get("ZONE1_EDGE_PORT", 9999))),
    2: (os.environ.get("ZONE2_EDGE_HOST", "127.0.0.1"),
        int(os.environ.get("ZONE2_EDGE_PORT", 9995))),
}

MAX_ZONES          = int(os.environ.get("MAX_ZONES",           8))
MAX_CLIENTS        = int(os.environ.get("MAX_CLIENTS",         40))
TCP_TIMEOUT_S      = float(os.environ.get("TCP_TIMEOUT_S",     5.0))
FORWARD_TIMEOUT_S  = float(os.environ.get("FORWARD_TIMEOUT_S", 5.0))
VERSION            = "v1.0"

# Health monitor
HEALTH_INTERVAL_S  = float(os.environ.get("HEALTH_INTERVAL_S",  10.0))
HEALTH_STALE_S     = float(os.environ.get("HEALTH_STALE_S",     30.0))

# Overlap consensus window: if two zones both score the same CID within this
# many wall-clock seconds, log a CONSENSUS event (agree or disagree).
OVERLAP_WINDOW_S   = float(os.environ.get("OVERLAP_WINDOW_S",   5.0))

# Cap in-transit table to avoid unbounded growth during long simulations
MAX_TRANSIT_CIDS   = int(os.environ.get("MAX_TRANSIT_CIDS",    500))

# Keep the last N TRUST_HANDOVER payloads per CID for TRUST_EXPORT_REQ recovery
HANDOVER_HISTORY   = int(os.environ.get("HANDOVER_HISTORY",    20))

# Decision trace log (JSONL). Set to "" to disable.
TRACE_LOG_PATH     = os.environ.get(
    "COORD_TRACE_LOG_PATH",
    "logs/traces/coordinator_decision_trace.jsonl")

# =============================================================================
# SHARED STATE
# =============================================================================

_state_lock = threading.Lock()

# Zone registry:
#   {zone_id (int): {"host": str, "port": int, "status": str,
#                    "last_seen": float, "last_ping_attempt": float,
#                    "handovers_out": int, "handovers_in": int,
#                    "load_failures": int}}
_zone_registry = {}

# In-transit table:
#   {cid (int): {"from_zone": int, "to_zone": int,
#                "handover_sim_ts": float, "handover_wall_ts": float,
#                "state": str,            # PENDING / LOADED / CONFIRMED
#                "p_edge_last": float,
#                "last_verdict": str}}
_in_transit = {}

# Full handover payload history per CID (for TRUST_EXPORT_REQ recovery)
_handover_history = defaultdict(lambda: deque(maxlen=HANDOVER_HISTORY))

# Overlap tracking:
#   {cid (int): {"zones": [z1, z2],
#                "verdicts": {zone_id: verdict},
#                "scores":   {zone_id: p_edge},
#                "window_start": float,
#                "sim_ts": float}}
_overlap_table = {}

# Per-zone stats counters
_zone_stats = defaultdict(lambda: {
    "handover_out":   0, "handover_in":  0,
    "load_ok":        0, "load_fail":    0,
    "consensus_ok":   0, "consensus_miss": 0,
})

# Global counters (single-element lists for mutability inside closures)
_total_handovers     = [0]
_total_load_ok       = [0]
_total_load_fail     = [0]
_total_consensus_ok  = [0]
_total_consensus_miss= [0]

# =============================================================================
# DECISION TRACER  (line-buffered JSONL file)
# =============================================================================

_trace_lock = threading.Lock()
_trace_file = None


def _open_trace_file():
    global _trace_file
    if not TRACE_LOG_PATH:
        return
    try:
        os.makedirs(os.path.dirname(TRACE_LOG_PATH), exist_ok=True)
        _trace_file = open(TRACE_LOG_PATH, "a", buffering=1)
    except Exception as exc:
        print("[COORD] Trace file open failed: %s" % exc)


def trace_event(stage, **fields):
    if not TRACE_LOG_PATH:
        return
    try:
        rec = {"ts": datetime.datetime.utcnow().isoformat(),
               "stage": stage, **fields}
        line = json.dumps(rec, default=str)
        with _trace_lock:
            if _trace_file:
                _trace_file.write(line + "\n")
    except Exception:
        pass

# =============================================================================
# ZONE REGISTRY BUILDER
# =============================================================================

def _build_zone_registry():
    """Populate _zone_registry from _DEFAULT_ZONES and ZONE{N}_* env vars."""
    registry = {}
    for zid, (host, port) in _DEFAULT_ZONES.items():
        registry[zid] = _new_zone_entry(host, port)
    for zid in range(3, MAX_ZONES + 1):
        host = os.environ.get("ZONE%d_EDGE_HOST" % zid, "")
        if host:
            port = int(os.environ.get("ZONE%d_EDGE_PORT" % zid,
                                      str(9999 - zid)))
            registry[zid] = _new_zone_entry(host, port)
    return registry


def _new_zone_entry(host, port):
    return {
        "host":               host,
        "port":               port,
        "status":             "UNKNOWN",
        "last_seen":          0.0,
        "last_ping_attempt":  0.0,
        "handovers_out":      0,
        "handovers_in":       0,
        "load_failures":      0,
    }

# =============================================================================
# TCP FRAMING  (big-endian 4-byte length prefix — matches edge + bridge)
# =============================================================================

def recv_framed(conn):
    """Read one length-prefixed UTF-8 message from conn. Returns str or None."""
    try:
        raw = b""
        while len(raw) < 4:
            chunk = conn.recv(4 - len(raw))
            if not chunk:
                return None
            raw += chunk
        length = struct.unpack("!I", raw)[0]
        if length == 0 or length > 131072:   # 128 KB hard cap
            return None
        data = b""
        while len(data) < length:
            chunk = conn.recv(length - len(data))
            if not chunk:
                return None
            data += chunk
        return data.decode("utf-8", errors="replace").strip()
    except Exception:
        return None


def send_framed(conn, msg):
    """Send a length-prefixed UTF-8 message. Returns True on success."""
    try:
        enc = msg.encode("utf-8")
        conn.sendall(struct.pack("!I", len(enc)) + enc)
        return True
    except Exception:
        return False

# =============================================================================
# OUTBOUND TCP HELPER
# =============================================================================

def tcp_call_framed(host, port, payload_str,
                    timeout_s=None, want_response=True):
    """Send a framed message to host:port; optionally read a response.
    Returns response string or None on any failure.
    """
    ts = timeout_s or FORWARD_TIMEOUT_S
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(ts)
        s.connect((host, port))
        enc = payload_str.encode("utf-8")
        s.sendall(struct.pack("!I", len(enc)) + enc)
        if not want_response:
            s.close()
            return "SENT"
        raw = b""
        while len(raw) < 4:
            chunk = s.recv(4 - len(raw))
            if not chunk:
                break
            raw += chunk
        if len(raw) == 4:
            length = struct.unpack("!I", raw)[0]
            if 0 < length <= 131072:
                data = b""
                while len(data) < length:
                    chunk = s.recv(length - len(data))
                    if not chunk:
                        break
                    data += chunk
                s.close()
                return data.decode("utf-8", errors="replace").strip()
        s.close()
    except Exception:
        pass
    return None


def tcp_ping(host, port):
    """Quick open-port check. Returns True if reachable."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False

# =============================================================================
# ZONE REGISTRY ACCESSORS  (all thread-safe)
# =============================================================================

def get_zone_entry(zone_id):
    with _state_lock:
        return dict(_zone_registry.get(zone_id, {}))


def mark_zone_seen(zone_id):
    with _state_lock:
        if zone_id in _zone_registry:
            _zone_registry[zone_id]["last_seen"] = time.time()
            _zone_registry[zone_id]["status"]    = "ONLINE"


def get_zone_effective_status(zone_id, now=None):
    now = now or time.time()
    with _state_lock:
        entry = _zone_registry.get(zone_id)
        if not entry:
            return "NOT_REGISTERED"
        age = now - entry.get("last_seen", 0.0)
        st  = entry["status"]
        if st == "ONLINE" and age > HEALTH_STALE_S:
            return "STALE"
        return st

# =============================================================================
# FORWARD  TRUST_HANDOVER_LOAD  TO TARGET EDGE
# =============================================================================

def forward_handover_load(to_zone, payload_dict):
    """Send TRUST_HANDOVER_LOAD JSON to the edge of to_zone.
    Returns True on success (edge acknowledged with an ACK-containing response).
    """
    zone = get_zone_entry(to_zone)
    if not zone:
        print("[COORD] FORWARD ERROR: zone %d not registered" % to_zone)
        trace_event("forward_error", to_zone=to_zone,
                    reason="zone_not_registered",
                    cid=payload_dict.get("cid"))
        return False

    msg  = json.dumps(payload_dict)
    resp = tcp_call_framed(zone["host"], zone["port"], msg,
                           timeout_s=FORWARD_TIMEOUT_S,
                           want_response=True)
    cid  = payload_dict.get("cid", -1)

    if resp and "ACK" in resp.upper():
        mark_zone_seen(to_zone)
        with _state_lock:
            _zone_registry[to_zone]["handovers_in"] += 1
            _zone_stats[to_zone]["load_ok"]         += 1
            _total_load_ok[0]                       += 1
        print("[COORD] LOAD OK   CID:%-4d  Z%d  (%s:%d)"
              % (cid, to_zone, zone["host"], zone["port"]))
        trace_event("handover_load_ok", cid=cid, to_zone=to_zone,
                    host=zone["host"], port=zone["port"],
                    response=resp[:80])
        return True

    # Forward failed — edge may be down or returned an unexpected response
    with _state_lock:
        _zone_registry[to_zone]["load_failures"] += 1
        _zone_stats[to_zone]["load_fail"]        += 1
        _total_load_fail[0]                      += 1
    print("[COORD] LOAD FAIL CID:%-4d  Z%d  (%s:%d)  resp=%s"
          % (cid, to_zone, zone["host"], zone["port"],
             repr(resp)[:40] if resp else "None"))
    trace_event("handover_load_fail", cid=cid, to_zone=to_zone,
                host=zone["host"], port=zone["port"],
                response=repr(resp)[:80] if resp else "None")
    return False

# =============================================================================
# HANDLER: TRUST_HANDOVER
# =============================================================================

def handle_trust_handover(payload, conn):
    """Process a TRUST_HANDOVER arriving from an originating edge server.

    Mandatory fields in payload:
        msg_type, from_zone (int), to_zone (int), cid (int)

    Strongly recommended fields (all forwarded verbatim to target edge):
        alpha (float)          Bayesian alpha (honest belief)
        beta  (float)          Bayesian beta  (suspicious belief)
        safe_wins (int)        Consecutive clean BSMs confirmed by edge
        ban_count (int)        Total BAN verdicts accumulated this zone
        p_edge_avg (float)     Mean p_edge over last N packets
        p_edge_last (float)    Most recent p_edge score
        last_verdict (str)     SAFE / WARN / BAN
        ban_streak (int)       Consecutive BAN-zone hits at handover time
        warn_streak (int)      Consecutive WARN-zone hits at handover time
        w_biases (dict)        Cloud teaching biases:
                                 {"b_ts": f, "b_px": f,
                                  "temporal_bias": f, "shadow_boost": f}
        spd_hist (list)        Last 5-10 speed values (m/s) for M1 init
        ts_hist (list)         Last 5-10 ts-sim_ts deltas for M2 init
        vehicle_class (int)    0=normal, 1=emergency, ...
        handover_sim_ts (float) Simulation timestamp at handover decision
        handover_wall_ts (float) Wall-clock time at handover decision
    """
    # [HD-DEFENSE] Preserve explicit metadata so target edge can log
    # that this handover should be treated with decay/probation/CUSUM reset.
    payload.setdefault("handover_defense", {
        "trust_decay": True,
        "probation": True,
        "cusum_reset": True,
    })

    try:
        from_zone = int(payload.get("from_zone", -1))
        to_zone   = int(payload.get("to_zone",   -1))
        cid       = int(payload.get("cid",       -1))

        if from_zone < 0 or to_zone < 0 or cid < 0:
            resp = json.dumps({"status": "ERROR",
                               "reason": "missing_required_fields",
                               "required": ["from_zone", "to_zone", "cid"]})
            send_framed(conn, resp)
            return

        if from_zone == to_zone:
            resp = json.dumps({"status": "ERROR",
                               "reason": "same_zone_handover_not_allowed",
                               "from_zone": from_zone})
            send_framed(conn, resp)
            return

        wall_ts = float(payload.get("handover_wall_ts", time.time()))
        sim_ts  = float(payload.get("handover_sim_ts",  0.0))

        print("[COORD] HANDOVER  CID:%-4d  Z%d --> Z%d  "
              "verdict=%-4s  p_edge=%.3f  sim_ts=%.1f"
              % (cid, from_zone, to_zone,
                 payload.get("last_verdict", "?"),
                 float(payload.get("p_edge_last", 0.0)),
                 sim_ts))

        trace_event("handover_received",
                    cid=cid, from_zone=from_zone, to_zone=to_zone,
                    sim_ts=sim_ts,
                    last_verdict=payload.get("last_verdict", "?"),
                    p_edge_last=payload.get("p_edge_last", 0.0),
                    alpha=payload.get("alpha", 2.0),
                    beta=payload.get("beta",  1.0),
                    safe_wins=payload.get("safe_wins", 0),
                    ban_count=payload.get("ban_count", 0))

        # --- Update from-zone stats and registry ---
        with _state_lock:
            if from_zone in _zone_registry:
                _zone_registry[from_zone]["last_seen"]     = wall_ts
                _zone_registry[from_zone]["status"]        = "ONLINE"
                _zone_registry[from_zone]["handovers_out"] += 1
            _zone_stats[from_zone]["handover_out"] += 1
            _total_handovers[0]                    += 1

        # --- Record in in-transit table (evict oldest if at capacity) ---
        with _state_lock:
            if len(_in_transit) >= MAX_TRANSIT_CIDS:
                oldest = min(_in_transit,
                             key=lambda c: _in_transit[c]["handover_wall_ts"])
                del _in_transit[oldest]
            _in_transit[cid] = {
                "from_zone":        from_zone,
                "to_zone":          to_zone,
                "handover_sim_ts":  sim_ts,
                "handover_wall_ts": wall_ts,
                "state":            "PENDING",
                "p_edge_last":      float(payload.get("p_edge_last", 0.0)),
                "last_verdict":     str(payload.get("last_verdict", "SAFE")),
            }
            # Persist full payload to per-CID history for TRUST_EXPORT_REQ
            _handover_history[cid].append(dict(payload))

        # --- Build TRUST_HANDOVER_LOAD for target edge ---
        load_payload = dict(payload)
        load_payload["msg_type"]       = "TRUST_HANDOVER_LOAD"
        load_payload["coord_wall_ts"]  = time.time()
        load_payload["coord_version"]  = VERSION

        # --- Forward to target zone (blocking, with ACK wait) ---
        ok = forward_handover_load(to_zone, load_payload)

        if ok:
            with _state_lock:
                if cid in _in_transit:
                    _in_transit[cid]["state"] = "LOADED"

        # --- Ack back to originating edge ---
        resp_dict = {
            "status":    "OK" if ok else "FORWARD_FAIL",
            "cid":       cid,
            "from_zone": from_zone,
            "to_zone":   to_zone,
            "loaded":    ok,
        }
        send_framed(conn, json.dumps(resp_dict))

    except Exception as exc:
        print("[COORD] handle_trust_handover exception: %s" % exc)
        trace_event("handover_exception", error=str(exc))
        try:
            send_framed(conn, json.dumps({"status": "ERROR",
                                          "reason": str(exc)}))
        except Exception:
            pass

# =============================================================================
# HANDLER: TRUST_EXPORT_REQ
# =============================================================================

def handle_trust_export_req(payload, conn):
    """Return saved TRUST_HANDOVER state for a given CID, or all in-transit
    CIDs for a given zone_id.  Used by a restarted edge to recover state.

    Request (specific CID):
        {"msg_type": "TRUST_EXPORT_REQ", "cid": X}

    Request (all in-transit for a zone):
        {"msg_type": "TRUST_EXPORT_REQ", "zone_id": Y}

    Request (all in-transit, any zone):
        {"msg_type": "TRUST_EXPORT_REQ"}
    """
    try:
        cid_raw = payload.get("cid")
        zone_id = int(payload.get("zone_id", -1))

        # --- All in-transit vehicles for a zone (or all zones) ---
        if cid_raw is None:
            with _state_lock:
                if zone_id >= 0:
                    entries = [dict(v) for k, v in _in_transit.items()
                               if v.get("to_zone") == zone_id]
                else:
                    entries = [dict(v) for v in _in_transit.values()]
            resp = json.dumps({
                "status":   "OK",
                "zone_id":  zone_id,
                "entries":  entries,
                "count":    len(entries),
            })
            send_framed(conn, resp)
            trace_event("trust_export_bulk_served",
                        zone_id=zone_id, count=len(entries))
            return

        # --- Specific CID ---
        cid = int(cid_raw)
        with _state_lock:
            history = list(_handover_history.get(cid, []))
            transit = dict(_in_transit.get(cid, {}))

        if not history:
            send_framed(conn, json.dumps({"status": "NOT_FOUND", "cid": cid}))
            return

        resp = json.dumps({
            "status":          "OK",
            "cid":             cid,
            "latest_handover": history[-1],
            "transit_state":   transit,
            "history_count":   len(history),
        })
        send_framed(conn, resp)
        trace_event("trust_export_cid_served",
                    cid=cid, zone_id=zone_id,
                    history_count=len(history))

    except Exception as exc:
        print("[COORD] handle_trust_export_req exception: %s" % exc)
        send_framed(conn, json.dumps({"status": "ERROR", "reason": str(exc)}))

# =============================================================================
# HANDLER: OVERLAP_SCORE
# =============================================================================

def handle_overlap_score(payload, conn):
    """Track dual-zone scoring of a vehicle during overlap-region transit.

    An edge sends OVERLAP_SCORE when it continues to receive TELEM from a CID
    that is LOADED into the adjacent zone (i.e., the vehicle is in the overlap
    region and both edges are scoring it simultaneously).

    The coordinator collects scores from both zones within OVERLAP_WINDOW_S
    and logs consensus or disagreement.  The more severe verdict wins on
    disagreement (BAN > WARN > SAFE).

    Request fields:
        msg_type, cid (int), zone_id (int),
        verdict (str), p_edge (float), sim_ts (float)
    """
    try:
        cid     = int(payload.get("cid",     -1))
        zone_id = int(payload.get("zone_id", -1))
        verdict = str(payload.get("verdict",  "SAFE"))
        p_edge  = float(payload.get("p_edge",  0.0))
        sim_ts  = float(payload.get("sim_ts",  0.0))
        wall_ts = time.time()

        if cid < 0 or zone_id < 0:
            send_framed(conn, json.dumps({"status": "ERROR",
                                          "reason": "missing_cid_or_zone_id"}))
            return

        consensus = None
        sev = {"BAN": 3, "WARN": 2, "SAFE": 1}

        with _state_lock:
            entry = _overlap_table.get(cid)
            if entry is None:
                # First zone to report — open consensus window
                _overlap_table[cid] = {
                    "zones":        [zone_id],
                    "verdicts":     {zone_id: verdict},
                    "scores":       {zone_id: p_edge},
                    "window_start": wall_ts,
                    "sim_ts":       sim_ts,
                }
            else:
                age        = wall_ts - entry["window_start"]
                same_zone  = zone_id in entry["zones"]
                in_window  = age <= OVERLAP_WINDOW_S

                if in_window and not same_zone:
                    # Second zone reporting within window — compute consensus
                    entry["zones"].append(zone_id)
                    entry["verdicts"][zone_id] = verdict
                    entry["scores"][zone_id]   = p_edge

                    v_list = list(entry["verdicts"].values())
                    if len(set(v_list)) == 1:
                        # Both zones agree
                        consensus = {"type": "AGREE", "verdict": v_list[0],
                                     "scores": dict(entry["scores"])}
                        for z in entry["zones"]:
                            _zone_stats[z]["consensus_ok"] += 1
                        _total_consensus_ok[0] += 1
                        print("[COORD] CONSENSUS AGREE  CID:%-4d  verdict=%s  "
                              "p=[%s]"
                              % (cid, v_list[0],
                                 ", ".join("Z%d:%.3f" % (z, s)
                                           for z, s in entry["scores"].items())))
                    else:
                        # Zones disagree — use most conservative verdict
                        conservative = max(v_list,
                                           key=lambda v: sev.get(v, 0))
                        consensus = {
                            "type":      "DISAGREE",
                            "verdicts":  dict(entry["verdicts"]),
                            "scores":    dict(entry["scores"]),
                            "resolved":  conservative,
                        }
                        for z in entry["zones"]:
                            _zone_stats[z]["consensus_miss"] += 1
                        _total_consensus_miss[0] += 1
                        vd = entry["verdicts"]
                        sc = entry["scores"]
                        items = [(z, vd[z], sc[z]) for z in entry["zones"]]
                        parts = "  ".join("Z%d=%s(%.3f)" % (z, v, p)
                                          for z, v, p in items)
                        print("[COORD] CONSENSUS MISS   CID:%-4d  %s  --> %s"
                              % (cid, parts, conservative))
                else:
                    # Window expired or same zone re-reported — reset window
                    _overlap_table[cid] = {
                        "zones":        [zone_id],
                        "verdicts":     {zone_id: verdict},
                        "scores":       {zone_id: p_edge},
                        "window_start": wall_ts,
                        "sim_ts":       sim_ts,
                    }

        if consensus:
            trace_event("overlap_consensus",
                        cid=cid,
                        consensus_type=consensus["type"],
                        resolved=consensus.get(
                            "resolved",
                            consensus.get("verdict", "SAFE")),
                        scores=consensus.get("scores"),
                        verdicts=consensus.get(
                            "verdicts",
                            {zone_id: verdict}),
                        sim_ts=sim_ts)

        resp = {"status": "OK", "cid": cid, "zone_id": zone_id}
        if consensus:
            resp["consensus"] = consensus
        send_framed(conn, json.dumps(resp))

    except Exception as exc:
        print("[COORD] handle_overlap_score exception: %s" % exc)
        send_framed(conn, json.dumps({"status": "ERROR", "reason": str(exc)}))

# =============================================================================
# HANDLER: ZONE_STATUS
# =============================================================================

def handle_zone_status(payload, conn):
    """Return health, counts, and registry for all known zones."""
    try:
        now        = time.time()
        zones_info = []
        with _state_lock:
            for zid, info in sorted(_zone_registry.items()):
                age = now - info.get("last_seen", 0.0)
                st  = info["status"]
                if st == "ONLINE" and age > HEALTH_STALE_S:
                    st = "STALE"
                zones_info.append({
                    "zone_id":       zid,
                    "host":          info["host"],
                    "port":          info["port"],
                    "status":        st,
                    "last_seen_s":   round(age, 1),
                    "handovers_out": info["handovers_out"],
                    "handovers_in":  info["handovers_in"],
                    "load_failures": info["load_failures"],
                    "stats":         dict(_zone_stats[zid]),
                })
            in_transit_count = len(_in_transit)

        resp = {
            "status":          "OK",
            "coordinator":     VERSION,
            "zones":           zones_info,
            "total_handovers": _total_handovers[0],
            "total_load_ok":   _total_load_ok[0],
            "total_load_fail": _total_load_fail[0],
            "consensus_ok":    _total_consensus_ok[0],
            "consensus_miss":  _total_consensus_miss[0],
            "in_transit_cids": in_transit_count,
        }
        send_framed(conn, json.dumps(resp))
        trace_event("zone_status_query",
                    zones=[z["zone_id"] for z in zones_info])

    except Exception as exc:
        print("[COORD] handle_zone_status exception: %s" % exc)
        send_framed(conn, json.dumps({"status": "ERROR", "reason": str(exc)}))

# =============================================================================
# HANDLER: RESET
# =============================================================================

def handle_reset(conn):
    """Clear all in-memory state.
    Called by launch_pipeline_generic.sh before each experiment (same pattern
    as bridge and edge RESET handlers).
    """
    with _state_lock:
        _in_transit.clear()
        _handover_history.clear()
        _overlap_table.clear()
        for zid in _zone_registry:
            _zone_registry[zid]["handovers_out"] = 0
            _zone_registry[zid]["handovers_in"]  = 0
            _zone_registry[zid]["load_failures"] = 0
        for zid in list(_zone_stats.keys()):
            for k in _zone_stats[zid]:
                _zone_stats[zid][k] = 0
        _total_handovers[0]      = 0
        _total_load_ok[0]        = 0
        _total_load_fail[0]      = 0
        _total_consensus_ok[0]   = 0
        _total_consensus_miss[0] = 0

    print("[COORD] RESET OK — all in-memory state cleared")
    trace_event("reset", event="all_state_cleared")
    send_framed(conn, "RESET_OK")

# =============================================================================
# CLIENT HANDLER (dispatcher)
# =============================================================================

def handle_client(conn, addr):
    """Per-connection thread: parse message type, dispatch to handler."""
    try:
        conn.settimeout(TCP_TIMEOUT_S)
        raw = recv_framed(conn)
        if not raw:
            return

        # Plain-text RESET (matches bridge / edge pattern for launch script)
        if raw.strip().upper() == "RESET":
            handle_reset(conn)
            return

        # All coordinator messages are JSON
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            print("[COORD] Non-JSON from %s: %s" % (addr, raw[:80]))
            send_framed(conn, json.dumps({"status": "ERROR",
                                          "reason": "json_parse_error",
                                          "received": raw[:80]}))
            return

        msg_type = str(payload.get("msg_type", "")).upper()

        if msg_type == "TRUST_HANDOVER":
            handle_trust_handover(payload, conn)

        elif msg_type == "TRUST_EXPORT_REQ":
            handle_trust_export_req(payload, conn)

        elif msg_type == "OVERLAP_SCORE":
            handle_overlap_score(payload, conn)

        elif msg_type in ("ZONE_STATUS", "STATUS"):
            handle_zone_status(payload, conn)

        elif msg_type == "RESET":
            handle_reset(conn)

        else:
            print("[COORD] Unknown msg_type '%s' from %s" % (msg_type, addr))
            send_framed(conn, json.dumps({"status": "ERROR",
                                          "reason": "unknown_msg_type",
                                          "msg_type": msg_type}))

    except Exception as exc:
        print("[COORD] Client handler error %s: %s" % (addr, exc))
    finally:
        try:
            conn.close()
        except Exception:
            pass

# =============================================================================
# BACKGROUND: ZONE HEALTH MONITOR
# =============================================================================

def zone_health_monitor(shutdown_flag):
    """Ping each registered zone's edge server every HEALTH_INTERVAL_S.
    Updates status: ONLINE / STALE / OFFLINE.
    """
    print("[COORD] Health monitor started  "
          "(interval=%.0fs  stale_after=%.0fs)"
          % (HEALTH_INTERVAL_S, HEALTH_STALE_S))

    while not shutdown_flag.is_set():
        now = time.time()
        with _state_lock:
            snapshot = [(zid, dict(info))
                        for zid, info in _zone_registry.items()]

        for zid, info in snapshot:
            # Throttle: act only once per HEALTH_INTERVAL_S per zone
            if now - info.get("last_ping_attempt", 0.0) < HEALTH_INTERVAL_S:
                continue

            with _state_lock:
                if zid in _zone_registry:
                    _zone_registry[zid]["last_ping_attempt"] = now

            alive = tcp_ping(info["host"], info["port"])

            with _state_lock:
                if zid not in _zone_registry:
                    continue
                if alive:
                    _zone_registry[zid]["status"]    = "ONLINE"
                    _zone_registry[zid]["last_seen"] = now
                else:
                    age = now - info.get("last_seen", 0.0)
                    _zone_registry[zid]["status"] = (
                        "OFFLINE" if age > HEALTH_STALE_S else "STALE")

            if not alive:
                age = now - info.get("last_seen", 0.0)
                print("[COORD] HEALTH MISS  Zone %-2d  %s:%d  "
                      "last_seen=%.0fs ago  status=%s"
                      % (zid, info["host"], info["port"], age,
                         _zone_registry.get(zid, {}).get("status", "?")))
                trace_event("zone_health_miss",
                            zone_id=zid, host=info["host"], port=info["port"],
                            last_seen_age=round(age, 1))

        shutdown_flag.wait(timeout=2.0)

# =============================================================================
# BACKGROUND: OVERLAP TABLE JANITOR
# =============================================================================

def overlap_janitor(shutdown_flag):
    """Periodically evict expired overlap entries to bound table size."""
    while not shutdown_flag.is_set():
        now     = time.time()
        expired = []
        with _state_lock:
            for cid, entry in list(_overlap_table.items()):
                if now - entry.get("window_start", 0.0) > OVERLAP_WINDOW_S * 10:
                    expired.append(cid)
            for cid in expired:
                del _overlap_table[cid]
        if expired:
            trace_event("overlap_janitor_cleaned", evicted=len(expired))
        shutdown_flag.wait(timeout=30.0)

# =============================================================================
# PRINT METRICS
# =============================================================================

def print_metrics():
    """Dump final statistics to stdout on shutdown."""
    now = time.time()
    print("\n" + "=" * 64)
    print("  TRUST COORDINATOR METRICS  (%s)" % VERSION)
    print("=" * 64)
    with _state_lock:
        print("  Total handovers      : %d" % _total_handovers[0])
        print("  Loads OK  / FAIL     : %d / %d"
              % (_total_load_ok[0], _total_load_fail[0]))
        if _total_load_ok[0] + _total_load_fail[0] > 0:
            success_pct = (100.0 * _total_load_ok[0]
                           / (_total_load_ok[0] + _total_load_fail[0]))
            print("  Load success rate    : %.1f%%" % success_pct)
        print("  Consensus OK / MISS  : %d / %d"
              % (_total_consensus_ok[0], _total_consensus_miss[0]))
        print("  In-transit CIDs      : %d" % len(_in_transit))
        print("")
        print("  Zone breakdown:")
        for zid, info in sorted(_zone_registry.items()):
            age = now - info.get("last_seen", 0.0)
            st  = info["status"]
            if st == "ONLINE" and age > HEALTH_STALE_S:
                st = "STALE"
            stats = _zone_stats[zid]
            print("    Zone %-2d  %-7s  %s:%-5d  "
                  "out=%-4d  in=%-4d  fail=%-3d  "
                  "consensus_ok=%-3d  miss=%-3d"
                  % (zid, st, info["host"], info["port"],
                     info["handovers_out"], info["handovers_in"],
                     info["load_failures"],
                     stats["consensus_ok"], stats["consensus_miss"]))
    print("=" * 64)

# =============================================================================
# MAIN
# =============================================================================

def main():
    global _zone_registry

    parser = argparse.ArgumentParser(
        description="V2X Multi-UAV Trust Coordinator %s" % VERSION)
    parser.add_argument(
        "--port", type=int, default=COORD_PORT,
        help="Coordinator listen port (default %d, env COORD_PORT)" % COORD_PORT)
    parser.add_argument(
        "--zone1-edge-host", type=str,
        default=os.environ.get("ZONE1_EDGE_HOST", "127.0.0.1"),
        help="Edge AI host for zone 1 (env ZONE1_EDGE_HOST)")
    parser.add_argument(
        "--zone1-edge-port", type=int,
        default=int(os.environ.get("ZONE1_EDGE_PORT", 9999)),
        help="Edge AI port for zone 1 (env ZONE1_EDGE_PORT)")
    parser.add_argument(
        "--zone2-edge-host", type=str,
        default=os.environ.get("ZONE2_EDGE_HOST", "127.0.0.1"),
        help="Edge AI host for zone 2 (env ZONE2_EDGE_HOST)")
    parser.add_argument(
        "--zone2-edge-port", type=int,
        default=int(os.environ.get("ZONE2_EDGE_PORT", 9995)),
        help="Edge AI port for zone 2 (env ZONE2_EDGE_PORT)")
    args = parser.parse_args()

    # Apply CLI overrides to the defaults dict before building registry
    _DEFAULT_ZONES[1] = (args.zone1_edge_host, args.zone1_edge_port)
    _DEFAULT_ZONES[2] = (args.zone2_edge_host, args.zone2_edge_port)

    _zone_registry = _build_zone_registry()

    print("=" * 64)
    print("  TRUST COORDINATOR %s  --  Multi-UAV V2X" % VERSION)
    print("=" * 64)
    print("[COORD] Listen port       : %d" % args.port)
    print("[COORD] Registered zones  :")
    for zid, info in sorted(_zone_registry.items()):
        print("  Zone %-2d : %s:%d"
              % (zid, info["host"], info["port"]))
    print("[COORD] Health interval   : %.0fs  |  Stale after: %.0fs"
          % (HEALTH_INTERVAL_S, HEALTH_STALE_S))
    print("[COORD] Overlap window    : %.1fs" % OVERLAP_WINDOW_S)
    print("[COORD] Max transit CIDs  : %d"    % MAX_TRANSIT_CIDS)
    print("[COORD] Trace log         : %s"
          % (TRACE_LOG_PATH if TRACE_LOG_PATH else "disabled"))

    _open_trace_file()
    trace_event("startup", port=args.port, version=VERSION,
                zones={str(zid): "%s:%d" % (info["host"], info["port"])
                       for zid, info in _zone_registry.items()},
                health_interval_s=HEALTH_INTERVAL_S,
                overlap_window_s=OVERLAP_WINDOW_S,
                max_transit_cids=MAX_TRANSIT_CIDS)

    # Start background threads
    shutdown_flag = threading.Event()

    threading.Thread(target=zone_health_monitor,
                     args=(shutdown_flag,), daemon=True).start()
    threading.Thread(target=overlap_janitor,
                     args=(shutdown_flag,), daemon=True).start()

    # Main TCP server
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((COORD_HOST, args.port))
    srv.listen(MAX_CLIENTS)

    def _shutdown_handler(signum, frame):
        print("[COORD] Signal %d received — shutting down..." % signum)
        shutdown_flag.set()
        srv.close()

    signal.signal(signal.SIGTERM, _shutdown_handler)
    signal.signal(signal.SIGINT,  _shutdown_handler)

    print("[COORD] Ready — listening on port %d\n" % args.port)

    try:
        while not shutdown_flag.is_set():
            try:
                conn, addr = srv.accept()
                threading.Thread(target=handle_client,
                                 args=(conn, addr),
                                 daemon=True).start()
            except OSError:
                break
            except KeyboardInterrupt:
                break
            except Exception as exc:
                if not shutdown_flag.is_set():
                    print("[COORD] Accept error: %s" % exc)
    finally:
        shutdown_flag.set()
        print_metrics()
        if _trace_file:
            try:
                _trace_file.close()
            except Exception:
                pass
        try:
            srv.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
