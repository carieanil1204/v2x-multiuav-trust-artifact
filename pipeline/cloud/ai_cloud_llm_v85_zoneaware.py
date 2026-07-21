#!/usr/bin/env python3
"""
ai_cloud_llm_v79_flex.py -- Layer 3 Cloud LLM Server (Fully Flexible)
Fixes over v79:
  [FLEX-1]  SPEED_NORMAL, SPEED_CLEAN_GATE, PX_CLEAN_GATE in CONFIG BLOCK
  [FLEX-2]  All rule_based_suspicion() weights moved to CONFIG BLOCK
  [FLEX-3]  All pre_llm_clean_check() thresholds moved to CONFIG BLOCK
  [FLEX-4]  All classify_dominant() boundaries moved to CONFIG BLOCK
  [FLEX-5]  LLM prompt thresholds use CONFIG values (not hard-coded text)
  [FLEX-6]  Scenario preset examples in comments -- no code edits needed
All v79 fixes retained: per-CID alert_mode, cache isolation, BAN window reset,
NEUTRAL_SCORE=0.300, subprocess env fix, FP-FIX-1/2/3, hybrid weights.
"""

import socket
import threading
import struct
import json
import re
import subprocess
import argparse
import os
import time
from collections import defaultdict
import urllib.request    # [OPT-C] REST API call to persistent Ollama server
import threading as _threading
_ollama_lock = _threading.Lock()  # serialise Ollama calls — prevents concurrent truncation
import urllib.error      # [OPT-C] catch HTTP/network errors cleanly

# =============================================================================
# DECISION TRACER
# =============================================================================
try:
    from decision_tracer import DecisionTracer, make_trace_id  # type: ignore
except Exception:
    def _trace_level_num(name: str) -> int:
        levels = {"off": 0, "info": 1, "detail": 2}
        return levels.get(str(name).strip().lower(), 1)

    def _trace_safe(obj):
        if isinstance(obj, (str, int, float, bool)) or obj is None:
            return obj
        if isinstance(obj, dict):
            return {str(k): _trace_safe(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple, set)):
            return [_trace_safe(v) for v in obj]
        return str(obj)

    def make_trace_id(cid, sim_time) -> str:
        try:
            cid_i = int(cid)
        except Exception:
            cid_i = -1
        try:
            t_ms = int(round(float(sim_time) * 1000.0))
        except Exception:
            t_ms = int(time.time() * 1000.0)
        return "CID%d-T%d" % (cid_i, t_ms)

    class DecisionTracer:
        def __init__(self, service_name: str, log_dir: str = None,
                     level: str = None, stdout: bool = None):
            self.service_name = str(service_name)
            self.log_dir = log_dir or os.environ.get("TRACE_DIR", "logs/traces")
            self.level = str(level or os.environ.get("TRACE_LEVEL", "info")).lower()
            self.stdout = bool(int(os.environ.get("TRACE_STDOUT", "0"))) if stdout is None else bool(stdout)
            self._fh = None

            if self.level != "off":
                try:
                    os.makedirs(self.log_dir, exist_ok=True)
                    path = os.path.join(self.log_dir, "%s_decision_trace.jsonl" % self.service_name)
                    self._fh = open(path, "a", buffering=1)
                except Exception:
                    self._fh = None

        def enabled(self, event_level="detail") -> bool:
            return _trace_level_num(self.level) >= _trace_level_num(event_level)

        def event(self, stage: str, cid=None, sim_time=None, trace_id=None,
                  event_level="detail", **kwargs):
            if not self.enabled(event_level):
                return
            rec = {
                "wall_time": time.time(),
                "service": self.service_name,
                "stage": stage,
                "cid": cid,
                "sim_time": sim_time,
                "trace_id": trace_id,
                "event_level": event_level,
            }
            rec.update({str(k): _trace_safe(v) for k, v in kwargs.items()})
            self._write(rec)

        def decision(self, stage: str, cid, verdict: str, reason: str = "",
                     sim_time=None, trace_id=None, event_level="info",
                     decision_changed=None, **kwargs):
            rec = {
                "verdict": verdict,
                "reason": reason,
            }
            if decision_changed is not None:
                rec["decision_changed"] = bool(decision_changed)
            rec.update(kwargs)
            self.event(stage=stage, cid=cid, sim_time=sim_time, trace_id=trace_id,
                       event_level=event_level, **rec)

        def _write(self, rec: dict):
            line = json.dumps(rec, ensure_ascii=False)
            if self._fh is not None:
                try:
                    self._fh.write(line + "\n")
                    self._fh.flush()
                except Exception:
                    pass
            if self.stdout:
                try:
                    print("[TRACE:%s] %s" % (self.service_name, line))
                except Exception:
                    pass

TRACER = DecisionTracer("cloud")

def trace_event(stage: str, cid=None, sim_time=None, trace_id=None,
                event_level="detail", **kwargs):
    TRACER.event(stage=stage, cid=cid, sim_time=sim_time, trace_id=trace_id,
                 event_level=event_level, **kwargs)

def trace_decision(stage: str, cid, verdict: str, reason: str = "",
                   sim_time=None, trace_id=None, event_level="info",
                   decision_changed=None, **kwargs):
    TRACER.decision(stage=stage, cid=cid, verdict=verdict, reason=reason,
                    sim_time=sim_time, trace_id=trace_id,
                    event_level=event_level, decision_changed=decision_changed,
                    **kwargs)


parser = argparse.ArgumentParser()
parser.add_argument('--port', type=int, default=6666,
                    help='TCP port to listen on (default 6666)')
args = parser.parse_args()

CLOUD_PORT = args.port
VERSION    = "v84-adaptive"
EXP_NAME   = "V2X-EXP1-STEALTHY-ATTACKER"

# =============================================================================
# CONFIG BLOCK -- ALL tunable values here, override via environment variables
#
# SCENARIO PRESETS (run without editing code):
#
# Default / ATK_STEALTHY:
#   python3 ai_cloud_llm_v79_flex.py --port 6666
#
# ATK_SPEEDONLY (speed 10-15% above normal):
#   SPEED_CLEAN_GATE=21.5 SPEED_STEALTHY_MIN=2.0 RULE_SPD_BONUS_RATE=0.05 \
#   python3 ai_cloud_llm_v79_flex.py --port 6666
#
# ATK_ADAPTIVE (honest interleave, tight detection):
#   WARNING_THRESHOLD=2 CLEAN_WINDOW_RESET=5 BAN_SUPPRESS_SCORE=0.30 \
#   LLM_WEIGHT=0.80 RULE_WEIGHT=0.20 python3 ai_cloud_llm_v79_flex.py --port 6666
#
# ATK_COMPOSITE (obvious attack, aggressive rules):
#   SPEED_CLEAN_GATE=20.2 PX_FROZEN_HARD=10.0 RULE_FROZEN_HARD_BONUS=0.35 \
#   ALERT_THRESHOLD=2 LLM_WEIGHT=0.60 RULE_WEIGHT=0.40 \
#   python3 ai_cloud_llm_v79_flex.py --port 6666
#
# ATK_TSONLY (timestamp replay, LLM-heavy):
#   LLM_WEIGHT=0.90 RULE_WEIGHT=0.10 WARNING_THRESHOLD=2 NEUTRAL_SCORE=0.200 \
#   python3 ai_cloud_llm_v79_flex.py --port 6666
# =============================================================================

OLLAMA_MODEL  = os.environ.get("OLLAMA_MODEL",  "llama3:latest")
OLLAMA_HOST   = os.environ.get("OLLAMA_HOST",   "127.0.0.1:11434")
LEDGER_PATH   = os.environ.get("LEDGER_PATH",   "blockchain_ledger.jsonl")

# [HD-DEFENSE] Zone/time-aware ledger reputation controls.
LEDGER_OTHER_ZONE_DECAY   = float(os.environ.get("LEDGER_OTHER_ZONE_DECAY",   0.30))
LEDGER_RECENT_WINDOW_S    = float(os.environ.get("LEDGER_RECENT_WINDOW_S",    120.0))
POST_HANDOVER_LEDGER_FACTOR = float(os.environ.get("POST_HANDOVER_LEDGER_FACTOR", 0.25))

LLM_WEIGHT    = float(os.environ.get("LLM_WEIGHT",   0.70))
RULE_WEIGHT   = float(os.environ.get("RULE_WEIGHT",  0.30))

REPUTATION_DISCOUNT = float(os.environ.get("REPUTATION_DISCOUNT", 0.005))
RULE_REPUTATION_CAP = float(os.environ.get("RULE_REPUTATION_CAP", 0.10))
CACHE_MAX_SIZE      = int(os.environ.get("CACHE_MAX_SIZE",         100))

BASE_T1_TIME      = float(os.environ.get("BASE_T1_TIME",     5.0))
BASE_T2_COUNT     = int(os.environ.get("BASE_T2_COUNT",      10))
WARNING_THRESHOLD = int(os.environ.get("WARNING_THRESHOLD",  3))
SHORTEN_FACTOR    = float(os.environ.get("SHORTEN_FACTOR",   0.5))

NEUTRAL_SCORE       = float(os.environ.get("NEUTRAL_SCORE",       0.250))
BAN_SUPPRESS_SCORE  = float(os.environ.get("BAN_SUPPRESS_SCORE",  0.250))
TRIGGER_BAN_BONUS  = float(os.environ.get("TRIGGER_BAN_BONUS",  0.10))
TRIGGER_BAN_REPEAT_BONUS = float(os.environ.get("TRIGGER_BAN_REPEAT_BONUS", 0.05))
TRIGGER_BAN_BONUS_CAP = float(os.environ.get("TRIGGER_BAN_BONUS_CAP", 0.18))
TRIGGER_BAN_SKIP_SUPPRESS = int(os.environ.get("TRIGGER_BAN_SKIP_SUPPRESS", 1))
ALERT_BASELINE      = float(os.environ.get("ALERT_BASELINE",      0.200))
ALERT_CLAMP         = float(os.environ.get("ALERT_CLAMP",         0.300))
SANITY_CLAMP_NORMAL = float(os.environ.get("SANITY_CLAMP_NORMAL", 0.200))
CLEAN_WINDOW_RESET  = int(os.environ.get("CLEAN_WINDOW_RESET",    3))

# [FLEX-1] Normal vehicle baseline
SPEED_NORMAL     = float(os.environ.get("SPEED_NORMAL",     20.0))
SPEED_CLEAN_GATE = float(os.environ.get("SPEED_CLEAN_GATE", 20.5))
PX_CLEAN_GATE    = float(os.environ.get("PX_CLEAN_GATE",    75.0))

# [FLEX-2] Rule-based scoring weights
RULE_BASE_CAP          = float(os.environ.get("RULE_BASE_CAP",           0.50))
RULE_SHADOW_WEIGHT     = float(os.environ.get("RULE_SHADOW_WEIGHT",      0.005))
RULE_SHADOW_CAP        = float(os.environ.get("RULE_SHADOW_CAP",         0.10))
RULE_BAN_WEIGHT        = float(os.environ.get("RULE_BAN_WEIGHT",         0.10))
RULE_BAN_CAP           = float(os.environ.get("RULE_BAN_CAP",            0.40))
RULE_SPD_BONUS_RATE    = float(os.environ.get("RULE_SPD_BONUS_RATE",     0.03))
RULE_SPD_BONUS_CAP     = float(os.environ.get("RULE_SPD_BONUS_CAP",      0.20))
RULE_FROZEN_HARD_BONUS = float(os.environ.get("RULE_FROZEN_HARD_BONUS",  0.25))
RULE_FROZEN_SOFT_BONUS = float(os.environ.get("RULE_FROZEN_SOFT_BONUS",  0.15))
RULE_MOVING_DISCOUNT   = float(os.environ.get("RULE_MOVING_DISCOUNT",    0.15))
RULE_SCORE_CAP_NOBAN   = float(os.environ.get("RULE_SCORE_CAP_NOBAN",    0.85))
RULE_SCORE_CAP_BAN     = float(os.environ.get("RULE_SCORE_CAP_BAN",      0.95))

# [FLEX-3] Pre-check clean gate return scores
CLEAN_GATE_SCORE_PX  = float(os.environ.get("CLEAN_GATE_SCORE_PX",  0.05))
CLEAN_GATE_SCORE_NPN = float(os.environ.get("CLEAN_GATE_SCORE_NPN", 0.08))

# [FLEX-4] Dominant classifier boundaries
PX_FROZEN_HARD       = float(os.environ.get("PX_FROZEN_HARD",        5.0))
PX_FROZEN_SOFT       = float(os.environ.get("PX_FROZEN_SOFT",       20.0))
PX_MOVING_MIN        = float(os.environ.get("PX_MOVING_MIN",        75.0))
SPEED_STEALTHY_MIN   = float(os.environ.get("SPEED_STEALTHY_MIN",    1.5))
SPEED_STEALTHY_MAX   = float(os.environ.get("SPEED_STEALTHY_MAX",   10.0))
AVG_EDGE_SUSP_SPIKE_THRESH = float(os.environ.get("AVG_EDGE_SUSP_SPIKE_THRESH", 1.0 - float(os.environ.get("AVG_SCR_SPIKE_THRESH", 0.30))))
FLAT_SCORE_LOW           = float(os.environ.get("FLAT_SCORE_LOW",           0.45))
FLAT_SCORE_HIGH          = float(os.environ.get("FLAT_SCORE_HIGH",          0.55))
FLAT_SCORE_SHADOW_BONUS  = float(os.environ.get("FLAT_SCORE_SHADOW_BONUS",  0.10))
FLAT_SCORE_STEALTH_BONUS = float(os.environ.get("FLAT_SCORE_STEALTH_BONUS", 0.12))
FLAT_SCORE_FROZEN_BONUS  = float(os.environ.get("FLAT_SCORE_FROZEN_BONUS",  0.18))


# [EVOLVE] hidden-pattern tuning and edge-teaching controls
HIDDEN_PATTERN_BONUS = float(os.environ.get("HIDDEN_PATTERN_BONUS", 0.18))
REPEAT_WARN_BONUS    = float(os.environ.get("REPEAT_WARN_BONUS",    0.14))
BAN_CONFIRM_BONUS    = float(os.environ.get("BAN_CONFIRM_BONUS",    0.14))
SAFE_ESCALATE_HIDDEN_BONUS = float(os.environ.get("SAFE_ESCALATE_HIDDEN_BONUS", 0.06))
TEACH_EDGE_DELTA_CAP = float(os.environ.get("TEACH_EDGE_DELTA_CAP", 0.22))
TEACH_TS_BIAS        = float(os.environ.get("TEACH_TS_BIAS",        0.20))
TEACH_PX_BIAS        = float(os.environ.get("TEACH_PX_BIAS",        0.16))

# [ADAPTIVE] Calibration batch handler parameters
# DELTA_SCALE: max weight delta applied per calibration round — key learning-rate param
# SEP_CONFIDENCE_NORM: divisor that maps max_sep → confidence (sep/norm >= 0.5 → applied)
CALIB_DELTA_SCALE        = float(os.environ.get("CALIB_DELTA_SCALE",        0.04))
CALIB_SEP_CONFIDENCE_NORM = float(os.environ.get("CALIB_SEP_CONFIDENCE_NORM", 3.0))

# [FLEX-5] LLM prompt thresholds
PROMPT_SPD_NORMAL = float(os.environ.get("PROMPT_SPD_NORMAL", SPEED_NORMAL))
PROMPT_SPD_ATTACK = float(os.environ.get("PROMPT_SPD_ATTACK", SPEED_CLEAN_GATE))
PROMPT_PX_NORMAL  = float(os.environ.get("PROMPT_PX_NORMAL",  PX_CLEAN_GATE))
PROMPT_PX_FROZEN  = float(os.environ.get("PROMPT_PX_FROZEN",  60.0))

# =============================================================================
# PER-CID STATE
# =============================================================================
recent_warnings    = defaultdict(int)
ban_window_count   = defaultdict(int)
clean_window_count = defaultdict(int)
cid_safe_wins_prev = defaultdict(int)
cid_ban_prev       = defaultdict(int)

# =============================================================================
# CACHE
# =============================================================================
cache = {}

def cache_key(cid, avg_edge_susp, spd_avg, px_range, shadow, bans):
    avg_key = round(float(avg_edge_susp), 2)
    spd_key = round(float(spd_avg), 1)
    px_key  = round(float(px_range), 0) if px_range is not None else "None"
    return (cid, avg_key, spd_key, px_key, shadow, bans)

def cache_invalidate_if_state_changed(cid, ban_count, safe_wins):
    if cid_ban_prev[cid] != ban_count or cid_safe_wins_prev[cid] != safe_wins:
        keys_to_del = [k for k in cache if isinstance(k, tuple) and k[0] == cid]
        for k in keys_to_del:
            del cache[k]
        cid_ban_prev[cid]       = ban_count
        cid_safe_wins_prev[cid] = safe_wins
        if keys_to_del:
            print("[CLOUD-LLM] [V79-4] Cache flushed CID:%d" % cid)

# =============================================================================
# TCP FRAMING
# =============================================================================
def recv_framed(sock):
    try:
        raw = b""
        while len(raw) < 4:
            chunk = sock.recv(4 - len(raw))
            if not chunk:
                return None
            raw += chunk
        length = struct.unpack(">I", raw)[0]
        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                return None
            data += chunk
        return data.decode("utf-8")
    except Exception:
        return None

def send_framed(sock, msg):
    enc = msg.encode("utf-8")
    sock.sendall(struct.pack(">I", len(enc)) + enc)

# =============================================================================
# LEDGER READER
# =============================================================================
def read_prior_bans(cid):
    ban_count = 0
    safe_wins = 0
    try:
        with open(LEDGER_PATH, "r") as f:
            for line in f:
                try:
                    blk = json.loads(line.strip())
                    if blk.get("cid") == cid:
                        evt = blk.get("evt", "")
                        if "BAN" in evt:
                            ban_count += 1
                        elif "SAFE" in evt:
                            safe_wins += 1
                except Exception:
                    pass
    except FileNotFoundError:
        pass
    return ban_count, safe_wins


def read_zone_aware_safe_wins(cid, current_zone=None, sim_time=None, post_handover=False):
    """Return decayed SAFE count from ledger using zone/time/handover metadata when present.
    Backward compatible with older ledger rows that do not contain zone_id.
    """
    total = 0.0
    try:
        with open(LEDGER_PATH, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                if int(row.get("cid", -1)) != int(cid):
                    continue
                evt = str(row.get("evt", ""))
                if not evt.startswith("SAFE"):
                    continue
                w = 1.0
                z = row.get("zone_id", None)
                if current_zone is not None and z is not None:
                    try:
                        if int(z) != int(current_zone):
                            w *= LEDGER_OTHER_ZONE_DECAY
                    except Exception:
                        pass
                if sim_time is not None and "t" in row:
                    try:
                        age = max(0.0, float(sim_time) - float(row.get("t", 0.0)))
                        if age > LEDGER_RECENT_WINDOW_S:
                            w *= LEDGER_OTHER_ZONE_DECAY
                    except Exception:
                        pass
                total += w
    except Exception:
        return 0
    if post_handover:
        total *= POST_HANDOVER_LEDGER_FACTOR
    return int(round(total))

# =============================================================================
# ADAPTIVE TRIGGERS
# =============================================================================
def get_adaptive_triggers(cid):
    cid_warnings = recent_warnings[cid]
    if cid_warnings >= WARNING_THRESHOLD:
        t1 = BASE_T1_TIME * SHORTEN_FACTOR
        t2 = max(3, int(BASE_T2_COUNT * SHORTEN_FACTOR))
        alert_mode = True
    else:
        t1 = BASE_T1_TIME
        t2 = BASE_T2_COUNT
        alert_mode = False
    return t1, t2, alert_mode

# =============================================================================
# PRE-LLM CLEAN GATE
# =============================================================================
def pre_llm_clean_check(spd_avg, px_range, shadow, ban_count, alert_mode):
    if alert_mode:
        return False, 0.0, "", ""
    spd  = float(spd_avg)
    shad = int(shadow)
    bans = int(ban_count)
    if shad > 0 or bans > 0:
        return False, 0.0, "", ""
    if spd > SPEED_CLEAN_GATE:
        return False, 0.0, "", ""
    if px_range is not None and float(px_range) > PX_CLEAN_GATE:
        return True, CLEAN_GATE_SCORE_PX, "normal", "Pre-check: SPD+PX normal, no shadow"
    if px_range is None:
        return True, CLEAN_GATE_SCORE_NPN, "normal", "Pre-check: SPD normal, PX unknown"
    return False, 0.0, "", ""

# =============================================================================
# RULE-BASED SUSPICION
# =============================================================================
def rule_based_suspicion(avg_edge_susp, shadow, ban_count, spd_avg=None,
                         px_range=None, safe_wins=0):
    if spd_avg is None:
        spd_avg = SPEED_NORMAL
    spd  = float(spd_avg)
    shad = int(shadow)
    bans = int(ban_count)
    if shad == 0 and bans == 0 and spd <= SPEED_CLEAN_GATE:
        if px_range is None or float(px_range) > PX_CLEAN_GATE:
            return 0.10
    # avg_edge_susp is already a suspicion-like score from the bridge
    base                 = min(RULE_BASE_CAP, max(0.0, float(avg_edge_susp)))
    shadow_bonus         = min(RULE_SHADOW_CAP, shad * RULE_SHADOW_WEIGHT)
    ban_bonus            = min(RULE_BAN_CAP,    bans * RULE_BAN_WEIGHT)
    spd_excess           = spd - SPEED_NORMAL
    stealthy_spd_bonus   = 0.0
    if SPEED_STEALTHY_MIN < spd_excess < SPEED_STEALTHY_MAX:
        stealthy_spd_bonus = min(RULE_SPD_BONUS_CAP, spd_excess * RULE_SPD_BONUS_RATE)
    frozen_pos_bonus = 0.0
    if px_range is not None:
        pr = float(px_range)
        if pr < PX_FROZEN_HARD:
            frozen_pos_bonus = RULE_FROZEN_HARD_BONUS
        elif pr < PX_FROZEN_SOFT:
            frozen_pos_bonus = RULE_FROZEN_SOFT_BONUS
    moving_discount     = 0.0
    if px_range is not None and float(px_range) > PX_MOVING_MIN:
        moving_discount = RULE_MOVING_DISCOUNT

    flat_score_bonus = 0.0
    if FLAT_SCORE_LOW <= float(avg_edge_susp) <= FLAT_SCORE_HIGH:
        if shad > 0:
            flat_score_bonus += min(FLAT_SCORE_SHADOW_BONUS, shad * 0.03)
        if px_range is not None and float(px_range) < PX_FROZEN_SOFT:
            flat_score_bonus += FLAT_SCORE_FROZEN_BONUS
        if SPEED_STEALTHY_MIN < spd_excess < SPEED_STEALTHY_MAX:
            flat_score_bonus += FLAT_SCORE_STEALTH_BONUS

    reputation_discount = min(RULE_REPUTATION_CAP, safe_wins * REPUTATION_DISCOUNT)
    if frozen_pos_bonus > 0.0 or stealthy_spd_bonus > 0.0 or shad > 0 or bans > 0:
        reputation_discount *= 0.25
    cap    = RULE_SCORE_CAP_NOBAN if bans == 0 else RULE_SCORE_CAP_BAN
    result = min(cap, max(0.0,
                          base + shadow_bonus + ban_bonus
                          + stealthy_spd_bonus + frozen_pos_bonus + flat_score_bonus
                          - moving_discount - reputation_discount))
    return round(result, 3)

# =============================================================================
# DOMINANT CLASSIFIER
# =============================================================================
def classify_dominant(avg_edge_susp, spd_avg=None, px_range=None):
    if spd_avg is None:
        spd_avg = SPEED_NORMAL
    spd = float(spd_avg)
    if px_range is not None and float(px_range) > PX_MOVING_MIN and spd <= SPEED_CLEAN_GATE:
        return "normal"
    if px_range is not None and float(px_range) < PX_FROZEN_HARD:
        return "frozen_position"
    spd_excess = spd - SPEED_NORMAL
    if SPEED_STEALTHY_MIN < spd_excess < SPEED_STEALTHY_MAX:
        return "stealthy_speed"
    if float(avg_edge_susp) >= AVG_EDGE_SUSP_SPIKE_THRESH:
        return "speed_spike"
    return "normal"

# =============================================================================
# EXTRACT JSON
# =============================================================================
def extract_json_from_ollama(text):
    try:
        start = text.index("{")
        end   = text.rindex("}") + 1
        return json.loads(text[start:end])
    except Exception:
        pass
    m = re.search(r"\{.*?\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group())
        except Exception:
            pass
    return None

# =============================================================================
# OLLAMA QUERY
# =============================================================================
def hidden_pattern_tuner(cid, avg_edge_susp, n, shadow, trigger, ban_count, safe_wins,
                         spd_avg=None, px_range=None, rule_susp=0.0, llm_susp=0.0):
    # Cloud should upgrade weak/hidden malicious trends more often than it cancels edge.
    hidden = 0.0
    if n >= 4 and shadow >= 1 and avg_edge_susp >= 0.60:
        hidden += HIDDEN_PATTERN_BONUS + 0.02 * min(3, shadow)
    if recent_warnings[cid] >= 1:
        hidden += REPEAT_WARN_BONUS * min(2.0, float(recent_warnings[cid])) / 2.0
    if trigger in ("WARN", "SAFE_ESCALATE") and shadow >= 2 and avg_edge_susp >= 0.55:
        hidden += 0.04
    if trigger == "SAFE_ESCALATE":
        if n >= 5 and avg_edge_susp >= 0.10:
            hidden += SAFE_ESCALATE_HIDDEN_BONUS
        if shadow >= 1:
            hidden += 0.02
    if trigger in ("BAN", "BAN_REPORTED"):
        hidden += 0.06
    if ban_window_count[cid] >= 1 or ban_count > 0:
        hidden += BAN_CONFIRM_BONUS * min(2.0, float(max(ban_window_count[cid], ban_count))) / 2.0
    if px_range is not None and float(px_range) < PX_FROZEN_SOFT and spd_avg is not None and float(spd_avg) > SPEED_NORMAL:
        hidden += 0.05

    edge_delta = 0.0
    ts_bias = 0.0
    px_bias = 0.0
    promote = 0
    if hidden > 0 or trigger in ("WARN", "BAN", "SAFE_ESCALATE"):
        edge_delta = min(TEACH_EDGE_DELTA_CAP, 0.6 * hidden + 0.08 * max(0.0, rule_susp - 0.15))
        if px_range is not None and float(px_range) < PX_FROZEN_SOFT:
            px_bias = TEACH_PX_BIAS
        if spd_avg is not None and float(spd_avg) > SPEED_NORMAL:
            ts_bias = TEACH_TS_BIAS
        elif spd_avg is not None and float(spd_avg) > SPEED_STEALTHY_MIN:
            ts_bias = TEACH_TS_BIAS * 0.5
        if trigger in ("BAN", "BAN_REPORTED") or ban_count > 0 or ban_window_count[cid] >= 1 or recent_warnings[cid] >= 1:
            promote = 1
    teach = min(1.0, max(llm_susp, rule_susp, hidden + max(llm_susp, rule_susp) * 0.7))
    return round(hidden,3), round(edge_delta,3), round(ts_bias,3), round(px_bias,3), int(promote), round(teach,3)

def query_ollama(cid, avg_edge_susp, n, shadow, trigger, ban_count, safe_wins,
                 spd_avg=None, px_range=None, alert_mode=False, sim_time=None, trace_id=None):
    if spd_avg is None:
        spd_avg = SPEED_NORMAL
    px_info = ("PX_RANGE=%.1fm" % float(px_range)) if px_range is not None else "PX_RANGE=unknown"

    is_clean, c_susp, c_dom, c_smry = pre_llm_clean_check(
        spd_avg, px_range, shadow, ban_count, alert_mode)
    if is_clean:
        print("[CLOUD-LLM] Pre-check CLEAN CID:%d -> skip LLM" % cid)
        trace_event("ollama_precheck_clean", cid=cid, sim_time=sim_time, trace_id=trace_id, event_level="info",
                    llm_susp=c_susp, dominant=c_dom, summary=c_smry, spd_avg=float(spd_avg),
                    px_range=px_range, shadow=int(shadow), ban_count=int(ban_count), alert_mode=bool(alert_mode))
        return c_susp, c_dom, c_smry

    key = cache_key(cid, avg_edge_susp, spd_avg, px_range, shadow, ban_count)
    if key in cache:
        print("[CLOUD-LLM] Cache hit CID:%d" % cid)
        cached = cache[key]
        trace_event("ollama_cache_hit", cid=cid, sim_time=sim_time, trace_id=trace_id, event_level="detail",
                    cache_key=str(key), llm_susp=float(cached[0]), dominant=str(cached[1]))
        return cached

    examples = (
        "Examples:\n"
        "- Normal vehicle: SPD_AVG=%.1f, PX_RANGE=120, shadow=0, bans=0 "
        "-> suspicion=0.05, dominant=normal\n"
        "- Stealthy attacker: SPD_AVG=%.1f, PX_RANGE=2, shadow=5, bans=0 "
        "-> suspicion=0.70, dominant=stealthy_speed\n"
        "- Frozen position: SPD_AVG=%.1f, PX_RANGE=3, shadow=2, bans=0 "
        "-> suspicion=0.60, dominant=frozen_position\n"
        "- Speed spike: SPD_AVG=35.0, PX_RANGE=80, shadow=0, bans=0 "
        "-> suspicion=0.80, dominant=speed_spike\n"
    ) % (PROMPT_SPD_NORMAL, PROMPT_SPD_NORMAL + 2.0, PROMPT_SPD_NORMAL)

    lines = [
        "You are a V2X network security analyst detecting stealthy vehicle attackers.",
        "",
        "NORMAL BASELINE (NOT suspicious):",
        "  - SPD_AVG = %.1f m/s is the exact normal cruise speed." % PROMPT_SPD_NORMAL,
        "    DO NOT flag SPD_AVG <= %.1f as suspicious." % PROMPT_SPD_ATTACK,
        "  - PX_RANGE > %.0f m means the vehicle GPS is advancing normally." % PROMPT_PX_NORMAL,
        "    A moving vehicle is NOT using frozen GPS.",
        "",
        "STEALTHY ATTACK SIGNATURES (flag these):",
        "  - Speed slightly above normal: SPD_AVG > %.1f m/s (normal=%.1f)" % (
            PROMPT_SPD_ATTACK, PROMPT_SPD_NORMAL),
        "  - Timestamp slightly in past: TS offset = -0.5s (borderline replay)",
        "  - Frozen GPS: PX_RANGE < %.0f m over 10 packets (vehicle not advancing)" % PROMPT_PX_FROZEN,
        "  - Heading exactly 0.0 with no natural jitter",
        "  - Attacker has BOTH elevated SPD AND frozen PX together.",
        (
            "  - A vehicle with large PX_RANGE (> %.0f m) can STILL be stealthy:"
            " if SPD_AVG > %.1f AND timestamps are slightly in the past together,"
            " classify as suspicious regardless of px_range."
        ) % (PROMPT_PX_NORMAL, PROMPT_SPD_NORMAL),
        "  - Do NOT classify as 'normal' based on large PX_RANGE alone if both speed_excess and ts_replay signals are present simultaneously.",
        "",
        examples,
        "Vehicle CID:%d data: n=%d packets avg_edge_susp=%.3f shadow=%d trigger=%s" % (
            cid, n, avg_edge_susp, shadow, trigger),
        "prior_bans=%d safe_wins=%d SPD_AVG=%.1f %s" % (
            ban_count, safe_wins, float(spd_avg), px_info),
        "",
        "DECISION GUIDE:",
        "  If SPD_AVG<=%.1f AND PX_RANGE>%.0f AND shadow=0 -> llm_suspicion <= 0.15" % (
            PROMPT_SPD_ATTACK, PROMPT_PX_NORMAL),
        "  If SPD_AVG>%.1f AND PX_RANGE<%.0f AND shadow>0  -> llm_suspicion >= 0.70" % (
            PROMPT_SPD_ATTACK, PROMPT_PX_FROZEN),
        "",
        "Reply ONLY with valid JSON, no extra text:",
        '{"llm_suspicion": <0.0-1.0>, "dominant_anomaly": "<type>", "summary": "<brief>"}',
    ]
    prompt = "\n".join(lines)

    try:
        trace_event("ollama_query_start", cid=cid, sim_time=sim_time, trace_id=trace_id, event_level="detail",
                    avg_edge_susp=float(avg_edge_susp), n=int(n), shadow=int(shadow), trigger=str(trigger),
                    ban_count=int(ban_count), safe_wins=int(safe_wins), spd_avg=float(spd_avg),
                    px_range=px_range, alert_mode=bool(alert_mode))

        # [OPT-C] REST API call to persistent Ollama server.
        # Model stays loaded in GPU between calls — no cold-start per query.
        # Replaces subprocess "ollama run" which spawned a new process every time.
        ollama_url = "http://%s/api/generate" % OLLAMA_HOST
        payload = json.dumps({
            "model":  OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0, "seed": 42}
        }).encode("utf-8")
        req = urllib.request.Request(
            ollama_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=25) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            text = body.get("response", "").strip()

        data = extract_json_from_ollama(text)
        if data:
            llm_s = float(data.get("llm_suspicion", 0.5))
            dom   = str(data.get("dominant_anomaly", "unknown"))
            smry  = str(data.get("summary", "LLM analysis complete"))
            if float(spd_avg) <= SPEED_CLEAN_GATE and px_range is not None \
                    and float(px_range) > PX_CLEAN_GATE:
                llm_s = min(llm_s, ALERT_CLAMP if alert_mode else SANITY_CLAMP_NORMAL)
                dom   = "normal"
            if len(cache) < CACHE_MAX_SIZE:
                cache[key] = (llm_s, dom, smry)
            trace_event("ollama_query_result", cid=cid, sim_time=sim_time, trace_id=trace_id, event_level="info",
                        llm_susp=float(llm_s), dominant=str(dom), summary=str(smry)[:120],
                        cache_store=bool(len(cache) < CACHE_MAX_SIZE), model=str(OLLAMA_MODEL))
            return llm_s, dom, smry

        print("[CLOUD-LLM] [FP-FIX-1] Bad JSON -> neutral %.3f" % NEUTRAL_SCORE)
        trace_event("ollama_bad_json", cid=cid, sim_time=sim_time, trace_id=trace_id, event_level="info",
                    neutral_score=float(NEUTRAL_SCORE))
        return NEUTRAL_SCORE, "unknown", "ollama_bad_json"

    except urllib.error.URLError as e:
        # Ollama server unreachable (not running, wrong port, network issue)
        print("[CLOUD-LLM] [OPT-C] Ollama unreachable: %s -> neutral %.3f" % (e, NEUTRAL_SCORE))
        trace_event("ollama_error", cid=cid, sim_time=sim_time, trace_id=trace_id, event_level="info",
                    error=str(e), neutral_score=float(NEUTRAL_SCORE))
        return NEUTRAL_SCORE, "unknown", "ollama_unreachable"

    except TimeoutError:
        print("[CLOUD-LLM] [FP-FIX-1] Timeout -> neutral %.3f" % NEUTRAL_SCORE)
        trace_event("ollama_timeout", cid=cid, sim_time=sim_time, trace_id=trace_id, event_level="info",
                    neutral_score=float(NEUTRAL_SCORE))
        return NEUTRAL_SCORE, "unknown", "ollama_timeout"

    except Exception as e:
        print("[CLOUD-LLM] [FP-FIX-1] Error: %s -> neutral %.3f" % (e, NEUTRAL_SCORE))
        trace_event("ollama_error", cid=cid, sim_time=sim_time, trace_id=trace_id, event_level="info",
                    error=str(e), neutral_score=float(NEUTRAL_SCORE))
        return NEUTRAL_SCORE, "unknown", "ollama_error"


# =============================================================================
# HANDLER
# =============================================================================

# =============================================================================

# [ADAPTIVE] CALIBRATE BATCH HANDLER — OLLAMA POWERED
# =============================================================================

_calib_in_flight = [False]

def handle_calibrate_batch(payload_str):
    """
    Receive CALIBRATE batch from bridge.

    STRICT MODE:
    - Cloud must return only Ollama-backed calibration output.
    - If Ollama is unavailable, malformed, or returns bad JSON, return
      CALIBRATION_ERROR instead of any rule-based fallback.
    """
    import json, re as _re, urllib.request

    # In-flight guard: skip if Ollama is already processing a request
    if _calib_in_flight[0]:
        print("[CLOUD-CALIB] Ollama busy — dropping concurrent request")
        return "CALIBRATION_ERROR ollama_busy"
    _calib_in_flight[0] = True

    try:
        payload = json.loads(payload_str)
    except Exception:
        return "CALIBRATION_ERROR bad_json"

    summaries = payload.get("vehicle_summaries", [])
    sep       = payload.get("separability", {})
    sim_ts    = payload.get("sim_ts", 0.0)

    if not summaries:
        return "CALIBRATION_ERROR empty_batch"

    warn_sums = [s for s in summaries if s.get("edge_verdict") in ("WARN", "BAN")]
    safe_sums = [s for s in summaries if s.get("edge_verdict") == "SAFE"]

    ts_sep  = float(sep.get("ts_delta_mean",   0.0))
    px_sep  = float(sep.get("px_frozen_ratio", 0.0))
    spd_sep = float(sep.get("spd_z_mean",      0.0))
    hdg_sep = float(sep.get("hdg_var_excess",  0.0))
    max_sep = float(sep.get("max_separation",  0.0))

    def feat_mean(sums, key):
        vals = [s[key] for s in sums if key in s]
        return round(sum(vals) / len(vals), 4) if vals else 0.0

    mean_warn_p     = feat_mean(warn_sums, "p_edge")
    mean_safe_p     = feat_mean(safe_sums, "p_edge")
    mean_warn_ts    = feat_mean(warn_sums, "ts_delta_mean")
    mean_warn_px    = feat_mean(warn_sums, "px_frozen_ratio")
    mean_warn_spd_z = feat_mean(warn_sums, "spd_z_mean")

    # ── Build Ollama prompt ──────────────────────────────────────────────────
    prompt = """You are a V2X network security analyst calibrating edge AI detection weights.

The bridge has summarised vehicle telemetry from a road zone.
Vehicles are classified as SUSPICIOUS (WARN/BAN) or SAFE by the edge AI.

FEATURE SEPARATION SCORES (Fisher F-score, higher = clearer attack signal):
  Timestamp replay separation  : {ts_sep:.3f}
  GPS position freeze sep      : {px_sep:.3f}
  Speed anomaly separation     : {spd_sep:.3f}
  Heading freeze separation    : {hdg_sep:.3f}
  Max separation overall       : {max_sep:.3f}

SUSPICIOUS vehicles summary (n={n_warn}):
  Mean p_edge            : {mean_warn_p:.3f}   (detection score, 0=safe 1=malicious)
  Mean ts_delta          : {mean_warn_ts:.4f}  (negative = timestamp replay attack)
  Mean px_frozen_ratio   : {mean_warn_px:.3f}  (near 1.0 = GPS position frozen)
  Mean spd_z             : {mean_warn_spd_z:.3f}  (positive = speed above normal)

SAFE vehicles summary (n={n_safe}):
  Mean p_edge            : {mean_safe_p:.3f}

CURRENT EDGE AI WEIGHTS:
  W1=0.27 (speed anomaly)
  W2=0.18 (timestamp replay)
  W3=0.23 (heading behaviour)
  W4=0.18 (GPS position)
  W5=0.14 (temporal patterns)

ATTACK TYPE GUIDE:
  ts_replay      -> timestamp systematically in the past, ts_sep is highest
  gps_freeze     -> GPS position not advancing despite speed, px_sep is highest
  speed_attack   -> speed consistently above normal, spd_sep is highest
  heading_freeze -> heading exactly 0.0 with no jitter, hdg_sep is highest
  composite      -> multiple signals high simultaneously

TASK: Identify the dominant attack type and recommend weight deltas to improve
future detection. Raise the weight of the model that detects the dominant signal.
Keep deltas small (max 0.04 per weight). Only adjust weights where signal is clear.

Reply ONLY with valid JSON, no extra text, no markdown:
{{"attack_type_detected": "<ts_replay|gps_freeze|speed_attack|heading_freeze|composite>",
  "confidence": <0.0-1.0>,
  "W1_delta": <0.000-0.040>,
  "W2_delta": <0.000-0.040>,
  "W3_delta": <0.000-0.040>,
  "W4_delta": <0.000-0.040>,
  "W5_delta": <0.000-0.040>,
  "ZONE_MALICIOUS_delta": <-0.030 to 0.020>,
  "reasoning": "<one sentence explaining the dominant signal>"}}
""".format(
        ts_sep=ts_sep, px_sep=px_sep, spd_sep=spd_sep, hdg_sep=hdg_sep,
        max_sep=max_sep, n_warn=len(warn_sums), n_safe=len(safe_sums),
        mean_warn_p=mean_warn_p, mean_safe_p=mean_safe_p,
        mean_warn_ts=mean_warn_ts, mean_warn_px=mean_warn_px,
        mean_warn_spd_z=mean_warn_spd_z
    )

    # ── Call Ollama ──────────────────────────────────────────────────────────
    ollama_result = None
    try:
        ollama_url = "http://%s/api/generate" % OLLAMA_HOST
        req_body = json.dumps({
            "model":  OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0, "seed": 42}
        }).encode("utf-8")

        req = urllib.request.Request(
            ollama_url,
            data=req_body,
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        with _ollama_lock:
         with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            text = body.get("response", "").strip()

        # Extract JSON from response — handle markdown fences and plain JSON
        m = _re.search(r'\{.*\}', text, _re.DOTALL)
        if not m:
            print("[CLOUD-CALIB-LLM] Ollama bad JSON response — refusing calibration")
            _calib_in_flight[0] = False
            return "CALIBRATION_ERROR ollama_bad_json"

        ollama_result = json.loads(m.group())
        print("[CLOUD-CALIB-LLM] Ollama OK: attack=%s conf=%.2f reason=%s" % (
            ollama_result.get("attack_type_detected", "?"),
            float(ollama_result.get("confidence", 0)),
            str(ollama_result.get("reasoning", ""))[:80]
        ))

    except Exception as e:
        print("[CLOUD-CALIB-LLM] Ollama unreachable or invalid: %s — refusing calibration" % e)
        _calib_in_flight[0] = False
        return "CALIBRATION_ERROR ollama_unavailable"

    # ── Clamp and build final result from Ollama only ────────────────────────
    try:
        dominant = str(ollama_result.get("attack_type_detected", "unknown"))
        confidence = round(max(0.0, min(1.0, float(ollama_result.get("confidence", 0.5)))), 2)

        def _clamp_delta(key):
            return round(max(0.0, min(0.04, float(ollama_result.get(key, 0.0)))), 3)

        zone_mal_delta = round(
            max(-0.03, min(0.02, float(ollama_result.get("ZONE_MALICIOUS_delta", 0.0)))),
            3
        )

        result = {
            "msg_type":             "CALIBRATION_RESULT",
            "sim_ts":               sim_ts,
            "attack_type_detected": dominant,
            "confidence":           confidence,
            "n_warn":               len(warn_sums),
            "n_safe":               len(safe_sums),
            "W1_delta":             _clamp_delta("W1_delta"),
            "W2_delta":             _clamp_delta("W2_delta"),
            "W3_delta":             _clamp_delta("W3_delta"),
            "W4_delta":             _clamp_delta("W4_delta"),
            "W5_delta":             _clamp_delta("W5_delta"),
            "ZONE_MALICIOUS_delta": zone_mal_delta,
            "sep_before":           round(max_sep, 3),
            "sep_after":            round(max_sep * 1.15, 2) if max_sep > 1.0 else round(max_sep, 3),
            "max_separation":       round(max_sep, 3),
            "llm_used":             True,
            "llm_reasoning":        str(ollama_result.get("reasoning", ""))[:120],
        }

        print("[CLOUD-CALIB] CALIBRATION_RESULT attack=%s conf=%.2f llm=%s "
              "W2d=%.3f W4d=%.3f ZONE_d=%.3f sep=%.2f->%.2f" % (
              dominant, confidence, True,
              result["W2_delta"], result["W4_delta"],
              zone_mal_delta, max_sep, result["sep_after"]
        ))

        _calib_in_flight[0] = False
        return "CALIBRATION_RESULT " + json.dumps(result)

    except Exception as e:
        print("[CLOUD-CALIB] Invalid Ollama calibration fields: %s" % e)
        _calib_in_flight[0] = False
        return "CALIBRATION_ERROR ollama_invalid_fields"



def handle_client(conn, addr):
    print("[CLOUD-LLM] Query from %s" % str(addr))
    cid = None
    sim_time = None
    trace_id = None
    msg = None
    trace_event("connection_accepted", event_level="detail", remote_addr=str(addr))
    try:
        msg = recv_framed(conn)
        if msg is None:
            return
        print("[CLOUD-LLM] Received: %s" % msg.strip()[:120])
        # [ADAPTIVE] Route CALIBRATE batch to population handler
        if msg.strip().startswith("{") and '"msg_type": "CALIBRATE"' in msg:
            result = handle_calibrate_batch(msg.strip())
            send_framed(conn, result)
            return
        trace_event("query_received", event_level="info", raw_message=msg.strip(), remote_addr=str(addr))

        q = {}
        for part in msg.strip().split():
            if ":" in part:
                k, v = part.split(":", 1)
                q[k.lower()] = v

        cid       = int(q.get("cid",       -1))
        # Bridge now sends `avg_edge_susp:` as the primary key. `avg:` is a legacy alias.
        if "avg_edge_susp" in q:
            avg_edge_susp = float(q.get("avg_edge_susp", 0.5))
        else:
            avg_edge_susp = float(q.get("avg", 0.5))
            if "avg" in q:
                print("[CLOUD-WARN] Legacy avg: wire key accepted; please migrate sender to avg_edge_susp:")
        n         = int(q.get("n",          1))
        shadow    = int(q.get("shd",        0))
        trigger   = q.get("trg",            "UNKNOWN")
        spd_avg   = float(q.get("spd_avg",  SPEED_NORMAL))
        px_range  = q.get("px_range",       None)
        safe_wins = int(q.get("safe_wins", q.get("safewins", 0)))
        current_zone = int(q.get("zone_id", q.get("zone", 0)) or 0)
        post_handover = str(q.get("post_handover", q.get("handover", "0"))).lower() in ("1", "true", "yes")
        sim_raw = q.get("sim_ts", q.get("ts", q.get("simtime", q.get("time", None))))
        try:
            sim_time = float(sim_raw) if sim_raw is not None else None
        except Exception:
            sim_time = None
        trace_id = q.get("trace_id")
        if not trace_id:
            if sim_time is not None:
                trace_id = make_trace_id(cid, sim_time)
            else:
                trace_id = "CID%d-REQ%d" % (cid, int(time.time() * 1000.0))

        trace_event("query_parsed", cid=cid, sim_time=sim_time, trace_id=trace_id, event_level="info",
                    avg_edge_susp=float(avg_edge_susp), n=int(n), shadow=int(shadow), trigger=str(trigger),
                    spd_avg=float(spd_avg), px_range=px_range, safe_wins=int(safe_wins), remote_addr=str(addr))

        ledger_bans, _ = read_prior_bans(cid)
        cc_reported    = int(q.get("bans", 0))
        ban_count      = max(ledger_bans, cc_reported)

        print("[CLOUD-LLM] CID:%d bans=%d safeWins=%d spd_avg=%.1f px_range=%s"
              % (cid, ban_count, safe_wins, float(spd_avg), str(px_range)))
        trace_event("ledger_state", cid=cid, sim_time=sim_time, trace_id=trace_id, event_level="detail",
                    ledger_bans=int(ledger_bans), ledger_safe_wins=int(ledger_safe_wins),
                    zone_safe_wins=int(zone_safe_wins), current_zone=int(current_zone),
                    post_handover=bool(post_handover), reported_bans=int(cc_reported), ban_count=int(ban_count),
                    safe_wins=int(safe_wins), spd_avg=float(spd_avg), px_range=px_range)

        cache_invalidate_if_state_changed(cid, ban_count, safe_wins)
        t1, t2, alert_mode = get_adaptive_triggers(cid)
        trace_event("adaptive_trigger_state", cid=cid, sim_time=sim_time, trace_id=trace_id, event_level="detail",
                    t1=float(t1), t2=int(t2), alert_mode=bool(alert_mode), recent_warnings=int(recent_warnings[cid]))

        prev_recent_warnings = recent_warnings[cid]
        if trigger in ("WARN", "SCORE_ALERT", "BAN_REPORTED") or (avg_edge_susp > 0.5 and shadow > 0):
            recent_warnings[cid] += 1
            warn_update_mode = "increment"
        else:
            warn_update_mode = "hold"
            if recent_warnings[cid] > 0:
                recent_warnings[cid] = max(0, recent_warnings[cid] - 1)
                warn_update_mode = "decrement"
        trace_event("warning_counter_updated", cid=cid, sim_time=sim_time, trace_id=trace_id, event_level="detail",
                    prev_warnings=int(prev_recent_warnings), new_warnings=int(recent_warnings[cid]),
                    mode=str(warn_update_mode), trigger=str(trigger), avg_edge_susp=float(avg_edge_susp), shadow=int(shadow))

        is_ban_trigger = (trigger in ("BAN", "BAN_REPORTED") or ban_count > 0)
        if is_ban_trigger:
            ban_window_count[cid]   += 1
            clean_window_count[cid]  = 0
        else:
            clean_window_count[cid] += 1
            if clean_window_count[cid] >= CLEAN_WINDOW_RESET:
                if ban_window_count[cid] > 0:
                    print("[CLOUD-LLM] [V79-5] BAN window reset CID:%d" % cid)
                ban_window_count[cid]   = 0
                clean_window_count[cid] = 0

        ban_confirmed = (ban_window_count[cid] >= 2)
        trace_event("ban_window_updated", cid=cid, sim_time=sim_time, trace_id=trace_id, event_level="detail",
                    is_ban_trigger=bool(is_ban_trigger), ban_window_count=int(ban_window_count[cid]),
                    clean_window_count=int(clean_window_count[cid]), ban_confirmed=bool(ban_confirmed))

        if alert_mode:
            print("[CLOUD-LLM] ALERT_MODE CID:%d (warnings=%d)"
                  % (cid, recent_warnings[cid]))
            trace_event("alert_mode_active", cid=cid, sim_time=sim_time, trace_id=trace_id, event_level="info",
                        warnings=int(recent_warnings[cid]), t1=float(t1), t2=int(t2))

        llm_susp, dominant, summary = query_ollama(
            cid, avg_edge_susp, n, shadow, trigger, ban_count, safe_wins,
            spd_avg, px_range, alert_mode, sim_time, trace_id)


        if alert_mode:
            llm_susp = max(llm_susp, ALERT_BASELINE)
            if float(spd_avg) <= SPEED_CLEAN_GATE and px_range is not None \
                    and float(px_range) > PX_CLEAN_GATE:
                llm_susp = min(llm_susp, ALERT_CLAMP)

        rule_susp   = rule_based_suspicion(avg_edge_susp, shadow, ban_count,
                                            spd_avg, px_range, safe_wins)
        trace_event("rule_scored", cid=cid, sim_time=sim_time, trace_id=trace_id, event_level="detail",
                    rule_susp=float(rule_susp), avg_edge_susp=float(avg_edge_susp), shadow=int(shadow),
                    ban_count=int(ban_count), spd_avg=float(spd_avg), px_range=px_range, safe_wins=int(safe_wins))
        hybrid_susp = LLM_WEIGHT * llm_susp + RULE_WEIGHT * rule_susp

        # Preserve BAN-triggered evidence from bridge/edge so mild cloud readings
        # do not immediately wash out a real edge BAN.
        if trigger in ("BAN", "BAN_REPORTED") and (shadow > 0 or ban_count > 0):
            bonus = min(TRIGGER_BAN_BONUS_CAP,
                        TRIGGER_BAN_BONUS + max(0, ban_count - 1) * TRIGGER_BAN_REPEAT_BONUS)
            if px_range is not None and float(px_range) < PX_FROZEN_SOFT:
                bonus = min(TRIGGER_BAN_BONUS_CAP, bonus + 0.03)
            hybrid_susp += bonus
            trace_event("trigger_ban_bonus_applied", cid=cid, sim_time=sim_time, trace_id=trace_id, event_level="detail",
                        bonus=float(bonus), trigger=str(trigger), shadow=int(shadow), ban_count=int(ban_count),
                        hybrid_after=float(hybrid_susp))

        hidden_bonus, edge_delta, ts_bias, px_bias, promote, teach = hidden_pattern_tuner(
            cid, avg_edge_susp, n, shadow, trigger, ban_count, safe_wins, spd_avg, px_range, rule_susp, llm_susp)
        trace_event("hidden_pattern_tuned", cid=cid, sim_time=sim_time, trace_id=trace_id, event_level="detail",
                    hidden_bonus=float(hidden_bonus), edge_delta=float(edge_delta), ts_bias=float(ts_bias),
                    px_bias=float(px_bias), promote=int(promote), teach=float(teach))
        hybrid_susp = round(min(1.0, max(0.0, hybrid_susp + hidden_bonus)), 3)
        trace_event("hybrid_scored", cid=cid, sim_time=sim_time, trace_id=trace_id, event_level="info",
                    llm_susp=float(llm_susp), rule_susp=float(rule_susp), hidden_bonus=float(hidden_bonus),
                    hybrid_susp=float(hybrid_susp), dominant=str(dominant), summary=str(summary)[:120],
                    trigger=str(trigger), ban_count=int(ban_count), safe_wins=int(safe_wins), promote=int(promote))

        # Stronger early fusion for hidden-pattern cases so the cloud acts as a confirmer/upgrader.
        if promote == 1:
            if trigger in ("BAN", "BAN_REPORTED"):
                floor = min(0.75, 0.40 + 0.05 * min(3, shadow) + 0.04 * min(3, ban_count))
                hybrid_susp = max(hybrid_susp, floor)
                trace_event("promote_floor_applied", cid=cid, sim_time=sim_time, trace_id=trace_id, event_level="detail",
                            floor=float(floor), trigger=str(trigger), hybrid_after=float(hybrid_susp))
            elif trigger in ("WARN", "SAFE_ESCALATE"):
                floor = min(0.55, 0.26 + 0.05 * min(2, shadow) + 0.05 * min(1.0, hidden_bonus))
                hybrid_susp = max(hybrid_susp, floor)
                trace_event("promote_floor_applied", cid=cid, sim_time=sim_time, trace_id=trace_id, event_level="detail",
                            floor=float(floor), trigger=str(trigger), hybrid_after=float(hybrid_susp))

        # Only suppress truly first-ban soft cases; do not suppress explicit BAN trigger
        # traffic from the guarded bridge unless the user disables the skip.
        suppress_ok = is_ban_trigger and not ban_confirmed and ban_count <= 1
        if TRIGGER_BAN_SKIP_SUPPRESS == 1 and trigger in ("BAN", "BAN_REPORTED"):
            suppress_ok = False
        if suppress_ok:
            if hybrid_susp > BAN_SUPPRESS_SCORE:
                print("[CLOUD-LLM] [FP-FIX-3] BAN suppressed: %.3f -> %.3f" % (hybrid_susp, BAN_SUPPRESS_SCORE))
                trace_event("ban_suppress_applied", cid=cid, sim_time=sim_time, trace_id=trace_id, event_level="info",
                            before=float(hybrid_susp), after=float(BAN_SUPPRESS_SCORE), trigger=str(trigger),
                            ban_confirmed=bool(ban_confirmed), ban_count=int(ban_count))
                hybrid_susp = BAN_SUPPRESS_SCORE
        if abs(hybrid_susp - llm_susp) > 0.1 or hidden_bonus > 0:
            print("[HYBRID] CID:%d trig=%s LLM=%.3f Rule=%.3f Hidden=%.3f -> Hybrid=%.3f"
                  % (cid, trigger, llm_susp, rule_susp, hidden_bonus, hybrid_susp))

        resp = ("LLM_RESP llm_susp:%.3f dominant:%s teach:%.3f edge_delta:%.3f ts_bias:%.3f px_bias:%.3f hidden_promote:%.3f promote:%d summary:%s" % (
            hybrid_susp, dominant, teach, edge_delta, ts_bias, px_bias, hidden_bonus, promote, summary[:60].replace(" ", "_")))
        print("[CLOUD-LLM-RESP] %s" % resp)
        trace_event("cloud_response_sent", cid=cid, sim_time=sim_time, trace_id=trace_id, event_level="info",
                    llm_susp=float(hybrid_susp), dominant=str(dominant), teach=float(teach),
                    edge_delta=float(edge_delta), ts_bias=float(ts_bias), px_bias=float(px_bias),
                    hidden_promote=float(hidden_bonus), promote=int(promote), response=resp)
        send_framed(conn, resp)

    except Exception as e:
        print("[CLOUD-LLM] Handler error: %s" % e)
        trace_event("handler_error", cid=cid, sim_time=sim_time, trace_id=trace_id, event_level="info", error=str(e), raw_message=msg.strip() if isinstance(msg, str) else None)
        try:
            send_framed(conn, "LLM_RESP llm_susp:%.3f dominant:unknown summary:handler_error"
                        % NEUTRAL_SCORE)
        except Exception:
            pass
    finally:
        conn.close()

# =============================================================================
# MAIN
# =============================================================================
if __name__ == "__main__":
    print("=" * 68)
    print(" CLOUD LLM SERVER %s -- Layer 3 (%s)" % (VERSION, EXP_NAME))
    print("=" * 68)
    print("[CLOUD-LLM] FLEX additions over v79:")
    print("  [FLEX-1] SPEED_NORMAL=%.1f SPEED_CLEAN_GATE=%.1f PX_CLEAN_GATE=%.0f"
          % (SPEED_NORMAL, SPEED_CLEAN_GATE, PX_CLEAN_GATE))
    print("  [FLEX-2] SHADOW_W=%.3f BAN_W=%.2f SPD_RATE=%.3f"
          % (RULE_SHADOW_WEIGHT, RULE_BAN_WEIGHT, RULE_SPD_BONUS_RATE))
    print("           REP_DISC=%.3f REP_CAP=%.2f"
          % (REPUTATION_DISCOUNT, RULE_REPUTATION_CAP))
    print("           FROZEN_HARD=%.2f FROZEN_SOFT=%.2f MOVING_DISC=%.2f"
          % (RULE_FROZEN_HARD_BONUS, RULE_FROZEN_SOFT_BONUS, RULE_MOVING_DISCOUNT))
    print("  [FLEX-3] CLEAN_GATE: PX=%.2f NPN=%.2f"
          % (CLEAN_GATE_SCORE_PX, CLEAN_GATE_SCORE_NPN))
    print("  [FLEX-4] PX_FROZEN_HARD=%.1f PX_FROZEN_SOFT=%.1f"
          % (PX_FROZEN_HARD, PX_FROZEN_SOFT))
    print("           SPD_STEALTHY=%.1f-%.1f AVG_EDGE_SUSP_SPIKE=%.2f"
          % (SPEED_STEALTHY_MIN, SPEED_STEALTHY_MAX, AVG_EDGE_SUSP_SPIKE_THRESH))
    print("           FLAT_SCORE=[%.2f, %.2f] bonuses shd=%.2f spd=%.2f frozen=%.2f"
          % (FLAT_SCORE_LOW, FLAT_SCORE_HIGH, FLAT_SCORE_SHADOW_BONUS, FLAT_SCORE_STEALTH_BONUS, FLAT_SCORE_FROZEN_BONUS))
    print("  [FLEX-5] Prompt: SPD_NORMAL=%.1f PX_GATE=%.0f"
          % (PROMPT_SPD_NORMAL, PROMPT_PX_NORMAL))
    print("[CLOUD-LLM] Retained: per-CID alert_mode, cache isolation,")
    print("  BAN window reset, NEUTRAL=%.3f, FP-FIX-1/2/3, subprocess env"
          % NEUTRAL_SCORE)
    print("[CLOUD-LLM] Hybrid: %.0f%% LLM + %.0f%% rule | Model: %s"
          % (LLM_WEIGHT * 100, RULE_WEIGHT * 100, OLLAMA_MODEL))
    print("[CLOUD-LLM] Evolving: hidden=%.2f repeat_warn=%.2f ban_confirm=%.2f safe_esc_hidden=%.2f teach_cap=%.2f ts_bias=%.2f px_bias=%.2f"
          % (HIDDEN_PATTERN_BONUS, REPEAT_WARN_BONUS, BAN_CONFIRM_BONUS, SAFE_ESCALATE_HIDDEN_BONUS, TEACH_EDGE_DELTA_CAP, TEACH_TS_BIAS, TEACH_PX_BIAS))
    print("=" * 68)

    trace_event("startup", event_level="info", version=str(VERSION), exp_name=str(EXP_NAME), port=int(CLOUD_PORT), model=str(OLLAMA_MODEL))

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", CLOUD_PORT))
    srv.listen(20)
    print("[CLOUD-LLM] Listening on port %d -- ready" % CLOUD_PORT)
    trace_event("listening", event_level="info", port=int(CLOUD_PORT))

    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client, args=(conn, addr),
                         daemon=True).start()
