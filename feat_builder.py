# feat_builder.py  minimal extractor for your 35-feature training (no feature list/mapping/freq map)

import os
import json
from typing import List, Iterable, Optional, Tuple
import numpy as np

# =========================
# Fixed feature schema (order matters)
# =========================
FEATURES: List[str] = [
    # numeric
    "duration","src_bytes","dst_bytes","src_pkts","dst_pkts","missed_bytes",
    "src_ip_bytes","dst_ip_bytes","http_request_body_len","http_response_body_len",
    "http_trans_depth","http_status_code",
    # ports
    "src_port","dst_port",
    # categoricals (strings; you will label-encode later)
    "proto","service","conn_state","http_method","http_user_agent",
    "http_resp_mime_types","http_orig_mime_types","ssl_version","ssl_cipher","weird_name",
    # DNS numeric codes/flags
    "dns_qtype","dns_qclass","dns_rcode","dns_RD","dns_RA","dns_AA","dns_rejected",
    # TLS/weird booleans
    "ssl_established","ssl_resumed","weird_notice",
    # (targets if present; not used as features)
    # "type","label"
]

# Categorical columns you label-encoded during training
CAT_COLS = [
    "proto","service","conn_state","http_method","http_user_agent",
    "http_resp_mime_types","http_orig_mime_types","ssl_version","ssl_cipher","weird_name"
]

# =========================
# Helpers
# =========================
def _norm_str(x) -> Optional[str]:
    if x is None:
        return None
    try:
        s = str(x).strip().lower()
        return s if s else None
    except Exception:
        return None

def _to_f32(x) -> np.float32:
    try:
        return np.float32(float(x))
    except Exception:
        return np.float32(0.0)

def _to_int(x, default=0) -> int:
    try:
        xi = int(float(x))
        return xi
    except Exception:
        return int(default)

def _to_bool01(x) -> int:
    # robustly convert various representations to 0/1
    if isinstance(x, (int, np.integer)):
        return 1 if x != 0 else 0
    if isinstance(x, bool):
        return 1 if x else 0
    sx = _norm_str(x)
    if sx in ("true","t","yes","y","1"): return 1
    if sx in ("false","f","no","n","0","none","na",""): return 0
    try:
        return 1 if float(x) != 0 else 0
    except Exception:
        return 0

# =========================
# Core extractor
# =========================


class FeatureVectorizer:
    """
    Build fixed-order rows with your 35 features, no one-hot / hashing.
    Categoricals are left as lowercased strings for downstream label-encoding.
    Booleans are emitted as 0/1 ints.
    """
        
    def __init__(self, encoders_path: str):
        """
        encoders_path: path to label_encoders.json produced during training.
        Mapping format: {column_name: {token: id, ...}, ...}
        Unknown tokens map to 0.
        """
        with open(encoders_path, "r") as f:
            self.encoders = json.load(f)

        # ensure all expected cat columns exist in mapping
        for c in CAT_COLS:
            if c not in self.encoders:
                self.encoders[c] = {}  # still map unknowns to 0

        # fixed feature order (your 35)
        self.features = [
            "duration","src_bytes","dst_bytes","src_pkts","dst_pkts","missed_bytes",
            "src_ip_bytes","dst_ip_bytes","http_request_body_len","http_response_body_len",
            "http_trans_depth","http_status_code",
            "src_port","dst_port",
            # categoricals (now encoded to int32)
            "proto","service","conn_state","http_method","http_user_agent",
            "http_resp_mime_types","http_orig_mime_types","ssl_version","ssl_cipher","weird_name",
            # DNS and flags
            "dns_qtype","dns_qclass","dns_rcode","dns_RD","dns_RA","dns_AA","dns_rejected",
            "ssl_established","ssl_resumed","weird_notice",
        ]

    def _enc(self, col: str, raw) -> int:
        """Label-encode a single categorical value with 0 for unknown."""
        tok = _norm_str(raw)
        if not tok:
            return 0
        return int(self.encoders.get(col, {}).get(tok, 0))

    def event_to_row(self, ev: dict) -> dict:
        """Return a numeric row dict matching training schema (no label/type)."""
        out = {}
        # numerics
        
        out["duration"]               = _to_f32(ev.get("duration", 0))
        out["src_bytes"]              = _to_f32(ev.get("orig_bytes", ev.get("src_bytes", 0)))
        out["dst_bytes"]              = _to_f32(ev.get("resp_bytes", ev.get("dst_bytes", 0)))
        out["src_pkts"]               = _to_f32(ev.get("orig_pkts", ev.get("src_pkts", 0)))
        out["dst_pkts"]               = _to_f32(ev.get("resp_pkts", ev.get("dst_pkts", 0)))
        out["missed_bytes"]           = _to_f32(ev.get("missed_bytes", 0))
        out["src_ip_bytes"]           = _to_f32(ev.get("orig_ip_bytes", ev.get("src_ip_bytes", 0)))
        out["dst_ip_bytes"]           = _to_f32(ev.get("resp_ip_bytes", ev.get("dst_ip_bytes", 0)))
        out["http_request_body_len"]  = _to_f32(ev.get("request_body_len", 0))
        out["http_response_body_len"] = _to_f32(ev.get("response_body_len", 0))
        out["http_trans_depth"]       = _to_f32(ev.get("trans_depth", 0))
        out["http_status_code"]       = _to_int(ev.get("status_code", 0))
        out["src_port"]               = _to_int(ev.get("id.orig_p") or ev.get("orig_p") or 0)
        out["dst_port"]               = _to_int(ev.get("id.resp_p") or ev.get("resp_p") or 0)

        # categoricals -> integer IDs (label-encoded)
        out["proto"]                  = self._enc("proto", ev.get("proto"))
        out["service"]                = self._enc("service", ev.get("service"))
        out["conn_state"]             = self._enc("conn_state", ev.get("conn_state"))
        out["http_method"]            = self._enc("http_method", ev.get("method"))
        out["http_user_agent"]        = self._enc("http_user_agent", ev.get("user_agent") or ev.get("user_agent_orig"))
        out["http_resp_mime_types"]   = self._enc("http_resp_mime_types", ev.get("resp_mime_types") or ev.get("mime_type"))
        out["http_orig_mime_types"]   = self._enc("http_orig_mime_types", ev.get("orig_mime_types") or ev.get("mime_type"))
        out["ssl_version"]            = self._enc("ssl_version", ev.get("version"))
        out["ssl_cipher"]             = self._enc("ssl_cipher", ev.get("cipher"))
        out["weird_name"]             = self._enc("weird_name", ev.get("name"))

        # DNS ints + boolean flags (0/1)
        out["dns_qtype"]              = _to_int(ev.get("qtype", 0))
        out["dns_qclass"]             = _to_int(ev.get("qclass", 0))
        out["dns_rcode"]              = _to_int(ev.get("rcode", 0))
        out["dns_RD"]                 = _to_bool01(ev.get("RD"))
        out["dns_RA"]                 = _to_bool01(ev.get("RA"))
        out["dns_AA"]                 = _to_bool01(ev.get("AA"))
        out["dns_rejected"]           = _to_bool01(ev.get("rejected"))
        out["ssl_established"]        = _to_bool01(ev.get("established"))
        out["ssl_resumed"]            = _to_bool01(ev.get("resumed"))
        out["weird_notice"]           = _to_bool01(ev.get("notice"))

        return out        
        

    def batch_events_to_rows(self, events: Iterable[dict]) -> List[dict]:
        return [self.event_to_row(ev) for ev in events]


# =========================
# Simple multi-log aggregator (uid or 5-tuple within window)
# =========================
from collections import deque

def _to_float_ts(ts):
    try: return float(ts)
    except Exception: return None

def _non_empty(x):
    return x is not None and x != "" and x != [] and x != {}

def _merge_values(a, b, key):
    # Sum counters; OR booleans; prefer non-empty otherwise
    counter_like = {"orig_bytes","resp_bytes","orig_pkts","resp_pkts","missed_bytes",
                    "src_bytes","dst_bytes","src_ip_bytes","dst_ip_bytes","src_pkts","dst_pkts"}
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a + b if key in counter_like else b
    if isinstance(a, bool) or isinstance(b, bool):
        return bool(a) or bool(b)
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
        seen=set(); out=[]
        for v in list(a)+list(b):
            if v not in seen:
                out.append(v); seen.add(v)
        return out
    return b if _non_empty(b) else a

def merge_event_dicts(base: dict, new: dict) -> dict:
    for k, v in new.items():
        if k == "ts": continue
        base[k] = v if k not in base else _merge_values(base[k], v, k)
    ts_new = _to_float_ts(new.get("ts"))
    if ts_new is not None:
        base["_last_ts"] = max(base.get("_last_ts", ts_new), ts_new)
    return base

def _make_flow_key(ev: dict, window_s: float):
    oh = ev.get("id.orig_h") or ev.get("orig_h")
    rh = ev.get("id.resp_h") or ev.get("resp_h")
    op = ev.get("id.orig_p") or ev.get("orig_p")
    rp = ev.get("id.resp_p") or ev.get("resp_p")
    pr = ev.get("proto")
    ts = _to_float_ts(ev.get("ts")) or 0.0
    bucket = int(ts / max(window_s, 0.5))
    return ("FLOW", oh, op, rh, rp, pr, bucket)

def _make_join_key(ev: dict, window_s: float):
    uid = ev.get("uid")
    return ("UID", uid) if _non_empty(uid) else _make_flow_key(ev, window_s)

def aggregate_logs_to_events(paths, window_s: float = 2.0, max_cache: int = 50000):
    cache = {}
    order = deque()
    high_water_ts = 0.0

    def _flush_ready(cutoff_ts):
        # flush entries older than cutoff_ts
        while order:
            k = order[0]
            ev = cache.get(k)
            if ev is None:
                order.popleft(); continue
            last_ts = ev.get("_last_ts", 0.0)
            if last_ts is None or last_ts > cutoff_ts:
                break
            order.popleft()
            ev_out = dict(ev); ev_out.pop("_last_ts", None)
            cache.pop(k, None)
            yield ev_out
        # bound cache size
        while len(cache) > max_cache and order:
            k = order.popleft()
            ev = cache.pop(k, None)
            if ev:
                ev_out = dict(ev); ev_out.pop("_last_ts", None)
                yield ev_out

    for p in paths:
        p = os.path.expanduser(p)
        if not os.path.exists(p):
            continue
        with open(p, "r") as f:
            for line in f:
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                ts = _to_float_ts(ev.get("ts"))
                if ts is not None:
                    high_water_ts = max(high_water_ts, ts)
                key = _make_join_key(ev, window_s)
                if key not in cache:
                    cache[key] = {}
                    order.append(key)
                merge_event_dicts(cache[key], ev)

                cutoff = high_water_ts - window_s
                for flushed in _flush_ready(cutoff):
                    yield flushed

    # flush remaining
    while order:
        k = order.popleft()
        ev = cache.pop(k, None)
        if ev:
            ev_out = dict(ev); ev_out.pop("_last_ts", None)
            yield ev_out


# =========================
# CLI: preview and CSV dump
# =========================

if __name__ == "__main__":
    import argparse, csv, os

    ap = argparse.ArgumentParser(description="Pi: build numeric rows using label_encoders.json")
    ap.add_argument("--encoders", required=True, help="Path to label_encoders.json from training")
    ap.add_argument("--logs", nargs="+", required=True, help="Paths to Zeek JSONL logs")
    ap.add_argument("--out-csv", required=True, help="Output CSV path with numeric features")
    ap.add_argument("--n", type=int, default=0, help="Preview first N rows to console")
    ap.add_argument("--n-total", type=int, default=0, help="Stop after this many rows (0 = all)")
    args = ap.parse_args()

    fv = FeatureVectorizer(args.encoders)
    out_dir = os.path.dirname(args.out_csv)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    # Write header once
    with open(args.out_csv, "w", newline="") as f:
        csv.writer(f, lineterminator="\n").writerow(fv.features)

    count = 0
    stop_after = int(args.n_total) if args.n_total and args.n_total > 0 else None

    for p in args.logs:
        with open(os.path.expanduser(p), "r") as f:
            for line in f:
                try:
                    ev = json.loads(line)
                except Exception:
                    continue

                row = fv.event_to_row(ev)
                vals = [row[col] for col in fv.features]

                with open(args.out_csv, "a", newline="") as fa:
                    csv.writer(fa, lineterminator="\n").writerow(vals)

                # console preview
                if args.n and count < args.n:
                    print(f"--- row {count} ---")
                    for k in fv.features:
                        print(f"{k}: {row[k]}")

                count += 1
                if stop_after is not None and count >= stop_after:
                    break
        if stop_after is not None and count >= stop_after:
            break

    shown = min(count, args.n) if args.n else 0
    print(f"Done. Wrote {count} rows to {args.out_csv}. Previewed {shown} rows.")
