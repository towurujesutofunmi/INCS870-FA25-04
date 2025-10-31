#!/usr/bin/env python3
# realtime_inference.py  Raspberry Pi realtime IDS inference from Zeek JSONL

import os
import sys
import time
import json
import signal
import argparse
from pathlib import Path
from typing import List, Dict, Iterable, Optional
from collections import defaultdict
import numpy as np
import pandas as pd
import xgboost as xgb
import csv

# psutil is optionalonly used when --perf is on
try:
    import psutil
except ImportError:
    psutil = None


# Import your vectorizer (uses label_encoders.json + fixed 35 features)
from feat_builder import FeatureVectorizer

# --- Debug helpers (add this near the top) ---
DEBUG = False  # will be set from --debug in main()

def _dbg(*args, **kwargs):
    """Safe debug print that won't crash if DEBUG isn't set yet."""
    if DEBUG:
        print(*args, **kwargs)


# --- Class mapping you used in training ---
IDX2CLASS = {
    0: "mitm",
    1: "ransomware",
    2: "injection",
    3: "backdoor",
    4: "normal",
    5: "password",
    6: "xss",
    7: "dos",
    8: "ddos",
    9: "scanning",
}

# -----------------------
# Tail helpers
# -----------------------

# -----------------------
# Non-blocking tail (multi-file)
# -----------------------


def open_tail(path, follow: bool):
    """Open a file for tailing and return (file_handle, inode)."""
    p = os.path.expanduser(path)
    f = open(p, "r", encoding="utf-8", errors="replace")
    f.seek(0, os.SEEK_END if follow else os.SEEK_SET)
    st = os.fstat(f.fileno())
    return f, st.st_ino

def tail_step(state, path, follow: bool):
    """
    One non-blocking read step. Returns (event_or_None, new_state).
    Reopens the file if it rotated.
    """
    f, inode = state
    p = os.path.expanduser(path)

    # handle rotation / missing file
    try:
        st = os.stat(p)
        if st.st_ino != inode:
            try:
                f.close()
            except Exception:
                pass
            f, inode = open_tail(p, follow)
    except FileNotFoundError:
        time.sleep(0.05)
        return None, (f, inode)

    pos = f.tell()
    line = f.readline()
    if not line:
        f.seek(pos)  # stay at EOF; don't advance
        return None, (f, inode)

    # NEW: ignore pure whitespace lines so json.loads doesn't crash
    s = line.strip()
    if not s:
        return None, (f, inode)

    try:
        ev = json.loads(s)
        if isinstance(ev, dict):
            ev["_src"] = p  # <--- add this
    except Exception as e:
        _dbg(f"[DEBUG json-fail] file={p} err={e} line={line[:200]!r}")
        ev = None

    return ev, (f, inode)


def multiplex_logs(paths, follow: bool = True, poll_sleep: float = 0.05):
    """
    Non-blocking multiplexer across many files: never blocks on a quiet file.
    Yields events as they appear.
    """
    paths = [os.path.expanduser(p) for p in paths]
    states = []
    for p in paths:
        try:
            states.append(open_tail(p, follow))
        except FileNotFoundError:
            states.append((None, None))  # will retry open later

    while True:
        any_event = False
        for i, p in enumerate(paths):
            if states[i][0] is None:
                try:
                    states[i] = open_tail(p, follow)
                except FileNotFoundError:
                    continue
            ev, states[i] = tail_step(states[i], p, follow)
            if ev is not None:
                any_event = True
                yield ev
        if not any_event:
            time.sleep(poll_sleep)
            if not follow:
                # batch mode: a quiet pass means EOF everywhere ? done
                break

# -----------------------
# Online UID/5-tuple aggregator (merge conn/http/ssl/dns events)
# -----------------------
from collections import deque

def _float_ts(x):
    try: return float(x)
    except: return None

def _non_empty(x):
    return x is not None and x != "" and x != [] and x != {}

def _merge_vals(a, b, key):
    counters = {"orig_bytes","resp_bytes","orig_pkts","resp_pkts","missed_bytes",
                "src_bytes","dst_bytes","src_ip_bytes","dst_ip_bytes","src_pkts","dst_pkts"}
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a + b if key in counters else b
    if isinstance(a, bool) or isinstance(b, bool):
        return bool(a) or bool(b)
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
        seen=set(); out=[]
        for v in list(a)+list(b):
            if v not in seen: out.append(v); seen.add(v)
        return out
    return b if _non_empty(b) else a

def _flow_key(ev, window_s: float):
    oh = ev.get("id.orig_h") or ev.get("orig_h")
    rh = ev.get("id.resp_h") or ev.get("resp_h")
    op = ev.get("id.orig_p") or ev.get("orig_p")
    rp = ev.get("id.resp_p") or ev.get("resp_p")
    pr = ev.get("proto")
    ts = _float_ts(ev.get("ts")) or 0.0
    bucket = int(ts / max(window_s, 0.5))
    return ("FLOW", oh, op, rh, rp, pr, bucket)

def _join_key(ev, window_s: float):
    uid = ev.get("uid")
    return ("UID", uid) if _non_empty(uid) else _flow_key(ev, window_s)

class OnlineMerger:
    def __init__(self, window_s: float = 120.0, max_cache: int = 50000):
        self.window_s = float(max(0.5, window_s))
        self.max_cache = max_cache
        self.cache = {}
        self.order = deque()
        self.high_water_ts = 0.0
    
    def _merge_into(self, base: dict, new: dict):
        for k, v in new.items():
            if k == "ts":
                # keep the earliest human-readable ts
                try:
                    tv = float(v)
                except Exception:
                    tv = None
                if tv is not None:
                    prev = base.get("ts")
                    try:
                        prevf = float(prev)
                    except Exception:
                        prevf = None
                    if prevf is None or tv < prevf:
                        base["ts"] = v
                continue
            
            if k == "_src":
                # defer handling to the dedicated block below
                continue
            base[k] = v if k not in base else _merge_vals(base[k], v, k)

        tsn = _float_ts(new.get("ts"))
        if tsn is not None:
            self.high_water_ts = max(self.high_water_ts, tsn)
            base["_last_ts"] = max(base.get("_last_ts", tsn), tsn)

        # keep contributing sources
        if "_src" in new:
            prev = base.get("_src")
            if isinstance(prev, set):
                prev.add(new["_src"])
                base["_src"] = prev
            elif isinstance(prev, str):
                base["_src"] = {prev, new["_src"]}
            else:
                base["_src"] = {new["_src"]}
                
        # >>> DEBUG: log when we have >=2 sources and the last_ts
        if getattr(self, "_DEBUG", False):
            src = base.get("_src")
            sc = len(src) if isinstance(src, set) else (1 if isinstance(src, str) else 0)
            if sc >= 2:
                print(f"[DEBUG merge-join] uid={base.get('uid','-')} "
                f"sources={sorted(src) if isinstance(src, set) else src} "
                f"ts_first={base.get('ts')} last_ts={base.get('_last_ts')}")
                
        # At the very end of _merge_into, after the _src handling:
        if getattr(self, "_DEBUG", False):
            cur = base.get("_src")
            sc = len(cur) if isinstance(cur, set) else (1 if isinstance(cur, str) else 0)
            print(f"[DEBUG src-state] uid={base.get('uid','-')} "
                  f"added_from={new.get('_src','-')} src_count={sc} src={sorted(cur) if isinstance(cur,set) else cur}")


    def flush_aged(self):
        """Flush only flows older than the current cutoff (aged/ready)."""
        cutoff = self.high_water_ts - self.window_s
        return self._flush_ready(cutoff)


        
    def _flush_ready(self, cutoff_ts: float):
        out = []
        # Keep single-source UID flows much longer so other logs can join
        uid_ttl = self.window_s * 10.0  # e.g., if window_s=30s, keep ~180s

        while self.order:
            k = self.order[0]
            ev = self.cache.get(k)
            if ev is None:
                self.order.popleft()
                continue

            last_ts = ev.get("_last_ts", 0.0)
            src = ev.get("_src")
            src_count = len(src) if isinstance(src, set) else (1 if isinstance(src, str) else 0)
            is_uid = isinstance(k, tuple) and k and k[0] == "UID"

            # Delay flushing single-source UID flows
            effective_cutoff = cutoff_ts
            if is_uid and src_count < 2:
                effective_cutoff = self.high_water_ts - uid_ttl
            # >>> DEBUG: show aging decision context
            try:
                uid_dbg = ev.get("uid", "-")
            except Exception:
                uid_dbg = "-"
            if getattr(self, "_DEBUG", False):
                print(f"[DEBUG flush-check] key={k} uid={uid_dbg} "
                      f"src_count={src_count} last_ts={last_ts} "
                      f"cutoff={effective_cutoff} high_water={self.high_water_ts}")
            
            if last_ts is None or last_ts > effective_cutoff:
                break  # this (and everything after it) is too fresh to flush

            # Ready to flush
            self.order.popleft()
            ev_out = dict(ev); ev_out.pop("_last_ts", None)
            self.cache.pop(k, None)
            out.append(ev_out)

        # Bound cache if we ever overflow
        while len(self.cache) > self.max_cache and self.order:
            k = self.order.popleft()
            ev = self.cache.pop(k, None)
            if ev:
                ev_out = dict(ev); ev_out.pop("_last_ts", None)
                out.append(ev_out)
        return out
    

    def add(self, ev: dict):
        ts = _float_ts(ev.get("ts"))
        if ts is not None:
            self.high_water_ts = max(self.high_water_ts, ts)
        key = _join_key(ev, self.window_s)
        
        # >>> DEBUG: print join key and ts
        if getattr(self, "_DEBUG", False):
            print(f"[DEBUG add] key={key} ev_ts={ts} high_water={self.high_water_ts}")

        if key not in self.cache:
            self.cache[key] = {}
            self.order.append(key)
        self._merge_into(self.cache[key], ev)
        cutoff = self.high_water_ts - self.window_s
        return self._flush_ready(cutoff)
        
        

    def flush_all(self):
        out = []
        while self.order:
            k = self.order.popleft()
            ev = self.cache.pop(k, None)
            if ev:
                ev_out = dict(ev); ev_out.pop("_last_ts", None)
                out.append(ev_out)
        return out


# -----------------------
# Drain-all tailer (reads backlog if from_start=True, then tails)
# -----------------------
def tail_and_merge_from_start_then_follow(paths, from_start: bool, merger, yield_interval=0.05):
    paths = [os.path.expanduser(p) for p in paths]
    files = []
    for p in paths:
        f = open(p, "r", encoding="utf-8", errors="replace")
        if not from_start:
            f.seek(0, os.SEEK_END)
        files.append((p, f))

    import json as _json
    last_emit = time.time()

    while True:
        any_new = False
        for p, f in files:
            line = f.readline()
            while line:
                any_new = True
                try:
                    ev = _json.loads(line)
                    if isinstance(ev, dict):
                        ev["_src"] = p  # tag source for debugging/visibility
                except Exception:
                    break

                # feed the online UID/5-tuple merger; may yield 0..N merged rows
                for merged in merger.add(ev):
                    yield merged

                line = f.readline()

        # periodic flush of old flows even if quiet
        now = time.time()
        if (now - last_emit) >= yield_interval:
            for merged in merger.flush_all():
                yield merged
            last_emit = now

        if not any_new:
            time.sleep(0.05)

# -----------------------
# Drain-all tailer: reads ALL new lines from each file every pass
# -----------------------
def tail_and_merge_drain(paths, from_start: bool, merger, idle_flush=0.25, sleep_s=0.05):
    """
    - Opens each file and (optionally) seeks to end if not from_start
    - For each pass, drains ALL newly appended lines from a file before moving on
    - Feeds each parsed JSON event into `merger.add`, yielding merged flows promptly
    - Periodically flushes aged flows even when quiet
    """
    paths = [os.path.expanduser(p) for p in paths]
    files = []
    for p in paths:
        f = open(p, "r", encoding="utf-8", errors="replace")
        if not from_start:
            f.seek(0, os.SEEK_END)
        files.append((p, f))

    import json as _json
    last_flush = time.time()

    while True:
        any_new = False
        for p, f in files:
            line = f.readline()
            # DRAIN THIS FILE COMPLETELY BEFORE MOVING ON
            while line:
                any_new = True
                try:
                    ev = _json.loads(line)
                    if isinstance(ev, dict):
                        ev["_src"] = p  # keep source for debugging/visibility
                except Exception:
                    # malformed line: skip
                    pass
                else:
                    for merged in merger.add(ev):   # may yield 0..N merged flows
                        yield merged
                line = f.readline()

        # periodic flush of aged flows (even if quiet)
        now = time.time()
        if (now - last_flush) >= idle_flush:
            for merged in merger.flush_all():
                yield merged
            last_flush = now

        if not any_new:
            time.sleep(sleep_s)


# -----------------------
# Inference core
# -----------------------
def rows_to_dmatrix(rows: List[Dict[str, float]], feature_order: List[str]) -> xgb.DMatrix:
    """Convert a list of dict rows into an XGBoost DMatrix with correct column order."""
    if not rows:
        return xgb.DMatrix(np.zeros((0, len(feature_order)), dtype=np.float32), feature_names=feature_order)
    X = np.asarray([[r[c] for c in feature_order] for r in rows], dtype=np.float32)
    return xgb.DMatrix(X, feature_names=feature_order)


def default_alert_logic(y_idx: np.ndarray, y_proba: np.ndarray, normal_class: int = 4, min_conf: float = 0.50):
    """
    Returns boolean mask of alerts and the (pred_idx, pred_prob).
    Alert if predicted class != normal_class AND max prob >= min_conf.
    """
    top_prob = y_proba.max(axis=1)
    is_abnormal = (y_idx != normal_class)
    return (is_abnormal & (top_prob >= min_conf)), y_idx, top_prob


def print_alert(ev_summary: Dict, cls_idx: int, prob: float, topk: List[tuple], ts: Optional[float] = None):
    ts_str = f"{ts:.3f}" if ts is not None else "-"
    cls_name = IDX2CLASS.get(int(cls_idx), str(cls_idx))
    topk_str = ", ".join([f"{IDX2CLASS.get(i,i)}:{p:.3f}" for (i, p) in topk])
    srcfile = ev_summary.get('_src','-')
    if isinstance(srcfile, set):
        srcfile = ",".join(sorted(srcfile))
    print(
        f"[ALERT] ts={ts_str} pred={cls_name} ({prob:.3f}) topk=[{topk_str}] "
        f"uid={ev_summary.get('uid','-')} "
        f"src={ev_summary.get('id.orig_h','-')}:{ev_summary.get('id.orig_p','-')} "    
        f"dst={ev_summary.get('id.resp_h','-')}:{ev_summary.get('id.resp_p','-')} "
        f"proto={ev_summary.get('proto','-')} ua={ev_summary.get('user_agent','-')} "
        f"srcfile={srcfile}"
    )
    sys.stdout.flush()


# -----------------------
# Main
# -----------------------

def main():
    ap = argparse.ArgumentParser(description="Realtime IoT IDS inference from Zeek JSONL")
    ap.add_argument("--model", required=True, help="Path to XGBoost model (.json) trained on 35 features")
    ap.add_argument("--encoders", required=True, help="Path to label_encoders.json built from TRAIN")
    ap.add_argument("--logs", nargs="+", required=True, help="Paths to Zeek JSONL logs to tail")
    ap.add_argument("--batch-size", type=int, default=1024, help="Batch size for prediction")
    ap.add_argument("--poll", type=float, default=0.10, help="Idle sleep seconds between polling cycles")
    ap.add_argument("--min-conf", type=float, default=0.60, help="Min prob to alert on non-normal")
    ap.add_argument("--normal-class", type=int, default=4, help="Index of 'normal' class (default 4)")
    ap.add_argument("--alert-csv", help="Optional CSV to append alerts to")
    ap.add_argument("--topk", type=int, default=3, help="How many top classes to show per alert line")
    # args
    ap.add_argument("--follow", action="store_true", help="Tail from end and wait for new lines (default: read from start and stop at EOF)")
    ap.add_argument("--max-wait", type=float, default=1.0,help="Flush partial batch if no new events arrive for this many seconds")
    ap.add_argument("--debug", action="store_true", help="Verbose debug logging for merging/flush timing")
    ap.add_argument("--emit", choices=["abnormal", "normal", "all"], default="abnormal", help="Which predictions to print (all still honor --min-conf).")
    ap.add_argument("--perf", action="store_true", help="Log per-predict latency, CPU, and RAM.")
    ap.add_argument("--perf-file", default=None, help="CSV path to append perf samples (if omitted, prints to stdout).")
    ap.add_argument("--perf-tag", default="", help="Optional tag (e.g., run id) included in perf rows.")




    args = ap.parse_args()
    
    # ---- PERF init ----
    perf_enabled = bool(args.perf)
    perf_writer = None
    perf_fh = None
    perf_process = None

    if perf_enabled and psutil is None:
        print("[PERF] psutil is not installed; run: pip install psutil")
        perf_enabled = False

    if perf_enabled:
        perf_process = psutil.Process(os.getpid())
        # Prime CPU percent so next call is meaningful
        perf_process.cpu_percent(interval=None)

        # Prepare CSV if requested
        if args.perf_file:
            os.makedirs(os.path.dirname(args.perf_file) or ".", exist_ok=True)
            file_exists = os.path.exists(args.perf_file)
            perf_fh = open(args.perf_file, "a", newline="")
            perf_writer = csv.writer(perf_fh)
            if not file_exists:
                perf_writer.writerow([
                    "ts","reason","batch_rows","latency_ms","cpu_proc_pct","rss_mb","vms_mb",
                    "window_s","emit","min_conf","tag"
                ])
        else:
            print("[PERF] logging to stdout (use --perf-file to save CSV)")

    
    # Make the global DEBUG visible to helpers
    global DEBUG
    DEBUG = args.debug


    # Load model
    bst = xgb.Booster()
    bst.load_model(os.path.expanduser(args.model))

    # Initialize vectorizer
    fv = FeatureVectorizer(os.path.expanduser(args.encoders))
    feature_order = fv.features  # exactly the training order
    
    
    def predict_with_perf(dm: xgb.DMatrix, reason: str):
        """Run bst.predict(dm) and, if perf_enabled, log CPU/RAM/latency."""
        start = time.perf_counter()
        proba = bst.predict(dm)
        end = time.perf_counter()

        if perf_enabled:
            ts = time.time()
            # process CPU% since last call (non-blocking)
            cpu = perf_process.cpu_percent(interval=None)
            mem = perf_process.memory_info()
            rss_mb = mem.rss / (1024 * 1024)
            vms_mb = mem.vms / (1024 * 1024)
            latency_ms = (end - start) * 1000.0
            batch_rows = dm.num_row()

            row = [
                f"{ts:.3f}", reason, batch_rows, f"{latency_ms:.3f}",
                f"{cpu:.2f}", f"{rss_mb:.2f}", f"{vms_mb:.2f}",
                getattr(merger, "window_s", None), getattr(args, "emit", None),
                getattr(args, "min_conf", None), args.perf_tag or "",
            ]
            if perf_writer:
                perf_writer.writerow(row)
                # flush for safety on Pi
                perf_fh.flush()
            else:
                print("[PERF] ts=%s reason=%s batch=%s latency=%sms cpu=%.2f%% rss=%.2fMB vms=%.2fMB"
                      % (row[0], row[1], row[2], row[3], cpu, rss_mb, vms_mb))
        return proba


    # Prepare alert CSV if requested
    if args.alert_csv:
        outdir = os.path.dirname(args.alert_csv)
        if outdir:
            os.makedirs(outdir, exist_ok=True)
        if not os.path.exists(args.alert_csv):
            # Write header once
            cols = ["ts", "pred_idx", "pred_name", "pred_prob"] + feature_order
            pd.DataFrame(columns=cols).to_csv(args.alert_csv, index=False)

    # Graceful shutdown
    stop = False

    def _sigint(_sig, _frm):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, _sigint)
    signal.signal(signal.SIGTERM, _sigint)

    # Main loop: batch up events, predict, alert
    merger = OnlineMerger(window_s=60.0, max_cache=50000)
    merger._DEBUG = DEBUG   # <-- add this line

    last_event_ts = time.time()

    batch_rows: List[Dict[str, float]] = []
    batch_evs: List[dict] = []

    # periodic flush timer for aged flows
    last_flush_check = time.time()
    FLUSH_EVERY = 0.25  # seconds
    
    # predict periodically even if traffic isn't quiet and batch isn't full
    last_predict_check = time.time()
    PRED_EVERY = 1.0  # seconds (tune this)

    # IMPORTANT: Do NOT call merger.flush_all() during live tailing.
    # We rely on merger.add(ev) + a periodic aged flush to emit only ready flows.
    for ev in multiplex_logs(args.logs, follow=args.follow, poll_sleep=args.poll):
        if stop:
            break

        # 1) Merge this raw Zeek event; add() yields only aged/ready merged flows
        for mev in merger.add(ev):
            try:
                row = fv.event_to_row(mev)
            except Exception:
                continue
            batch_rows.append(row)
            batch_evs.append(mev)
            last_event_ts = time.time()

        # 2) Periodic aged flush even if traffic is quiet
        now = time.time()
        if (now - last_flush_check) >= FLUSH_EVERY:
            for mev in merger.flush_aged():
                try:
                    row = fv.event_to_row(mev)
                except Exception:
                    continue
                batch_rows.append(row)
                batch_evs.append(mev)
                last_event_ts = now
            last_flush_check = now
            

        # 3) Idle prediction flush: if traffic is quiet, run on partial batch
        
        
        if args.max_wait > 0 and batch_rows and (now - last_event_ts) >= args.max_wait:
            dm = rows_to_dmatrix(batch_rows, feature_order)
            if dm.num_row() > 0:
                proba = predict_with_perf(dm, "idle")
                y_idx = proba.argmax(axis=1)
                top_probs = proba.max(axis=1)
                if args.emit == "abnormal":
                    mask = (y_idx != args.normal_class) & (top_probs >= args.min_conf)
                elif args.emit == "normal":
                    mask = (y_idx == args.normal_class) & (top_probs >= args.min_conf)
                else:  # "all"
                    mask = (top_probs >= args.min_conf)
                idxs = y_idx

                if mask.any():
                    if args.alert_csv:
                        alert_rows = []
                    for i, flagged in enumerate(mask):
                        if not flagged:
                            continue
                        ev_i = batch_evs[i]
                        topk_idx = np.argsort(proba[i])[::-1][: max(1, args.topk)]
                        topk = [(int(k), float(proba[i][k])) for k in topk_idx]
                        print_alert(
                            ev_summary=ev_i,
                            cls_idx=int(idxs[i]),
                            prob=float(top_probs[i]),
                            topk=topk,
                            ts=ev_i.get("ts"),
                        )
                        if args.alert_csv:
                            rec = {
                                "ts": ev_i.get("ts", None),
                                "pred_idx": int(idxs[i]),
                                "pred_name": IDX2CLASS.get(int(idxs[i]), str(int(idxs[i]))),
                                "pred_prob": float(top_probs[i]),
                            }
                            for c in feature_order:
                                rec[c] = float(batch_rows[i].get(c, 0.0))
                            alert_rows.append(rec)
                    if args.alert_csv and alert_rows:
                        pd.DataFrame(alert_rows).to_csv(args.alert_csv, mode="a", header=False, index=False)
            batch_rows.clear()
            batch_evs.clear()
            
        # 3b) Periodic predict: don't wait forever for batch_size or quiet
        now = time.time()
        if batch_rows and (now - last_predict_check) >= PRED_EVERY:
            dm = rows_to_dmatrix(batch_rows, feature_order)
            if dm.num_row() > 0:
                proba = predict_with_perf(dm, "idle")
                y_idx = proba.argmax(axis=1)
                top_probs = proba.max(axis=1)
                if args.emit == "abnormal":
                    mask = (y_idx != args.normal_class) & (top_probs >= args.min_conf)
                elif args.emit == "normal":
                    mask = (y_idx == args.normal_class) & (top_probs >= args.min_conf)
                else:  # "all"
                    mask = (top_probs >= args.min_conf)
                idxs = y_idx

                if mask.any():
                    if args.alert_csv:
                        alert_rows = []
                    for i, flagged in enumerate(mask):
                        if not flagged:
                            continue
                        ev_i = batch_evs[i]
                        topk_idx = np.argsort(proba[i])[::-1][: max(1, args.topk)]
                        topk = [(int(k), float(proba[i][k])) for k in topk_idx]
                        print_alert(
                            ev_summary=ev_i,
                            cls_idx=int(idxs[i]),
                            prob=float(top_probs[i]),
                            topk=topk,
                            ts=ev_i.get("ts"),
                        )
                        if args.alert_csv:
                            rec = {
                                "ts": ev_i.get("ts", None),
                                "pred_idx": int(idxs[i]),
                                "pred_name": IDX2CLASS.get(int(idxs[i]), str(int(idxs[i]))),
                                "pred_prob": float(top_probs[i]),
                            }
                            for c in feature_order:
                                rec[c] = float(batch_rows[i].get(c, 0.0))
                            alert_rows.append(rec)
                    if args.alert_csv and alert_rows:
                        pd.DataFrame(alert_rows).to_csv(args.alert_csv, mode="a", header=False, index=False)
            batch_rows.clear()
            batch_evs.clear()
            last_predict_check = now

        # 4) Normal batch-size flush
        if len(batch_rows) >= args.batch_size:
            dm = rows_to_dmatrix(batch_rows, feature_order)
            if dm.num_row() > 0:
                proba = predict_with_perf(dm, "idle")
                y_idx = proba.argmax(axis=1)
                top_probs = proba.max(axis=1)
                if args.emit == "abnormal":
                    mask = (y_idx != args.normal_class) & (top_probs >= args.min_conf)
                elif args.emit == "normal":
                    mask = (y_idx == args.normal_class) & (top_probs >= args.min_conf)
                else:  # "all"
                    mask = (top_probs >= args.min_conf)
                idxs = y_idx

                if mask.any():
                    if args.alert_csv:
                        alert_rows = []
                    for i, flagged in enumerate(mask):
                        if not flagged:
                            continue
                        ev_i = batch_evs[i]
                        topk_idx = np.argsort(proba[i])[::-1][: max(1, args.topk)]
                        topk = [(int(k), float(proba[i][k])) for k in topk_idx]
                        print_alert(
                            ev_summary=ev_i,
                            cls_idx=int(idxs[i]),
                            prob=float(top_probs[i]),
                            topk=topk,
                            ts=ev_i.get("ts"),
                        )
                        if args.alert_csv:
                            rec = {
                                "ts": ev_i.get("ts", None),
                                "pred_idx": int(idxs[i]),
                                "pred_name": IDX2CLASS.get(int(idxs[i]), str(int(idxs[i]))),
                                "pred_prob": float(top_probs[i]),
                            }
                            for c in feature_order:
                                rec[c] = float(batch_rows[i].get(c, 0.0))
                            alert_rows.append(rec)
                    if args.alert_csv and alert_rows:
                        pd.DataFrame(alert_rows).to_csv(args.alert_csv, mode="a", header=False, index=False)
            batch_rows.clear()
            batch_evs.clear()
            time.sleep(args.poll)
     
     
            
    # idle flush (if traffic is sparse)
    now = time.time()
    if args.max_wait > 0 and batch_rows and (now - last_event_ts) >= args.max_wait:
        dm = rows_to_dmatrix(batch_rows, feature_order)
        if dm.num_row() > 0:
            proba = predict_with_perf(dm, "idle")
            y_idx = proba.argmax(axis=1)
            top_probs = proba.max(axis=1)
            if args.emit == "abnormal":
                mask = (y_idx != args.normal_class) & (top_probs >= args.min_conf)
            elif args.emit == "normal":
                mask = (y_idx == args.normal_class) & (top_probs >= args.min_conf)
            else:  # "all"
                mask = (top_probs >= args.min_conf)
            idxs = y_idx

            if mask.any():
                if args.alert_csv:
                    alert_rows = []
                for i, flagged in enumerate(mask):
                    if not flagged:
                        continue
                    ev_i = batch_evs[i]
                    topk_idx = np.argsort(proba[i])[::-1][: max(1, args.topk)]
                    topk = [(int(k), float(proba[i][k])) for k in topk_idx]
                    print_alert(
                        ev_summary=ev_i,
                        cls_idx=int(idxs[i]),
                        prob=float(top_probs[i]),
                        topk=topk,
                        ts=ev_i.get("ts"),
                    )
                    if args.alert_csv:
                        rec = {
                            "ts": ev_i.get("ts", None),
                            "pred_idx": int(idxs[i]),
                            "pred_name": IDX2CLASS.get(int(idxs[i]), str(int(idxs[i]))),
                            "pred_prob": float(top_probs[i]),
                        }
                        for c in feature_order:
                            rec[c] = float(batch_rows[i][c])
                        alert_rows.append(rec)
                if args.alert_csv and alert_rows:
                    pd.DataFrame(alert_rows).to_csv(args.alert_csv, mode="a", header=False, index=False)
        batch_rows.clear()
        batch_evs.clear()
        
    # Drain any remaining merged flows before final predict
    for mev in merger.flush_all():
        try:
            row = fv.event_to_row(mev)
        except Exception:
            continue
        batch_rows.append(row)
        batch_evs.append(mev)


            
    # Final drain
    if batch_rows and not stop:
        dm = rows_to_dmatrix(batch_rows, feature_order)
        if dm.num_row() > 0:
            proba = predict_with_perf(dm, "idle")
            y_idx = proba.argmax(axis=1)
            top_probs = proba.max(axis=1)
            if args.emit == "abnormal":
                mask = (y_idx != args.normal_class) & (top_probs >= args.min_conf)
            elif args.emit == "normal":
                mask = (y_idx == args.normal_class) & (top_probs >= args.min_conf)
            else:  # "all"
                mask = (top_probs >= args.min_conf)
            idxs = y_idx

            if mask.any():
                if args.alert_csv:
                    alert_rows = []
                for i, flagged in enumerate(mask):
                    if not flagged:
                        continue
                    ev_i = batch_evs[i]
                    topk_idx = np.argsort(proba[i])[::-1][: max(1, args.topk)]
                    topk = [(int(k), float(proba[i][k])) for k in topk_idx]
                    print_alert(
                        ev_summary=ev_i,
                        cls_idx=int(idxs[i]),
                        prob=float(top_probs[i]),
                        topk=topk,
                        ts=ev_i.get("ts"),
                    )
                    if args.alert_csv:
                        rec = {
                            "ts": ev_i.get("ts", None),
                            "pred_idx": int(idxs[i]),
                            "pred_name": IDX2CLASS.get(int(idxs[i]), str(int(idxs[i]))),
                            "pred_prob": float(top_probs[i]),
                        }
                        for c in feature_order:
                            #rec[c] = float(batch_rows[i][c])
                            rec[c] = float(batch_rows[i].get(c, 0.0))
                        alert_rows.append(rec)
                if args.alert_csv and alert_rows:
                    pd.DataFrame(alert_rows).to_csv(args.alert_csv, mode="a", header=False, index=False)

    # ---- PERF close ----
    if perf_fh:
        perf_fh.close()

    print("Shutdown.")
    


if __name__ == "__main__":
    main()


