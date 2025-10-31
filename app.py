#!/usr/bin/env python3
import argparse, os, csv, json
from collections import deque
from datetime import datetime, timezone
from flask import Flask, make_response, send_from_directory, request

app = Flask(__name__, static_folder="static", static_url_path="/static")

parser = argparse.ArgumentParser(description="Lightweight IDS dashboard (Flask)")
parser.add_argument("--csv", default="alerts.csv", help="Path to alerts CSV file")
parser.add_argument("--host", default="127.0.0.1", help="Bind host")
parser.add_argument("--port", type=int, default=8000, help="Bind port")
parser.add_argument("--limit", type=int, default=2000, help="Default max rows returned by /api/alerts")
args, _ = parser.parse_known_args()

CSV_PATH = os.path.abspath(args.csv)
DEFAULT_LIMIT = max(1, args.limit)

def _tail_csv(path: str, max_rows: int):
    """
    Efficiently read the last max_rows CSV records by seeking backward from file end.
    We locate the last (max_rows+1) newline boundaries, then parse only that slice.
    """
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return []

    # Find start offset of the last N lines by scanning backwards in blocks
    block_size = 64 * 1024
    need_newlines = max_rows + 1  # +1 to include header or an extra split
    file_size = os.path.getsize(path)
    with open(path, "rb") as fb:
        # Gather newline positions
        newlines = []
        pos = file_size
        leftover = b""
        while pos > 0 and len(newlines) <= need_newlines:
            read_size = block_size if pos >= block_size else pos
            pos -= read_size
            fb.seek(pos)
            data = fb.read(read_size) + leftover
            # splitlines(True) keeps line endings; we count them
            lines = data.split(b"\n")
            # The first chunk piece may be partial; carry it to next loop
            leftover = lines[0]
            # Count newlines in the rest
            for part in lines[1:]:
                newlines.append(pos)  # mark a newline seen (only count)
        # Decide the byte offset to start reading
        # If we didn't find enough newlines, start at 0
        start_offset = 0
        if len(newlines) > need_newlines:
            # We found many; compute approximate start by moving to the (need_newlines)-th from end
            # Simpler approach: read a larger tail window and parse only last N rows below
            pass

    # Simpler robust approach: read a tail window (~few MB) then parse only last N rows.
    window_bytes = min(file_size, 2_000_000)  # 2 MB tail window (tune)
    with open(path, "rb") as fb:
        fb.seek(file_size - window_bytes)
        blob = fb.read(window_bytes)

    text = blob.decode("utf-8", errors="ignore").splitlines()
    # Ensure we have the header: if tail cut it, fallback by reading first line of file for header
    header = None
    for line in text[:50]:
        if "," in line:  # naive check
            header = line
            break
    if header is None:
        with open(path, "r", encoding="utf-8", errors="ignore", newline="") as f:
            header = f.readline().strip()

    # Ensure header is at top of the slice:
    if not text or text[0].strip() != header.strip():
        text = [header] + text

    # Keep only last max_rows lines + header
    if len(text) > max_rows + 1:
        text = [text[0]] + text[-max_rows:]

    # Parse CSV dicts
    import io, csv as _csv
    rdr = _csv.DictReader(io.StringIO("\n".join(text)))
    out = []
    for row in rdr:
        # skip empty rows
        if not any(v.strip() for v in row.values() if isinstance(v, str)):
            continue
        out.append(row)
    return out


def _f(x, default=None):
    try:
        if x is None or x == "": return default
        return float(x)
    except Exception:
        return default

def _no_cache(resp):
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")

@app.get("/api/alerts")
def api_alerts():
    limit = request.args.get("limit", type=int) or DEFAULT_LIMIT
    limit = max(1, min(limit, 100000))
    rows = _tail_csv(CSV_PATH, limit)

    out = []
    classes = set()
    for r in rows:
        r2 = dict(r)
        r2["ts"] = _f(r.get("ts"))
        r2["pred_prob"] = _f(r.get("pred_prob"))
        # normalize some common columns so the table can show them if present
        # (no harm if missing)
        r2["pred_name"] = r.get("pred_name") or r.get("pred_idx")
        classes.add(str(r2["pred_name"]))
        out.append(r2)

    payload = {
        "rows": out,
        "classes": sorted(list(classes)),
        "file_info": {
            "path": CSV_PATH,
            "size_bytes": os.path.getsize(CSV_PATH) if os.path.exists(CSV_PATH) else 0,
            "mtime_iso": (
                datetime.fromtimestamp(os.path.getmtime(CSV_PATH), tz=timezone.utc).isoformat()
                if os.path.exists(CSV_PATH) else None
            ),
        },
        "server": {"default_limit": DEFAULT_LIMIT},
    }
    resp = make_response(json.dumps(payload))
    resp.mimetype = "application/json"
    return _no_cache(resp)

if __name__ == "__main__":
    print(f"[+] Open http://{args.host}:{args.port}")
    print(f"[+] CSV: {CSV_PATH}  (default tail limit: {DEFAULT_LIMIT})")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)
