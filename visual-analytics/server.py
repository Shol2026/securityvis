import json
import mimetypes
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse


APP_ROOT = Path(__file__).resolve().parent
RAW_FIREWALL = APP_ROOT.parent / "raw_firewall_log_1.txt"


class VAHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(APP_ROOT), **kwargs)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/raw-firewall":
            self.handle_raw_firewall(parsed.query)
            return
        super().do_GET()

    def handle_raw_firewall(self, query):
        params = parse_qs(query)
        source = clean(params.get("source", [""])[0])
        dest = clean(params.get("dest", [""])[0])
        port = clean(params.get("port", [""])[0])
        limit = parse_limit(params.get("limit", ["25"])[0])

        matches = []
        scanned = 0
        if RAW_FIREWALL.exists():
            with RAW_FIREWALL.open(encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    scanned += 1
                    if source and source not in line:
                        continue
                    if dest and dest not in line:
                        continue
                    if port and f"/{port}" not in line and f":{port}" not in line:
                        continue
                    matches.append(line.rstrip("\r\n"))
                    if len(matches) >= limit:
                        break

        body = json.dumps(
            {
                "source": source or None,
                "dest": dest or None,
                "port": port or None,
                "limit": limit,
                "scanned_lines": scanned,
                "matches": matches,
                "note": "Raw firewall log is scanned only after explicit drill-down request.",
            },
            ensure_ascii=False,
        ).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def guess_type(self, path):
        if path.endswith(".js"):
            return "text/javascript; charset=utf-8"
        if path.endswith(".css"):
            return "text/css; charset=utf-8"
        if path.endswith(".json"):
            return "application/json; charset=utf-8"
        return mimetypes.guess_type(path)[0] or "application/octet-stream"


def clean(value):
    value = unquote(str(value or "")).strip()
    return "" if value == "all" else value[:80]


def parse_limit(value):
    try:
        return max(1, min(100, int(value)))
    except ValueError:
        return 25


def main():
    server = ThreadingHTTPServer(("127.0.0.1", 8090), VAHandler)
    print("Serving VA dashboard on http://127.0.0.1:8090/app/index.html")
    print("Raw firewall drill-down API: /api/raw-firewall?source=...&dest=...&port=...")
    server.serve_forever()


if __name__ == "__main__":
    main()
