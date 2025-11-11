#!/usr/bin/env python3
# log_webserver.py
#
# Usage:
#   python3 log_webserver.py --port 8080 --bind 0.0.0.0 --log access.log
#
# Press Ctrl+C to stop.

import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone

class LoggingHandler(BaseHTTPRequestHandler):
    server_banner = (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>Controlled Test Page</title></head>"
        "<body style='font-family:system-ui, sans-serif'>"
        "<h1>Controlled Test Page</h1>"
        "<p>You reached the lab web server. This is expected in the redirection test.</p>"
        "<hr><small>Time: {time}</small>"
        "</body></html>"
    )

    def log_line(self, msg):
        line = f"{datetime.now(timezone.utc).isoformat()}Z {self.client_address[0]} {msg}\n"
        try:
            self.server.log_fp.write(line)
            self.server.log_fp.flush()
        except Exception:
            pass
        # Also print to console
        print(line.strip())

    def do_HEAD(self):
        self._handle_request(send_body=False)

    def do_GET(self):
        self._handle_request(send_body=True)

    def do_POST(self):
        # Read body but discard, just to avoid broken pipes on clients
        length = int(self.headers.get('Content-Length', 0))
        if length:
            _ = self.rfile.read(length)
        self._handle_request(send_body=True)

    def _handle_request(self, send_body=True):
        host = self.headers.get('Host', '')
        ua = self.headers.get('User-Agent', '')
        self.log_line(f'"{self.command} {self.path}" Host="{host}" UA="{ua}"')

        body = self.server_banner.format(time=datetime.now(timezone.utc).isoformat() + "Z").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def log_message(self, format, *args):
        # Silence default logging; we already log via log_line
        return

def main():
    parser = argparse.ArgumentParser(description="Minimal logging web server (lab use).")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--log", default="access.log")
    args = parser.parse_args()

    httpd = HTTPServer((args.bind, args.port), LoggingHandler)
    httpd.log_fp = open(args.log, "a", encoding="utf-8")
    print(f"Listening on http://{args.bind}:{args.port} (logging to {args.log}) - Ctrl+C to stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.log_fp.close()

if __name__ == "__main__":
    main()