from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import subprocess
from urllib.parse import urlparse

PORT = 8765
DEFAULT_HOME_ASSISTANT_URL = "http://127.0.0.1:8123"


class Handler(BaseHTTPRequestHandler):
    def _json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        print(f"{self.client_address[0]} - {format % args}")

    def do_GET(self):
        if self.path == "/health":
            self._json(200, {
                "status": "ok",
                "service": "besmart-companion"
            })
            return

        if self.path == "/tailscale/status":
            result = subprocess.run(
                ["tailscale", "status", "--json"],
                capture_output=True,
                text=True
            )

            try:
                status_data = json.loads(result.stdout) if result.stdout else None
            except json.JSONDecodeError:
                status_data = None

            self._json(200, {
                "ok": result.returncode == 0,
                "status": status_data,
                "error": result.stderr or None
            })
            return

        self._json(404, {"error": "not_found"})

    def do_POST(self):
        if self.path == "/tailscale/connect":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                data = json.loads(body.decode("utf-8") or "{}")
            except Exception:
                self._json(400, {"error": "invalid_json"})
                return

            auth_key = data.get("auth_key")
            hostname = data.get("hostname", "besmart-home")
            enable_funnel = bool(data.get("enable_funnel", False))
            serve_target_url = normalize_serve_target(data.get("serve_target_url"))
            expected_url = data.get("expected_url")

            if not auth_key:
                self._json(400, {"error": "missing_auth_key"})
                return

            result = subprocess.run(
                [
                    "tailscale",
                    "up",
                    "--authkey", auth_key,
                    "--hostname", hostname,
                    "--accept-dns=true"
                ],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                self._json(500, {
                    "ok": False,
                    "error": result.stderr
                })
                return

            ip_result = subprocess.run(
                ["tailscale", "ip", "-4"],
                capture_output=True,
                text=True
            )

            lines = ip_result.stdout.strip().splitlines()
            ip = lines[0] if lines else None
            funnel_url = None

            if enable_funnel:
                funnel_result = subprocess.run(
                    [
                        "tailscale",
                        "funnel",
                        "--bg",
                        "--yes",
                        serve_target_url
                    ],
                    capture_output=True,
                    text=True
                )

                if funnel_result.returncode != 0:
                    self._json(500, {
                        "ok": False,
                        "ip": ip,
                        "error": funnel_result.stderr or funnel_result.stdout or "failed_to_enable_funnel"
                    })
                    return

                funnel_url = expected_url or tailscale_dns_url()

            self._json(200, {
                "ok": True,
                "ip": ip,
                "url": funnel_url or (f"http://{ip}:8123" if ip else None),
                "serve_target_url": serve_target_url if enable_funnel else None
            })
            return

        self._json(404, {"error": "not_found"})


def normalize_serve_target(value):
    if not value:
        return DEFAULT_HOME_ASSISTANT_URL

    target = str(value).strip().rstrip("/")
    parsed = urlparse(target)

    if parsed.scheme not in ("http", "https"):
        return DEFAULT_HOME_ASSISTANT_URL

    port = parsed.port or 8123
    path = parsed.path.rstrip("/")
    return f"http://127.0.0.1:{port}{path}"


def tailscale_dns_url():
    result = subprocess.run(
        ["tailscale", "status", "--json"],
        capture_output=True,
        text=True
    )
    if result.returncode != 0 or not result.stdout:
        return None

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None

    dns_name = data.get("Self", {}).get("DNSName")
    if not dns_name:
        return None

    return f"https://{dns_name.rstrip('.')}"


print(f"BeSmart Companion listening on port {PORT}")
server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
server.serve_forever()
