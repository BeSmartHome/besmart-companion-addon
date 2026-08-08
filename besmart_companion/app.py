from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import subprocess

PORT = 8765


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

            if not auth_key:
                self._json(400, {"error": "missing_auth_key"})
                return

            result = subprocess.run(
                [
                    "tailscale",
                    "up",
                    "--authkey", auth_key,
                    "--hostname", hostname
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

            self._json(200, {
                "ok": True,
                "ip": ip,
                "url": f"http://{ip}:8123" if ip else None
            })
            return

        self._json(404, {"error": "not_found"})


print(f"BeSmart Companion listening on port {PORT}")
server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
server.serve_forever()
