from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import subprocess
import urllib.error
import urllib.request
from urllib.parse import urlparse

PORT = 8765
DEFAULT_HOME_ASSISTANT_URL = "http://127.0.0.1:8123"
DEFAULT_COMPANION_URL = "http://127.0.0.1:8765"
REMOTE_PREFIX = "/remote/ha"
REMOTE_TOKEN_FILE = "/data/besmart_remote_token"
HA_UPSTREAM_FILE = "/data/besmart_ha_upstream"
SERVER_ID_FILE = "/data/besmart_server_id"
REMOTE_TOKEN_HEADER = "X-BeSmart-Remote-Token"


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
        if self.path.startswith(REMOTE_PREFIX):
            self._proxy_home_assistant()
            return

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
        if self.path.startswith(REMOTE_PREFIX):
            self._proxy_home_assistant()
            return

        if self.path == "/tailscale/connect":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                data = json.loads(body.decode("utf-8") or "{}")
            except Exception:
                self._json(400, {"error": "invalid_json"})
                return

            auth_key = data.get("auth_key")
            server_id = data.get("server_id")
            hostname = data.get("hostname", "besmart-home")
            enable_funnel = bool(data.get("enable_funnel", False))
            serve_target_url = normalize_companion_target(data.get("serve_target_url"))
            ha_upstream_url = normalize_ha_upstream(data.get("ha_upstream_url"))
            remote_token = data.get("remote_token")
            expected_url = data.get("expected_url")

            if not auth_key:
                self._json(400, {"error": "missing_auth_key"})
                return

            if enable_funnel and not remote_token:
                self._json(400, {"error": "missing_remote_token"})
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
                store_server_id(server_id)
                store_remote_token(remote_token)
                store_ha_upstream(ha_upstream_url)
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
                "server_id": server_id,
                "url": funnel_url or (f"http://{ip}:8123" if ip else None),
                "serve_target_url": serve_target_url if enable_funnel else None,
                "ha_upstream_url": ha_upstream_url if enable_funnel else None
            })
            return

        self._json(404, {"error": "not_found"})

    def _proxy_home_assistant(self):
        stored_token = read_remote_token()
        request_token = self.headers.get(REMOTE_TOKEN_HEADER)
        if not stored_token or not request_token or request_token != stored_token:
            self._json(401, {"error": "unauthorized"})
            return

        parsed_remote_path = urlparse(self.path)
        ha_path = parsed_remote_path.path[len(REMOTE_PREFIX):] or "/"
        if not is_allowed_ha_path(ha_path):
            self._json(403, {"error": "forbidden"})
            return

        target_url = f"{read_ha_upstream()}{ha_path}"
        if parsed_remote_path.query:
            target_url = f"{target_url}?{parsed_remote_path.query}"
        body = None
        if self.command in ("POST", "PUT", "PATCH"):
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length > 0 else None

        headers = {}
        for header in ("Authorization", "Content-Type", "Accept"):
            value = self.headers.get(header)
            if value:
                headers[header] = value

        request = urllib.request.Request(
            target_url,
            data=body,
            headers=headers,
            method=self.command
        )

        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                response_body = response.read()
                self.send_response(response.status)
                self.send_header("Content-Type", response.headers.get("Content-Type", "application/json"))
                self.send_header("Content-Length", str(len(response_body)))
                self.end_headers()
                self.wfile.write(response_body)
        except urllib.error.HTTPError as error:
            response_body = error.read()
            self.send_response(error.code)
            self.send_header("Content-Type", error.headers.get("Content-Type", "application/json"))
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)
        except Exception as error:
            self._json(502, {"error": str(error)})


def normalize_companion_target(value):
    if not value:
        return DEFAULT_COMPANION_URL

    target = str(value).strip().rstrip("/")
    parsed = urlparse(target)

    if parsed.scheme not in ("http", "https"):
        return DEFAULT_COMPANION_URL

    port = parsed.port or PORT
    return f"http://127.0.0.1:{port}"


def normalize_ha_upstream(value):
    if not value:
        return DEFAULT_HOME_ASSISTANT_URL

    target = str(value).strip().rstrip("/")
    parsed = urlparse(target)

    if parsed.scheme not in ("http", "https"):
        return DEFAULT_HOME_ASSISTANT_URL

    port = parsed.port or 8123
    path = parsed.path.rstrip("/")
    return f"http://127.0.0.1:{port}{path}"


def is_allowed_ha_path(path):
    allowed_exact = {
        "/api/",
        "/api/states",
        "/api/config/energy"
    }
    allowed_prefixes = (
        "/api/states/",
        "/api/services/"
    )

    if path in allowed_exact:
        return True

    return any(path.startswith(prefix) for prefix in allowed_prefixes)


def store_remote_token(token):
    os.makedirs(os.path.dirname(REMOTE_TOKEN_FILE), exist_ok=True)
    with open(REMOTE_TOKEN_FILE, "w", encoding="utf-8") as file:
        file.write(str(token).strip())


def store_server_id(server_id):
    if not server_id:
        return

    os.makedirs(os.path.dirname(SERVER_ID_FILE), exist_ok=True)
    with open(SERVER_ID_FILE, "w", encoding="utf-8") as file:
        file.write(str(server_id).strip())


def read_remote_token():
    try:
        with open(REMOTE_TOKEN_FILE, "r", encoding="utf-8") as file:
            return file.read().strip()
    except FileNotFoundError:
        return None


def store_ha_upstream(url):
    os.makedirs(os.path.dirname(HA_UPSTREAM_FILE), exist_ok=True)
    with open(HA_UPSTREAM_FILE, "w", encoding="utf-8") as file:
        file.write(str(url).strip().rstrip("/"))


def read_ha_upstream():
    try:
        with open(HA_UPSTREAM_FILE, "r", encoding="utf-8") as file:
            value = file.read().strip().rstrip("/")
            return value or DEFAULT_HOME_ASSISTANT_URL
    except FileNotFoundError:
        return DEFAULT_HOME_ASSISTANT_URL


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
