from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import select
import socket
import subprocess
import threading
import time
import uuid
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
TAILSCALE_CONNECT_LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def _json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except BrokenPipeError:
            print(f"Client disconnected before JSON response status={status}", flush=True)

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

        if self.path == "/identity":
            self._json(200, {
                "server_id": get_or_create_server_id(),
                "remote_url": read_remote_url(),
                "tailscale_dns_name": tailscale_dns_name(read_tailscale_status())
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
            server_id = data.get("server_id") or get_or_create_server_id()
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

            if not TAILSCALE_CONNECT_LOCK.acquire(blocking=False):
                self._json(409, {
                    "ok": False,
                    "error": "tailscale_connect_in_progress",
                    "message": "Remote access setup is already running. Wait for the current setup to finish.",
                    "url": read_remote_url()
                })
                return

            try:
                current_status = read_tailscale_status()
                reused_existing_login = tailscale_is_running(current_status)
                if reused_existing_login:
                    print(f"Reusing existing Tailscale login dns={tailscale_dns_name(current_status)}", flush=True)
                else:
                    up_result = run_tailscale_up(auth_key, hostname, enable_funnel)
                    if not up_result.get("ok"):
                        self._json(up_result.get("status", 500), up_result)
                        return

                ip = read_tailscale_ip()
                funnel_url = None

                if enable_funnel:
                    effective_remote_token = read_remote_token() or remote_token
                    store_server_id(server_id)
                    store_remote_token(effective_remote_token)
                    store_ha_upstream(ha_upstream_url)
                    funnel_target = str(urlparse(serve_target_url).port or PORT)
                    funnel_result = enable_tailscale_funnel(funnel_target)
                    if not funnel_result.get("ok"):
                        funnel_result["ip"] = ip
                        self._json(funnel_result.get("status", 500), funnel_result)
                        return

                    funnel_url = tailscale_dns_url() or expected_url or read_remote_url()
                    if funnel_url:
                        store_remote_url(funnel_url)
                        print(f"Tailscale Funnel configured url={funnel_url}", flush=True)

                self._json(200, {
                    "ok": True,
                    "ip": ip,
                    "server_id": server_id,
                    "url": funnel_url or (f"http://{ip}:8123" if ip else None),
                    "remote_token": read_remote_token(),
                    "remote_ready": False if funnel_url else None,
                    "remote_ready_reason": "public_https_must_be_tested_by_client" if funnel_url else None,
                    "serve_target_url": serve_target_url if enable_funnel else None,
                    "ha_upstream_url": ha_upstream_url if enable_funnel else None
                })
                return
            finally:
                TAILSCALE_CONNECT_LOCK.release()

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

        if is_websocket_upgrade(self.headers):
            self._proxy_home_assistant_websocket(ha_path, parsed_remote_path.query)
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
        except BrokenPipeError:
            print(f"Client disconnected while proxying {ha_path}", flush=True)
        except Exception as error:
            try:
                self._json(502, {"error": str(error)})
            except BrokenPipeError:
                print(f"Client disconnected before proxy error response {ha_path}: {error}", flush=True)

    def _proxy_home_assistant_websocket(self, ha_path, query):
        upstream = urlparse(read_ha_upstream())
        upstream_host = upstream.hostname or "127.0.0.1"
        upstream_port = upstream.port or 8123
        upstream_path = ha_path
        if query:
            upstream_path = f"{upstream_path}?{query}"

        try:
            print(f"WebSocket proxy accepted path={upstream_path}", flush=True)
            with socket.create_connection((upstream_host, upstream_port), timeout=10) as upstream_socket:
                upstream_socket.settimeout(None)
                self.connection.settimeout(None)
                upstream_socket.sendall(self._websocket_upgrade_request(upstream_path, upstream_host, upstream_port))

                response = read_http_headers(upstream_socket)
                if not response:
                    print("WebSocket upstream returned no response", flush=True)
                    self._json(502, {"error": "websocket_upstream_no_response"})
                    return

                status_line = response.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
                print(f"WebSocket upstream response: {status_line}", flush=True)
                self.connection.sendall(response)
                if not response.startswith(b"HTTP/1.1 101") and not response.startswith(b"HTTP/1.0 101"):
                    return

                tunnel_sockets(self.connection, upstream_socket)
                print("WebSocket proxy closed", flush=True)
        except Exception as error:
            print(f"WebSocket proxy error: {error}", flush=True)
            try:
                self._json(502, {"error": str(error)})
            except Exception:
                pass

    def _websocket_upgrade_request(self, upstream_path, upstream_host, upstream_port):
        headers = [
            f"GET {upstream_path} HTTP/1.1",
            f"Host: {upstream_host}:{upstream_port}",
            "Connection: Upgrade",
            "Upgrade: websocket",
        ]

        forwarded_headers = (
            "Sec-WebSocket-Key",
            "Sec-WebSocket-Version",
            "Sec-WebSocket-Protocol",
            "Sec-WebSocket-Extensions",
            "Origin"
        )
        for header in forwarded_headers:
            value = self.headers.get(header)
            if value:
                headers.append(f"{header}: {value}")

        missing_headers = [
            header
            for header in ("Sec-WebSocket-Key", "Sec-WebSocket-Version")
            if not self.headers.get(header)
        ]
        if missing_headers:
            print(f"WebSocket upgrade missing headers={missing_headers}", flush=True)

        headers.extend([
            "",
            ""
        ])
        return "\r\n".join(headers).encode("utf-8")


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
        "/api/websocket",
        "/api/config/energy"
    }
    allowed_prefixes = (
        "/api/states/",
        "/api/services/"
    )

    if path in allowed_exact:
        return True

    return any(path.startswith(prefix) for prefix in allowed_prefixes)


def is_websocket_upgrade(headers):
    connection = headers.get("Connection", "")
    upgrade = headers.get("Upgrade", "")
    return "upgrade" in connection.lower() and upgrade.lower() == "websocket"


def read_http_headers(source_socket):
    buffer = b""
    while b"\r\n\r\n" not in buffer:
        chunk = source_socket.recv(4096)
        if not chunk:
            break
        buffer += chunk
        if len(buffer) > 65536:
            break
    return buffer


def tunnel_sockets(client_socket, upstream_socket):
    sockets = [client_socket, upstream_socket]
    while True:
        readable, _, exceptional = select.select(sockets, [], sockets, 300)
        if exceptional:
            return
        if not readable:
            return
        for source in readable:
            try:
                data = source.recv(65536)
            except OSError:
                return
            if not data:
                return
            target = upstream_socket if source is client_socket else client_socket
            try:
                target.sendall(data)
            except OSError:
                return


def wait_for_remote_https_ready(remote_url, remote_token, timeout=150):
    if not remote_url or not remote_token:
        return {"ok": False, "error": "missing_remote_url_or_token"}

    deadline = time.monotonic() + timeout
    probe_url = f"{remote_url.rstrip('/')}/api/"
    last_error = None
    print(f"Waiting for Tailscale Funnel HTTPS url={probe_url}", flush=True)

    while time.monotonic() < deadline:
        request = urllib.request.Request(
            probe_url,
            headers={
                REMOTE_TOKEN_HEADER: remote_token,
                "Accept": "application/json"
            }
        )

        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                print(f"Tailscale Funnel HTTPS ready status={response.status}", flush=True)
                return {"ok": True, "status": response.status}
        except urllib.error.HTTPError as error:
            if error.code in (401, 403):
                print(f"Tailscale Funnel HTTPS ready status={error.code}", flush=True)
                return {"ok": True, "status": error.code}
            last_error = f"http_{error.code}"
        except Exception as error:
            last_error = str(error)

        time.sleep(2)

    print(f"Tailscale Funnel HTTPS not ready error={last_error}", flush=True)
    return {"ok": False, "error": last_error or "timeout"}


def run_tailscale_up(auth_key, hostname, enable_funnel):
    print(f"Connecting Tailscale hostname={hostname} funnel={enable_funnel}", flush=True)
    try:
        result = subprocess.run(
            [
                "tailscale",
                "up",
                "--authkey", auth_key,
                "--hostname", hostname,
                "--accept-dns=true"
            ],
            capture_output=True,
            text=True,
            timeout=60
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "status": 504,
            "error": "tailscale_up_timeout"
        }

    print(f"tailscale up finished rc={result.returncode}", flush=True)
    if result.returncode != 0:
        return {
            "ok": False,
            "status": 500,
            "error": result.stderr or result.stdout or "tailscale_up_failed"
        }

    return {"ok": True}


def reset_tailscale_login():
    print("Resetting stale Tailscale login", flush=True)
    try:
        result = subprocess.run(
            ["tailscale", "logout"],
            capture_output=True,
            text=True,
            timeout=30
        )
        print(f"tailscale logout finished rc={result.returncode}", flush=True)
    except subprocess.TimeoutExpired:
        print("tailscale logout timed out", flush=True)


def enable_tailscale_funnel(funnel_target):
    print(f"Enabling Tailscale Funnel target={funnel_target}", flush=True)
    try:
        result = subprocess.run(
            [
                "tailscale",
                "funnel",
                "--https=443",
                "--bg",
                "--yes",
                funnel_target
            ],
            capture_output=True,
            text=True,
            timeout=60
        )
    except subprocess.TimeoutExpired:
        status_result = subprocess.run(
            ["tailscale", "funnel", "status", "--json"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return {
            "ok": False,
            "status": 504,
            "error": "tailscale_funnel_timeout",
            "funnel_status": status_result.stdout or None,
            "funnel_status_error": status_result.stderr or None
        }

    print(f"tailscale funnel finished rc={result.returncode}", flush=True)
    if result.returncode != 0:
        return {
            "ok": False,
            "status": 500,
            "error": result.stderr or result.stdout or "failed_to_enable_funnel"
        }

    return {"ok": True}


def read_tailscale_ip():
    result = subprocess.run(
        ["tailscale", "ip", "-4"],
        capture_output=True,
        text=True,
        timeout=10
    )
    lines = result.stdout.strip().splitlines()
    return lines[0] if lines else None


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


def get_or_create_server_id():
    try:
        with open(SERVER_ID_FILE, "r", encoding="utf-8") as file:
            value = file.read().strip()
            if value:
                return value
    except FileNotFoundError:
        pass

    value = f"srv_{uuid.uuid4().hex[:12]}"
    store_server_id(value)
    return value


def remote_url_file():
    return "/data/besmart_remote_url"


def store_remote_url(url):
    os.makedirs(os.path.dirname(remote_url_file()), exist_ok=True)
    with open(remote_url_file(), "w", encoding="utf-8") as file:
        file.write(str(url).strip())


def read_remote_url():
    try:
        with open(remote_url_file(), "r", encoding="utf-8") as file:
            return file.read().strip() or None
    except FileNotFoundError:
        return None


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
    dns_name = tailscale_dns_name(read_tailscale_status())
    if not dns_name:
        return None

    return f"https://{dns_name.rstrip('.')}{REMOTE_PREFIX}"


def read_tailscale_status():
    result = subprocess.run(
        ["tailscale", "status", "--json"],
        capture_output=True,
        text=True
    )
    if result.returncode != 0 or not result.stdout:
        return None

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def tailscale_is_running(status_data):
    return bool(status_data and status_data.get("BackendState") == "Running" and tailscale_dns_name(status_data))


def tailscale_dns_name(status_data):
    if not status_data:
        return None

    dns_name = status_data.get("Self", {}).get("DNSName")
    return dns_name or None


print(f"BeSmart Companion listening on port {PORT}")
server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
server.serve_forever()
