from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import base64
import hashlib
import hmac
import json
import os
import re
import select
import socket
import subprocess
import threading
import time
import uuid
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_der_private_key,
    load_der_public_key,
)
from cryptography.exceptions import InvalidSignature
from pyhpke import AEADId, CipherSuite, KDFId, KEMId

PORT = int(os.environ.get("BESMART_COMPANION_PORT", "8765"))
DEFAULT_HOME_ASSISTANT_URL = "http://127.0.0.1:8123"
DEFAULT_COMPANION_URL = "http://127.0.0.1:8765"
REMOTE_PREFIX = "/remote/ha"
SIGNED_REMOTE_PREFIX = "/remote/signed"
SIGNED_REMOTE_PATTERN = re.compile(r"^/remote/signed/([0-9]{10,})/([A-Za-z0-9_-]{16,})/([A-Za-z0-9_-]{20,})/ha(/.*)?$")
SIGNED_ROUTE_MAX_TTL_SECONDS = 300
DATA_DIR = os.environ.get("BESMART_DATA_DIR", "/data")
REMOTE_TOKEN_FILE = os.path.join(DATA_DIR, "besmart_remote_token")
HA_UPSTREAM_FILE = os.path.join(DATA_DIR, "besmart_ha_upstream")
SERVER_ID_FILE = os.path.join(DATA_DIR, "besmart_server_id")
REMOTE_URL_FILE = os.path.join(DATA_DIR, "besmart_remote_url")
HOME_PROFILE_FILE = os.path.join(DATA_DIR, "besmart_home_profile.json")
ADDON_OPTIONS_FILE = os.path.join(DATA_DIR, "options.json")
COMPANION_IDENTITY_FILE = os.path.join(DATA_DIR, "besmart_companion_identity.json")
PAIRINGS_FILE = os.path.join(DATA_DIR, "besmart_pairings.json")
E2EE_IDENTITY_FILE = os.path.join(DATA_DIR, "besmart_e2ee_identity.json")
E2EE_PAIRINGS_FILE = os.path.join(DATA_DIR, "besmart_e2ee_pairings.json")
CONSUMED_PACKAGES_FILE = os.path.join(DATA_DIR, "besmart_consumed_setup_packages.json")
REMOTE_TOKEN_HEADER = "X-BeSmart-Remote-Token"
HOME_PROFILE_PATH = "/besmart/home-profile"
MAX_HOME_PROFILE_BYTES = 512 * 1024
TAILSCALE_CONNECT_LOCK = threading.Lock()
PAIRING_TTL_SECONDS = 120
E2EE_PROTOCOL_VERSION = 1
SETUP_PACKAGE_INFO = b"besmart-sosync-remote-setup-package-v1"
SETUP_PACKAGE_ENCRYPTION_ALG = "HPKE-X25519-HKDF-SHA256-CHACHA20-POLY1305"
SETUP_PACKAGE_SIGNATURE_ALG = "Ed25519"


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
        if self._reject_public_management_request():
            return

        if self.path.startswith(SIGNED_REMOTE_PREFIX):
            self._proxy_signed_home_assistant()
            return

        if self.path.startswith(REMOTE_PREFIX):
            self._proxy_home_assistant()
            return

        if self.path == HOME_PROFILE_PATH:
            self._handle_home_profile_get()
            return

        if self.path == "/health":
            self._json(200, {
                "status": "ok",
                "service": "besmart-companion"
            })
            return

        if self.path == "/identity":
            identity = ensure_companion_identity()
            self._json(200, {
                "protocol_version": 1,
                "companion_id": identity["companion_id"],
                "companion_instance_id": identity["companion_instance_id"],
                "signing_public_key": identity["signing_public_key"],
                "encryption_public_key": identity["encryption_public_key"],
                "setup_counter": identity.get("setup_counter", 0),
                "minimum_protocol_version": 1,
                "server_id": get_or_create_server_id(),
                "remote_url": read_remote_url(),
                "tailscale_dns_name": tailscale_dns_name(read_tailscale_status())
            })
            return

        if self.path == "/security/e2ee/identity":
            self._handle_e2ee_identity()
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

    def do_PUT(self):
        if self._reject_public_management_request():
            return

        if self.path.startswith(SIGNED_REMOTE_PREFIX):
            self._proxy_signed_home_assistant()
            return

        if self.path == HOME_PROFILE_PATH:
            self._handle_home_profile_put()
            return

        if self.path.startswith(REMOTE_PREFIX):
            self._proxy_home_assistant()
            return

        self._json(404, {"error": "not_found"})

    def do_PATCH(self):
        if self._reject_public_management_request():
            return

        if self.path.startswith(SIGNED_REMOTE_PREFIX):
            self._proxy_signed_home_assistant()
            return

        if self.path.startswith(REMOTE_PREFIX):
            self._proxy_home_assistant()
            return

        self._json(404, {"error": "not_found"})

    def do_DELETE(self):
        if self._reject_public_management_request():
            return

        if self.path.startswith(SIGNED_REMOTE_PREFIX):
            self._proxy_signed_home_assistant()
            return

        if self.path.startswith(REMOTE_PREFIX):
            self._proxy_home_assistant()
            return

        self._json(404, {"error": "not_found"})

    def do_HEAD(self):
        if self._reject_public_management_request():
            return

        if self.path.startswith(SIGNED_REMOTE_PREFIX):
            self._proxy_signed_home_assistant()
            return

        if self.path.startswith(REMOTE_PREFIX):
            self._proxy_home_assistant()
            return

        self.send_response(404)
        self.end_headers()

    def do_OPTIONS(self):
        if self._reject_public_management_request():
            return

        if self.path.startswith(SIGNED_REMOTE_PREFIX):
            self._proxy_signed_home_assistant()
            return

        if self.path.startswith(REMOTE_PREFIX):
            self._proxy_home_assistant()
            return

        self.send_response(204)
        self.send_header("Allow", "GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        if self._reject_public_management_request():
            return

        if self.path.startswith(SIGNED_REMOTE_PREFIX):
            self._proxy_signed_home_assistant()
            return

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

            if data.get("protocol_version") == 1 or data.get("setup_package") is not None:
                self._handle_secure_tailscale_connect(data)
                return

            auth_key = data.get("auth_key")
            server_id = data.get("server_id") or get_or_create_server_id()
            hostname = data.get("hostname", "besmart-home")
            enable_funnel = bool(data.get("enable_funnel", False))
            serve_target_url = normalize_companion_target(data.get("serve_target_url"))
            ha_upstream_url = normalize_ha_upstream(data.get("ha_upstream_url"))
            remote_token = data.get("remote_token")
            rotate_remote_token = bool(data.get("rotate_remote_token", False))
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
                    effective_remote_token = remote_token if rotate_remote_token else (read_remote_token() or remote_token)
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
                    "remote_token_rotated": rotate_remote_token,
                    "remote_ready": False if funnel_url else None,
                    "remote_ready_reason": "public_https_must_be_tested_by_client" if funnel_url else None,
                    "serve_target_url": serve_target_url if enable_funnel else None,
                    "ha_upstream_url": ha_upstream_url if enable_funnel else None
                })
                return
            finally:
                TAILSCALE_CONNECT_LOCK.release()

        if self.path == "/pairing/consume":
            self._handle_pairing_consume()
            return

        if self.path == "/security/e2ee/pair":
            self._handle_e2ee_pair()
            return

        if self.path == "/security/e2ee/revoke":
            self._handle_e2ee_revoke()
            return

        self._json(404, {"error": "not_found"})

    def _handle_e2ee_identity(self):
        identity = ensure_e2ee_identity()
        self._json(200, {
            "protocol_version": E2EE_PROTOCOL_VERSION,
            "companion_public_key": identity["public_key"],
            "key_version": identity["key_version"]
        })

    def _handle_e2ee_pair(self):
        if not has_local_e2ee_pairing_authorization(self.headers):
            self._json(401, {"error": "local_pairing_authorization_required"})
            return

        try:
            data = self._read_json_body(16 * 1024)
        except ValueError as error:
            self._json(400, {"error": str(error)})
            return

        if data.get("protocol_version") != E2EE_PROTOCOL_VERSION:
            self._json(426, {"error": "unsupported_protocol_version"})
            return

        home_id = opaque_e2ee_identifier(data.get("home_id"))
        device_id = opaque_e2ee_identifier(data.get("device_id"))
        device_public_key = normalized_e2ee_public_key(data.get("device_public_key"))
        if not home_id or not device_id or not device_public_key:
            self._json(400, {"error": "invalid_pairing_request"})
            return

        identity = ensure_e2ee_identity()
        pairings = read_e2ee_pairings()
        existing = pairings.get("devices", {}).get(device_id)
        if existing and existing.get("status") == "revoked":
            self._json(403, {"error": "device_revoked"})
            return

        record = make_e2ee_pairing_record(
            home_id=home_id,
            device_id=device_id,
            device_public_key=device_public_key,
            companion_public_key=identity["public_key"],
            key_version=identity["key_version"]
        )
        pairings.setdefault("devices", {})[device_id] = record
        write_json_file_secure(E2EE_PAIRINGS_FILE, pairings)
        clear_e2ee_pairing_authorization()
        print(f"[SOSYNC-E2EE] pairingCompleted deviceID={device_id[:8]}", flush=True)
        print("[SOSYNC-E2EE] pairingPersisted local=false companion=true", flush=True)
        self._json(200, {
            "protocol_version": E2EE_PROTOCOL_VERSION,
            "home_id": record["home_id"],
            "device_id": record["device_id"],
            "companion_public_key": record["companion_public_key"],
            "key_version": record["key_version"],
            "status": record["status"]
        })

    def _handle_e2ee_revoke(self):
        if not has_local_e2ee_pairing_authorization(self.headers):
            self._json(401, {"error": "local_pairing_authorization_required"})
            return

        try:
            data = self._read_json_body(8 * 1024)
        except ValueError as error:
            self._json(400, {"error": str(error)})
            return

        device_id = opaque_e2ee_identifier(data.get("device_id"))
        pairings = read_e2ee_pairings()
        existing = pairings.get("devices", {}).get(device_id) if device_id else None
        if not existing:
            self._json(404, {"error": "pairing_not_found"})
            return

        existing = dict(existing)
        existing["status"] = "revoked"
        existing["revoked_at"] = iso_now()
        pairings.setdefault("devices", {})[device_id] = existing
        write_json_file_secure(E2EE_PAIRINGS_FILE, pairings)
        self._json(200, {
            "protocol_version": E2EE_PROTOCOL_VERSION,
            "device_id": device_id,
            "status": "revoked"
        })

    def _handle_pairing_consume(self):
        try:
            data = self._read_json_body(16 * 1024)
        except ValueError as error:
            self._json(400, {"error": str(error)})
            return

        ingest_remote_pairing_from_supervisor_config()
        pairings = read_json_file(PAIRINGS_FILE, {})
        pairing_id = str(data.get("pairing_id") or "")
        pairing = pairings.get(pairing_id)
        identity = ensure_companion_identity()

        if not pairing or pairing.get("status") != "pending":
            self._json(404, {"error": "pairing_not_found"})
            return

        if is_expired_iso(pairing.get("expires_at")):
            pairing["status"] = "expired"
            write_json_file_secure(PAIRINGS_FILE, pairings)
            self._json(401, {"error": "pairing_expired"})
            return

        if pairing.get("backend_challenge_id") != data.get("backend_challenge_id"):
            self._json(401, {"error": "pairing_challenge_mismatch"})
            return

        if pairing.get("app_attest_key_id") != data.get("app_attest_key_id"):
            self._json(401, {"error": "pairing_app_attest_key_mismatch"})
            return

        if pairing.get("companion_id") != identity.get("companion_id"):
            self._json(401, {"error": "pairing_companion_mismatch"})
            return

        now = iso_now()
        pairing["status"] = "consumed"
        pairing["consumed_at"] = now
        write_json_file_secure(PAIRINGS_FILE, pairings)

        receipt = {
            "protocol_version": 1,
            "pairing_id": pairing["pairing_id"],
            "backend_challenge_id": pairing["backend_challenge_id"],
            "companion_id": identity["companion_id"],
            "companion_instance_id": identity["companion_instance_id"],
            "setup_counter": identity.get("setup_counter", 0),
            "issued_at": now,
            "expires_at": iso_from_now(PAIRING_TTL_SECONDS),
            "pairing_secret_hash": pairing["pairing_secret_hash"],
            "app_attest_key_id": pairing["app_attest_key_id"],
            "backend_nonce_hash": pairing["backend_nonce_hash"],
            "signature": ""
        }
        receipt["signature"] = sign_ed25519_base64url(
            identity["signing_private_key"],
            canonical_bytes(receipt_canonical_payload(receipt))
        )
        self._json(200, receipt)

    def _handle_secure_tailscale_connect(self, data):
        if data.get("auth_key"):
            self._json(400, {"ok": False, "error": "raw_auth_key_rejected"})
            return

        setup_package = data.get("setup_package")
        if not isinstance(setup_package, dict):
            self._json(400, {"ok": False, "error": "missing_setup_package"})
            return

        backend_public_key = read_backend_public_key()
        if not backend_public_key:
            self._json(500, {"ok": False, "error": "missing_backend_verification_key"})
            return

        if not TAILSCALE_CONNECT_LOCK.acquire(blocking=False):
            self._json(409, {"ok": False, "error": "tailscale_connect_in_progress", "url": read_remote_url()})
            return

        try:
            identity = ensure_companion_identity()
            consumed = read_consumed_packages()
            package_id = str(setup_package.get("package_id") or "")
            if not package_id:
                self._json(400, {"ok": False, "error": "missing_package_id"})
                return
            if consumed.get("package_ids", {}).get(package_id):
                self._json(409, {"ok": False, "error": "setup_package_reused"})
                return

            if not verify_setup_package_envelope(setup_package, backend_public_key):
                self._json(401, {"ok": False, "error": "invalid_setup_package_signature"})
                return

            if setup_package.get("companion_id") != identity.get("companion_id"):
                self._json(401, {"ok": False, "error": "setup_package_audience_mismatch"})
                return

            if is_expired_iso(setup_package.get("expires_at")):
                self._json(401, {"ok": False, "error": "setup_package_expired"})
                return

            try:
                plaintext = decrypt_setup_package(setup_package, identity["encryption_private_key"])
            except Exception:
                self._json(401, {"ok": False, "error": "setup_package_decryption_failed"})
                return

            server_id = str(plaintext.get("server_id") or "")
            current_server_id = get_or_create_server_id()
            if setup_package.get("server_id") != server_id or (current_server_id and current_server_id != server_id):
                self._json(401, {"ok": False, "error": "setup_package_server_mismatch"})
                return

            connect_id = str(plaintext.get("connect_id") or "")
            if not connect_id:
                self._json(400, {"ok": False, "error": "missing_connect_id"})
                return
            if consumed.get("connect_ids", {}).get(connect_id):
                self._json(409, {"ok": False, "error": "connect_id_reused"})
                return

            if is_expired_iso(plaintext.get("expires_at")) or is_expired_iso(plaintext.get("tailscale_auth_key_expires_at")):
                self._json(401, {"ok": False, "error": "setup_package_payload_expired"})
                return

            auth_key = str(plaintext.get("tailscale_auth_key") or "")
            remote_token = str(plaintext.get("remote_token") or "")
            hostname = sanitize_hostname(plaintext.get("hostname") or "besmart-home")
            expected_url = str(plaintext.get("expected_url") or "")
            serve_target_url = normalize_companion_target(plaintext.get("serve_target_url"))
            ha_upstream_url = normalize_ha_upstream(plaintext.get("ha_upstream_url"))

            if (
                not auth_key or
                not remote_token or
                not hostname or
                plaintext.get("tailscale_auth_key_reusable") is not False or
                plaintext.get("tailscale_auth_key_preauthorized") is not True
            ):
                self._json(400, {"ok": False, "error": "invalid_setup_package_payload"})
                return

            current_status = read_tailscale_status()
            reused_existing_login = tailscale_is_running(current_status)
            if reused_existing_login:
                print(f"Reusing existing Tailscale login dns={tailscale_dns_name(current_status)}", flush=True)
            else:
                up_result = run_tailscale_up(auth_key, hostname, True)
                if not up_result.get("ok"):
                    self._json(up_result.get("status", 500), {"ok": False, "error": up_result.get("error", "tailscale_up_failed")})
                    return

            ip = read_tailscale_ip()
            store_server_id(server_id)
            store_ha_upstream(ha_upstream_url)
            funnel_target = str(urlparse(serve_target_url).port or PORT)
            funnel_result = enable_tailscale_funnel(funnel_target)
            if not funnel_result.get("ok"):
                self._json(funnel_result.get("status", 500), {"ok": False, "error": funnel_result.get("error", "failed_to_enable_funnel")})
                return

            funnel_url = tailscale_dns_url() or expected_url or read_remote_url()
            if funnel_url:
                store_remote_url(funnel_url)
                print(f"Tailscale Funnel configured url={funnel_url}", flush=True)

            store_remote_token(remote_token)
            consumed.setdefault("package_ids", {})[package_id] = iso_now()
            consumed.setdefault("connect_ids", {})[connect_id] = iso_now()
            write_json_file_secure(CONSUMED_PACKAGES_FILE, consumed)
            identity["setup_counter"] = int(identity.get("setup_counter") or 0) + 1
            write_json_file_secure(COMPANION_IDENTITY_FILE, identity)

            self._json(200, {
                "protocol_version": 1,
                "status": "registered",
                "server_id": server_id,
                "url": funnel_url or (f"http://{ip}:8123" if ip else None),
                "remote_token_fingerprint": remote_token_fingerprint(remote_token)
            })
        finally:
            TAILSCALE_CONNECT_LOCK.release()

    def _reject_public_management_request(self):
        if self.path.startswith(REMOTE_PREFIX):
            return False
        if self.path.startswith(SIGNED_REMOTE_PREFIX):
            return False
        if self.path == HOME_PROFILE_PATH:
            return False

        if is_public_funnel_host(self.headers.get("Host", "")):
            self._json(404, {"error": "not_found"})
            return True

        return False

    def _handle_home_profile_get(self):
        if not self._is_authorized_companion_request():
            self._json(401, {"error": "unauthorized"})
            return

        profile = read_home_profile()
        if not profile:
            self._json(404, {"error": "profile_not_found"})
            return

        self._json(200, profile)

    def _handle_home_profile_put(self):
        if not self._is_authorized_companion_request():
            self._json(401, {"error": "unauthorized"})
            return

        try:
            profile = self._read_json_body(MAX_HOME_PROFILE_BYTES)
        except ValueError as error:
            self._json(400, {"error": str(error)})
            return

        if not is_valid_home_profile(profile):
            self._json(400, {"error": "invalid_home_profile"})
            return

        store_home_profile(profile)
        self._json(200, {
            "ok": True,
            "updated_at": profile.get("updatedAt")
        })

    def _proxy_home_assistant(self):
        stored_token = read_remote_token()
        request_token = self.headers.get(REMOTE_TOKEN_HEADER)
        if not stored_token or not request_token or request_token != stored_token:
            self._json(401, {"error": "unauthorized"})
            return

        parsed_remote_path = urlparse(self.path)
        ha_path = parsed_remote_path.path[len(REMOTE_PREFIX):] or "/"

        is_oauth_token_refresh = (
            ha_path == "/auth/token"
            and self.command == "POST"
        )

        if not is_allowed_ha_path(ha_path) and not is_oauth_token_refresh:
            self._json(403, {"error": "route_not_allowed"})
            return

        self._proxy_home_assistant_path(ha_path, parsed_remote_path.query)

    def _proxy_signed_home_assistant(self):
        parsed_remote_path = urlparse(self.path)
        signed_route = validate_signed_remote_route(parsed_remote_path.path)
        if not signed_route.get("ok"):
            print(f"[REMOTE-HTTP] signedRouteRejected reason={signed_route.get('error')}", flush=True)
            self._json(signed_route.get("status", 401), {"error": signed_route.get("error", "unauthorized")})
            return

        ha_path = signed_route["ha_path"]
        if not is_allowed_ha_path(ha_path):
            self._json(403, {"error": "forbidden"})
            return

        if is_websocket_upgrade(self.headers):
            print(f"[REMOTE-WS] upgradePath={sanitize_signed_path(parsed_remote_path.path)}", flush=True)
            print("[REMOTE-WS] signatureValid=true", flush=True)
            print(f"[REMOTE-WS] upstreamPath={ha_path}", flush=True)
        else:
            print(f"[REMOTE-HTTP] signedRouteAccepted upstreamPath={ha_path}", flush=True)

        self._proxy_home_assistant_path(ha_path, parsed_remote_path.query)

    def _proxy_home_assistant_path(self, ha_path, query):
        if is_websocket_upgrade(self.headers):
            self._proxy_home_assistant_websocket(ha_path, query)
            return

        target_url = f"{read_ha_upstream()}{ha_path}"
        if query:
            target_url = f"{target_url}?{query}"
        body = None
        if self.command in ("POST", "PUT", "PATCH", "DELETE"):
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length > 0 else None

        headers = {}
        for header in ("Authorization", "Content-Type", "Accept", "User-Agent"):
            value = self.headers.get(header)
            if value:
                headers[header] = value

        print(
            f"[REMOTE-HTTP] method={self.command} route=ha upstreamPath={sanitize_ha_path_for_log(ha_path)}",
            flush=True
        )

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
                if self.command != "HEAD":
                    self.wfile.write(response_body)
                print(
                    f"[REMOTE-HTTP] method={self.command} upstreamStatus={response.status} upstreamPath={sanitize_ha_path_for_log(ha_path)}",
                    flush=True
                )
        except urllib.error.HTTPError as error:
            response_body = error.read()
            self.send_response(error.code)
            self.send_header("Content-Type", error.headers.get("Content-Type", "application/json"))
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(response_body)
            print(
                f"[REMOTE-HTTP] method={self.command} upstreamStatus={error.code} upstreamPath={sanitize_ha_path_for_log(ha_path)}",
                flush=True
            )
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
            print(f"[REMOTE-WS] proxy upstreamPath={ha_path}", flush=True)
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

                print("[REMOTE-WS] upgradeAccepted", flush=True)
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

    def _read_json_body(self, max_bytes):
        length = int(self.headers.get("Content-Length", "0"))
        if length > max_bytes:
            raise ValueError("payload_too_large")

        body = self.rfile.read(length) if length > 0 else b"{}"
        try:
            return json.loads(body.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            raise ValueError("invalid_json")

    def _is_authorized_companion_request(self):
        stored_token = read_remote_token()
        if not stored_token:
            return True

        request_token = self.headers.get(REMOTE_TOKEN_HEADER)
        if request_token == stored_token:
            return True

        return is_local_client(self.client_address[0])


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
        "/api/config",
        "/api/states",
        "/api/services",
        "/api/websocket",
        "/api/config/energy"
    }
    allowed_prefixes = (
        "/api/config/automation/config/",
        "/api/config/config_entries",
        "/api/hassio/",
        "/api/history/period/",
        "/api/states/",
        "/api/services/"
    )

    if path in allowed_exact:
        return True

    return any(path.startswith(prefix) for prefix in allowed_prefixes)


def validate_signed_remote_route(path):
    match = SIGNED_REMOTE_PATTERN.match(path)
    if not match:
        return {"ok": False, "status": 404, "error": "signed_route_not_found"}

    stored_token = read_remote_token()
    if not stored_token:
        return {"ok": False, "status": 401, "error": "remote_token_missing"}

    expires_raw, nonce, signature, ha_path = match.groups()
    try:
        expires_at = int(expires_raw)
    except ValueError:
        return {"ok": False, "status": 401, "error": "invalid_expiry"}

    now = int(time.time())
    if expires_at < now:
        return {"ok": False, "status": 401, "error": "signed_route_expired"}

    if expires_at - now > SIGNED_ROUTE_MAX_TTL_SECONDS:
        return {"ok": False, "status": 401, "error": "signed_route_ttl_too_long"}

    signature_input = f"{expires_at}.{nonce}".encode("utf-8")
    digest = hmac.new(stored_token.encode("utf-8"), signature_input, hashlib.sha256).digest()
    expected_signature = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")
    if not hmac.compare_digest(signature, expected_signature):
        return {"ok": False, "status": 401, "error": "invalid_signature"}

    return {
        "ok": True,
        "ha_path": ha_path or "/"
    }


def sanitize_signed_path(path):
    return SIGNED_REMOTE_PATTERN.sub(
        "/remote/signed/<expires>/<nonce>/<signature>/ha\\4",
        path
    )


def sanitize_ha_path_for_log(path):
    return re.sub(r"/[A-Za-z0-9_-]{12,}", "/<id>", path)


def is_websocket_upgrade(headers):
    connection = headers.get("Connection", "")
    upgrade = headers.get("Upgrade", "")
    return "upgrade" in connection.lower() and upgrade.lower() == "websocket"


def is_public_funnel_host(host):
    hostname = str(host or "").split(":", 1)[0].strip().lower().rstrip(".")
    return hostname.endswith(".ts.net")


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


def store_remote_url(url):
    os.makedirs(os.path.dirname(REMOTE_URL_FILE), exist_ok=True)
    with open(REMOTE_URL_FILE, "w", encoding="utf-8") as file:
        file.write(str(url).strip())


def read_remote_url():
    try:
        with open(REMOTE_URL_FILE, "r", encoding="utf-8") as file:
            return file.read().strip() or None
    except FileNotFoundError:
        return None


def read_remote_token():
    try:
        with open(REMOTE_TOKEN_FILE, "r", encoding="utf-8") as file:
            return file.read().strip()
    except FileNotFoundError:
        return None


def ensure_companion_identity():
    identity = read_json_file(COMPANION_IDENTITY_FILE, None)
    if (
        isinstance(identity, dict) and
        identity.get("companion_id") and
        identity.get("companion_instance_id") and
        identity.get("signing_public_key") and
        identity.get("signing_private_key") and
        identity.get("encryption_public_key") and
        identity.get("encryption_private_key")
    ):
        return identity

    signing_private_key = ed25519.Ed25519PrivateKey.generate()
    signing_public_key = signing_private_key.public_key()
    encryption_private_key = x25519.X25519PrivateKey.generate()
    encryption_public_key = encryption_private_key.public_key()

    identity = {
        "protocol_version": 1,
        "companion_id": str(uuid.uuid4()),
        "companion_instance_id": str(uuid.uuid4()),
        "signing_public_key": base64url_encode(signing_public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)),
        "signing_private_key": base64url_encode(signing_private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())),
        "encryption_public_key": base64url_encode(encryption_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)),
        "encryption_private_key": base64url_encode(encryption_private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
        "setup_counter": 0,
        "minimum_protocol_version": 1,
        "created_at": iso_now()
    }
    write_json_file_secure(COMPANION_IDENTITY_FILE, identity)
    return identity


def ensure_e2ee_identity():
    identity = read_json_file(E2EE_IDENTITY_FILE, None)
    if (
        isinstance(identity, dict) and
        identity.get("public_key") and
        identity.get("private_key") and
        identity.get("key_version")
    ):
        return identity

    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    identity = {
        "protocol_version": E2EE_PROTOCOL_VERSION,
        "algorithm": "X25519",
        "public_key": base64url_encode(public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)),
        "private_key": base64url_encode(private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
        "key_version": 1,
        "created_at": iso_now()
    }
    write_json_file_secure(E2EE_IDENTITY_FILE, identity)
    return identity


def read_e2ee_pairings():
    pairings = read_json_file(E2EE_PAIRINGS_FILE, {"devices": {}})
    if not isinstance(pairings, dict):
        return {"devices": {}}
    if not isinstance(pairings.get("devices"), dict):
        pairings["devices"] = {}
    return pairings


def make_e2ee_pairing_record(home_id, device_id, device_public_key, companion_public_key, key_version):
    return {
        "protocol_version": E2EE_PROTOCOL_VERSION,
        "home_id": home_id,
        "device_id": device_id,
        "device_public_key": device_public_key,
        "companion_public_key": companion_public_key,
        "created_at": iso_now(),
        "key_version": key_version,
        "status": "active"
    }


def has_local_e2ee_pairing_authorization(headers):
    options = read_json_file(ADDON_OPTIONS_FILE, {})
    authorization = options.get("e2ee_pairing_authorization") if isinstance(options, dict) else None
    if not isinstance(authorization, dict):
        return False

    expected = str(authorization.get("token") or "").strip()
    expires_at = authorization.get("expires_at")
    if not expected or is_expired_iso(expires_at):
        return False

    received = str(headers.get("X-SoSync-Local-Pairing-Token") or "").strip()
    authorized = bool(received) and hmac.compare_digest(received, expected)
    if authorized:
        print("[SOSYNC-E2EE] pairingAuthorization source=supervisorOptions result=available", flush=True)
    return authorized


def clear_e2ee_pairing_authorization():
    options = read_json_file(ADDON_OPTIONS_FILE, {})
    if not isinstance(options, dict):
        return
    changed = False
    for key in ("e2ee_pairing_authorization", "e2eePairingAuthorization", "localPairingToken", "local_pairing_token"):
        if key in options:
            options.pop(key, None)
            changed = True
    if changed:
        write_json_file_secure(ADDON_OPTIONS_FILE, options)


def opaque_e2ee_identifier(value):
    candidate = str(value or "").strip()
    if re.fullmatch(r"[0-9A-Fa-f-]{16,64}", candidate):
        return candidate
    return ""


def normalized_e2ee_public_key(value):
    candidate = str(value or "").strip()
    try:
        raw = base64url_decode(candidate)
        if len(raw) != 32:
            return ""
        x25519.X25519PublicKey.from_public_bytes(raw)
        return base64url_encode(raw)
    except (ValueError, TypeError):
        return ""


def ingest_remote_pairing_from_supervisor_config():
    options = read_json_file(ADDON_OPTIONS_FILE, {})
    remote_pairing = options.get("remote_pairing") if isinstance(options, dict) else None
    if not isinstance(remote_pairing, dict):
        return

    identity = ensure_companion_identity()
    if remote_pairing.get("companion_id") != identity.get("companion_id") or is_expired_iso(remote_pairing.get("expires_at")):
        options.pop("remote_pairing", None)
        write_json_file_secure(ADDON_OPTIONS_FILE, options)
        return

    pairing_id = str(remote_pairing.get("pairing_id") or "")
    pairing_secret = str(remote_pairing.get("pairing_secret") or "")
    if not pairing_id or not pairing_secret:
        options.pop("remote_pairing", None)
        write_json_file_secure(ADDON_OPTIONS_FILE, options)
        return

    pairings = read_json_file(PAIRINGS_FILE, {})
    if pairing_id not in pairings:
        pairings[pairing_id] = {
            "pairing_id": pairing_id,
            "backend_challenge_id": str(remote_pairing.get("backend_challenge_id") or ""),
            "backend_nonce_hash": str(remote_pairing.get("backend_nonce_hash") or ""),
            "app_attest_key_id": str(remote_pairing.get("app_attest_key_id") or ""),
            "companion_id": str(remote_pairing.get("companion_id") or ""),
            "pairing_secret_hash": sha256_base64url(pairing_secret.encode("utf-8")),
            "created_at": iso_now(),
            "expires_at": str(remote_pairing.get("expires_at") or ""),
            "status": "pending"
        }
        write_json_file_secure(PAIRINGS_FILE, pairings)

    options.pop("remote_pairing", None)
    write_json_file_secure(ADDON_OPTIONS_FILE, options)


def read_consumed_packages():
    consumed = read_json_file(CONSUMED_PACKAGES_FILE, {})
    if not isinstance(consumed, dict):
        consumed = {}
    consumed.setdefault("package_ids", {})
    consumed.setdefault("connect_ids", {})
    return consumed


def read_backend_public_key():
    configured = os.environ.get("BESMART_BACKEND_SIGNING_PUBLIC_KEY", "").strip()
    if configured:
        return configured

    options = read_json_file(ADDON_OPTIONS_FILE, {})
    if isinstance(options, dict):
        return str(options.get("backend_signing_public_key") or "").strip()
    return ""


def verify_setup_package_envelope(envelope, backend_public_key):
    if envelope.get("encryption_alg") != SETUP_PACKAGE_ENCRYPTION_ALG:
        return False
    if envelope.get("signature_alg") != SETUP_PACKAGE_SIGNATURE_ALG:
        return False
    signature = envelope.get("backend_signature")
    if not signature:
        return False
    try:
        public_key = load_der_public_key(base64url_decode(backend_public_key))
        public_key.verify(base64url_decode(signature), canonical_bytes(envelope_canonical_payload(envelope)))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def decrypt_setup_package(envelope, encryption_private_key):
    suite = hpke_suite()
    private_key = suite.kem.deserialize_private_key(base64url_decode(encryption_private_key))
    context = suite.create_recipient_context(
        base64url_decode(envelope.get("encapsulated_key") or ""),
        private_key,
        info=SETUP_PACKAGE_INFO
    )
    plaintext = context.open(
        base64url_decode(envelope.get("ciphertext") or ""),
        aad=str(envelope.get("aad") or "").encode("utf-8")
    )
    return json.loads(plaintext.decode("utf-8"))


def hpke_suite():
    return CipherSuite.new(
        KEMId.DHKEM_X25519_HKDF_SHA256,
        KDFId.HKDF_SHA256,
        AEADId.CHACHA20_POLY1305
    )


def sign_ed25519_base64url(private_key_base64url, payload):
    private_key = load_der_private_key(base64url_decode(private_key_base64url), password=None)
    return base64url_encode(private_key.sign(payload))


def canonical_bytes(value):
    return canonicalize(value).encode("utf-8")


def canonicalize(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int) or isinstance(value, float):
        if isinstance(value, float) and not value.is_integer():
            return json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        return str(int(value))
    if isinstance(value, str):
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(canonicalize(item) for item in value) + "]"
    if isinstance(value, dict):
        items = []
        for key in sorted(value.keys()):
            if value[key] is not None:
                items.append(f"{json.dumps(str(key), separators=(',', ':'), ensure_ascii=False)}:{canonicalize(value[key])}")
        return "{" + ",".join(items) + "}"
    raise ValueError("unsupported_json_value")


def receipt_canonical_payload(receipt):
    return {key: value for key, value in receipt.items() if key != "signature"}


def envelope_canonical_payload(envelope):
    return {key: value for key, value in envelope.items() if key != "backend_signature"}


def read_json_file(path, default):
    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def write_json_file_secure(path, payload):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary_file = f"{path}.tmp"
    with open(temporary_file, "w", encoding="utf-8") as file:
        json.dump(payload, file, separators=(",", ":"))
    os.chmod(temporary_file, 0o600)
    os.replace(temporary_file, path)
    os.chmod(path, 0o600)


def base64url_encode(value):
    return base64.urlsafe_b64encode(value).decode("utf-8").rstrip("=")


def base64url_decode(value):
    normalized = str(value or "").replace("-", "+").replace("_", "/")
    padding = "=" * ((4 - len(normalized) % 4) % 4)
    return base64.b64decode(f"{normalized}{padding}")


def sha256_base64url(value):
    return base64url_encode(hashlib.sha256(value).digest())


def remote_token_fingerprint(remote_token):
    return sha256_base64url(str(remote_token).encode("utf-8"))[:16]


def iso_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def iso_from_now(seconds):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + seconds))


def is_expired_iso(value):
    if not value:
        return True
    try:
        timestamp = time.strptime(str(value).replace(".000Z", "Z"), "%Y-%m-%dT%H:%M:%SZ")
        import calendar
        return calendar.timegm(timestamp) <= time.time()
    except ValueError:
        try:
            normalized = str(value).replace("Z", "+00:00")
            return datetime.fromisoformat(normalized).timestamp() <= datetime.now(timezone.utc).timestamp()
        except Exception:
            return True


def sanitize_hostname(value):
    hostname = re.sub(r"[^a-zA-Z0-9-]", "-", str(value or "").strip().lower())
    hostname = re.sub(r"-+", "-", hostname).strip("-")
    return hostname[:63] or "besmart-home"


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


def store_home_profile(profile):
    os.makedirs(os.path.dirname(HOME_PROFILE_FILE), exist_ok=True)
    temporary_file = f"{HOME_PROFILE_FILE}.tmp"
    with open(temporary_file, "w", encoding="utf-8") as file:
        json.dump(profile, file, separators=(",", ":"))
    os.replace(temporary_file, HOME_PROFILE_FILE)


def read_home_profile():
    try:
        with open(HOME_PROFILE_FILE, "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError:
        return None


def is_valid_home_profile(profile):
    if not isinstance(profile, dict):
        return False
    if profile.get("schemaVersion") != 1:
        return False
    return isinstance(profile.get("values"), dict)


def is_local_client(address):
    return (
        address == "127.0.0.1" or
        address == "::1" or
        address.startswith("10.") or
        address.startswith("192.168.") or
        address.startswith("172.16.") or
        address.startswith("172.17.") or
        address.startswith("172.18.") or
        address.startswith("172.19.") or
        address.startswith("172.20.") or
        address.startswith("172.21.") or
        address.startswith("172.22.") or
        address.startswith("172.23.") or
        address.startswith("172.24.") or
        address.startswith("172.25.") or
        address.startswith("172.26.") or
        address.startswith("172.27.") or
        address.startswith("172.28.") or
        address.startswith("172.29.") or
        address.startswith("172.30.") or
        address.startswith("172.31.")
    )


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


if __name__ == "__main__":
    print(f"BeSmart Companion listening on port {PORT}")
    print("[SOSYNC-E2EE-COMPANION] routesRegistered identity=true pair=true revoke=true protocol=1", flush=True)
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    server.serve_forever()
