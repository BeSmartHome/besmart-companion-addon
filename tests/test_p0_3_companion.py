import json
import os
import tempfile
import threading
import time
import unittest
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat, load_der_public_key
from cryptography.exceptions import InvalidSignature

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "besmart_companion"))
import app


class CompanionP03Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.data_dir = self.tmp.name
        self._patch_paths(self.data_dir)
        self._patch_tailscale()
        os.environ.pop("BESMART_BACKEND_SIGNING_PUBLIC_KEY", None)

    def tearDown(self):
        os.environ.pop("BESMART_BACKEND_SIGNING_PUBLIC_KEY", None)
        self.tmp.cleanup()

    def test_legacy_state_is_preserved_by_identity_creation(self):
        Path(app.REMOTE_TOKEN_FILE).write_text("existing-token", encoding="utf-8")
        Path(app.SERVER_ID_FILE).write_text("srv_existing", encoding="utf-8")
        Path(app.REMOTE_URL_FILE).write_text("https://existing.example/remote/ha", encoding="utf-8")

        identity = app.ensure_companion_identity()

        self.assertEqual(Path(app.REMOTE_TOKEN_FILE).read_text(encoding="utf-8"), "existing-token")
        self.assertEqual(Path(app.SERVER_ID_FILE).read_text(encoding="utf-8"), "srv_existing")
        self.assertEqual(Path(app.REMOTE_URL_FILE).read_text(encoding="utf-8"), "https://existing.example/remote/ha")
        self.assertIn("companion_id", identity)

    def test_identity_persists_and_private_keys_are_not_returned(self):
        with self._server() as base_url:
            first = self._request_json("GET", base_url, "/identity")
            second = self._request_json("GET", base_url, "/identity")

        self.assertEqual(first[0], 200)
        self.assertEqual(first[1]["companion_id"], second[1]["companion_id"])
        self.assertIn("signing_public_key", first[1])
        self.assertIn("encryption_public_key", first[1])
        self.assertIn("runtime_instance_id", first[1])
        self.assertIn("runtime_started_at", first[1])
        self.assertEqual(first[1]["runtime_instance_id"], second[1]["runtime_instance_id"])
        self.assertNotIn("signing_private_key", first[1])
        self.assertNotIn("encryption_private_key", first[1])

    def test_e2ee_identity_route_is_exposed_by_addon_runtime(self):
        with self._server() as base_url:
            status, body = self._request_json("GET", base_url, "/security/e2ee/identity")

        self.assertEqual(status, 200)
        self.assertEqual(body["protocol_version"], 1)
        self.assertEqual(body["key_version"], 1)
        self.assertIn("companion_public_key", body)
        self.assertNotIn("private_key", body)

    def test_e2ee_pairing_authorization_status_exposes_only_safe_runtime_state(self):
        self._write_options({
            "e2ee_pairing_authorization": {
                "token": "local-pairing-token",
                "expires_at": app.iso_from_now(120)
            }
        })

        with self._server() as base_url:
            status, body = self._request_json("GET", base_url, "/security/e2ee/pairing-authorization")

        self.assertEqual(status, 200)
        self.assertEqual(body["protocol_version"], 1)
        self.assertTrue(body["configured"])
        self.assertEqual(body["token_fingerprint"], app.token_fingerprint("local-pairing-token"))
        self.assertTrue(body["expires_parse_success"])
        self.assertFalse(body["expired"])
        self.assertNotIn("token", body)

    def test_e2ee_pair_and_revoke_fail_closed_without_local_authorization(self):
        with self._server() as base_url:
            pair_status, pair_body = self._request_json("POST", base_url, "/security/e2ee/pair", {})
            revoke_status, revoke_body = self._request_json("POST", base_url, "/security/e2ee/revoke", {})

        self.assertEqual(pair_status, 401)
        self.assertEqual(pair_body["error"], "local_pairing_authorization_required")
        self.assertEqual(revoke_status, 401)
        self.assertEqual(revoke_body["error"], "local_pairing_authorization_required")

    def test_e2ee_pair_persists_record_and_consumes_local_authorization(self):
        device_private = x25519.X25519PrivateKey.generate()
        device_public = app.base64url_encode(device_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        self._write_options({
            "e2ee_pairing_authorization": {
                "token": "local-pairing-token",
                "expires_at": app.iso_from_now(120)
            }
        })

        with self._server() as base_url:
            status, body = self._request_json("POST", base_url, "/security/e2ee/pair", {
                "protocol_version": 1,
                "home_id": "11111111-1111-4111-8111-111111111111",
                "device_id": "22222222-2222-4222-8222-222222222222",
                "device_public_key": device_public,
                "key_version": 1
            }, headers={"X-SoSync-Local-Pairing-Token": "local-pairing-token"})

        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "active")
        self.assertEqual(body["device_id"], "22222222-2222-4222-8222-222222222222")
        pairings = json.loads(Path(app.E2EE_PAIRINGS_FILE).read_text(encoding="utf-8"))
        self.assertEqual(pairings["devices"]["22222222-2222-4222-8222-222222222222"]["status"], "active")
        options = json.loads(Path(app.ADDON_OPTIONS_FILE).read_text(encoding="utf-8"))
        self.assertNotIn("e2ee_pairing_authorization", options)

    def test_e2ee_pair_authorization_rejects_expired_token(self):
        device_private = x25519.X25519PrivateKey.generate()
        device_public = app.base64url_encode(device_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        self._write_options({
            "e2ee_pairing_authorization": {
                "token": "local-pairing-token",
                "expires_at": app.iso_from_now(-1)
            }
        })

        with self._server() as base_url:
            status, body = self._request_json("POST", base_url, "/security/e2ee/pair", {
                "protocol_version": 1,
                "home_id": "11111111-1111-4111-8111-111111111111",
                "device_id": "22222222-2222-4222-8222-222222222222",
                "device_public_key": device_public,
                "key_version": 1
            }, headers={"X-SoSync-Local-Pairing-Token": "local-pairing-token"})

        self.assertEqual(status, 401)
        self.assertEqual(body["error"], "local_pairing_authorization_required")

    def test_addon_package_metadata_exposes_next_version_and_e2ee_schema(self):
        addon_root = Path(__file__).resolve().parents[1] / "besmart_companion"
        config = (addon_root / "config.yaml").read_text(encoding="utf-8")
        dockerfile = (addon_root / "Dockerfile").read_text(encoding="utf-8")
        runtime = (addon_root / "app.py").read_text(encoding="utf-8")

        self.assertIn('version: "1.0.15"', config)
        self.assertIn("e2ee_pairing_authorization", config)
        self.assertIn("COPY app.py /app/app.py", dockerfile)
        self.assertIn("CLOUDFLARED_VERSION=2026.8.2", dockerfile)
        self.assertIn("BESMART_CLOUDFLARED_BIN=/usr/local/bin/cloudflared", dockerfile)
        self.assertIn("SOSYNC_COMPANION_VERSION=1.0.15", dockerfile)
        self.assertIn("SOSYNC_COMPANION_BUILD=1.0.15-secure-remote-dataplane-diag-v1", dockerfile)
        self.assertIn("/usr/local/bin/cloudflared --version", dockerfile)
        self.assertIn('self.path == "/security/e2ee/identity"', runtime)
        self.assertIn('self.path == "/security/e2ee/pair"', runtime)
        self.assertIn('self.path == "/security/e2ee/revoke"', runtime)
        self.assertIn("tunnelCredentialInstalled", runtime)
        self.assertIn("tunnelProcessStarted", runtime)
        self.assertIn("tunnelProcessFailed", runtime)
        self.assertIn("1.0.15-secure-remote-dataplane-diag-v1", runtime)

    def test_health_and_identity_expose_runtime_build_marker(self):
        with self._server() as base_url:
            health_status, health = self._request_json("GET", base_url, "/health")
            identity_status, identity = self._request_json("GET", base_url, "/identity")

        self.assertEqual(health_status, 200)
        self.assertEqual(identity_status, 200)
        self.assertEqual(health["build"], "1.0.15-secure-remote-dataplane-diag-v1")
        self.assertEqual(identity["build"], "1.0.15-secure-remote-dataplane-diag-v1")
        self.assertEqual(health["companion_version"], "1.0.15")
        self.assertIn("cloudflared_available", health)
        self.assertIn("cloudflared_running", health)

    def test_pairing_consume_hashes_secret_signs_receipt_and_rejects_replay(self):
        identity = app.ensure_companion_identity()
        self._write_options({
            "remote_pairing": {
                "protocol_version": 1,
                "pairing_id": "pairing-1",
                "pairing_secret": "pairing-secret",
                "backend_challenge_id": "challenge-1",
                "backend_nonce_hash": "nonce-hash",
                "app_attest_key_id": "app-attest-1",
                "companion_id": identity["companion_id"],
                "expires_at": app.iso_from_now(120)
            }
        })

        with self._server() as base_url:
            wrong_key_status, _ = self._request_json("POST", base_url, "/pairing/consume", {
                "protocol_version": 1,
                "pairing_id": "pairing-1",
                "backend_challenge_id": "challenge-1",
                "app_attest_key_id": "wrong-app-attest"
            })
            status, receipt = self._request_json("POST", base_url, "/pairing/consume", {
                "protocol_version": 1,
                "pairing_id": "pairing-1",
                "backend_challenge_id": "challenge-1",
                "app_attest_key_id": "app-attest-1"
            })
            replay_status, _ = self._request_json("POST", base_url, "/pairing/consume", {
                "protocol_version": 1,
                "pairing_id": "pairing-1",
                "backend_challenge_id": "challenge-1",
                "app_attest_key_id": "app-attest-1"
            })

        self.assertEqual(wrong_key_status, 401)
        self.assertEqual(status, 200)
        public_key = load_der_public_key(app.base64url_decode(identity["signing_public_key"]))
        try:
            public_key.verify(
                app.base64url_decode(receipt["signature"]),
                app.canonical_bytes(app.receipt_canonical_payload(receipt))
            )
        except InvalidSignature:
            self.fail("receipt signature was invalid")

        pairings = json.loads(Path(app.PAIRINGS_FILE).read_text(encoding="utf-8"))
        self.assertNotIn("pairing_secret", pairings["pairing-1"])
        self.assertEqual(pairings["pairing-1"]["status"], "consumed")
        self.assertEqual(replay_status, 404)

    def test_expired_pairing_is_rejected(self):
        identity = app.ensure_companion_identity()
        self._write_options({
            "remote_pairing": {
                "protocol_version": 1,
                "pairing_id": "pairing-expired",
                "pairing_secret": "pairing-secret",
                "backend_challenge_id": "challenge-1",
                "backend_nonce_hash": "nonce-hash",
                "app_attest_key_id": "app-attest-1",
                "companion_id": identity["companion_id"],
                "expires_at": "2020-01-01T00:00:00Z"
            }
        })

        with self._server() as base_url:
            status, body = self._request_json("POST", base_url, "/pairing/consume", {
                "protocol_version": 1,
                "pairing_id": "pairing-expired",
                "backend_challenge_id": "challenge-1",
                "app_attest_key_id": "app-attest-1"
            })

        self.assertEqual(status, 404)
        self.assertEqual(body["error"], "pairing_not_found")

    def test_secure_connect_rejects_raw_auth_key_for_p0_3(self):
        with self._server() as base_url:
            status, body = self._request_json("POST", base_url, "/tailscale/connect", {
                "protocol_version": 1,
                "auth_key": "tskey-raw"
            })

        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "raw_auth_key_rejected")

    def test_secure_connect_rejects_bad_signature_wrong_audience_and_replay(self):
        backend_private = ed25519.Ed25519PrivateKey.generate()
        backend_public = backend_private.public_key()
        os.environ["BESMART_BACKEND_SIGNING_PUBLIC_KEY"] = app.base64url_encode(
            backend_public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        )

        identity = app.ensure_companion_identity()
        app.store_server_id("srv_secure")
        valid_package = self._make_setup_package(identity, backend_private, "srv_secure")
        reused_connect = self._make_setup_package(identity, backend_private, "srv_secure", package_id="pkg-2", connect_id="connect-1")

        tampered = dict(valid_package)
        tampered["server_id"] = "srv_tampered"

        wrong_identity = dict(identity)
        wrong_identity["companion_id"] = "wrong-companion"
        wrong_audience = self._make_setup_package(wrong_identity, backend_private, "srv_secure")

        with self._server() as base_url:
            tampered_status, _ = self._request_json("POST", base_url, "/tailscale/connect", {
                "protocol_version": 1,
                "setup_package": tampered
            })
            audience_status, _ = self._request_json("POST", base_url, "/tailscale/connect", {
                "protocol_version": 1,
                "setup_package": wrong_audience
            })
            first_status, first_body = self._request_json("POST", base_url, "/tailscale/connect", {
                "protocol_version": 1,
                "setup_package": valid_package
            })
            replay_status, _ = self._request_json("POST", base_url, "/tailscale/connect", {
                "protocol_version": 1,
                "setup_package": valid_package
            })
            connect_replay_status, _ = self._request_json("POST", base_url, "/tailscale/connect", {
                "protocol_version": 1,
                "setup_package": reused_connect
            })

        self.assertEqual(tampered_status, 401)
        self.assertEqual(audience_status, 401)
        self.assertEqual(first_status, 200)
        self.assertNotIn("remote_token", first_body)
        self.assertNotIn("tailscale_auth_key", first_body)
        self.assertEqual(Path(app.REMOTE_TOKEN_FILE).read_text(encoding="utf-8"), "secure-token")
        self.assertEqual(replay_status, 409)
        self.assertEqual(connect_replay_status, 409)

    def test_existing_remote_token_proxy_behavior_unchanged(self):
        Path(app.REMOTE_TOKEN_FILE).write_text("expected-token", encoding="utf-8")
        with self._server() as base_url:
            unauthorized, _ = self._request_json("GET", base_url, "/remote/ha/api/states")
            authorized, body = self._request_json(
                "GET",
                base_url,
                "/remote/ha/api/states",
                headers={"X-BeSmart-Remote-Token": "expected-token"}
            )

        self.assertEqual(unauthorized, 401)
        self.assertIn(authorized, (200, 502))
        if authorized == 200:
            self.assertIsInstance(body, dict)

    def test_secure_remote_control_plane_persists_metadata_without_exposing_credentials(self):
        route_id = "r_abcdefghijklmnopqrstuvwxyz123456"
        tunnel_id = "tun_abcdefghijklmnopqrstuvwxyz123456"
        self._patch_cloudflared_start(running=True)
        try:
            with self._server() as base_url:
                identity_status, identity = self._request_json("GET", base_url, "/secure-remote/identity")
                provision_status, provision = self._request_json("POST", base_url, "/secure-remote/provision", {
                    "protocol_version": 1,
                    "route_id": route_id,
                    "tunnel_binding_id": tunnel_id,
                    "home_reference": "home_ref",
                    "device_reference": "device_ref",
                    "device_public_key_fingerprint": "device_fp",
                    "companion_public_key_fingerprint": "companion_key_fp",
                    "companion_identity_fingerprint": "companion_identity_fp",
                    "credential_version": 1
                })
                install_status, install = self._request_json("POST", base_url, "/secure-remote/tunnel/install", {
                    "protocol_version": 1,
                    "route_id": route_id,
                    "credential_version": 1,
                    "tunnel_credential": "secret-tunnel-credential"
                })
                status_code, status = self._request_json("GET", base_url, "/secure-remote/status")
        finally:
            self._restore_cloudflared_start()

        self.assertEqual(identity_status, 200)
        self.assertIn("companion_public_key_fingerprint", identity)
        self.assertEqual(provision_status, 200)
        self.assertEqual(install_status, 200)
        self.assertEqual(status_code, 200)
        self.assertTrue(provision["configured"])
        self.assertTrue(install["tunnel_configured"])
        self.assertTrue(status["tunnel_configured"])
        self.assertEqual(install["tunnel_state"], "running")
        self.assertTrue(install["cloudflared_running"])
        self.assertEqual(status["credential_version"], 1)
        serialized = json.dumps(status)
        self.assertNotIn("secret-tunnel-credential", serialized)
        self.assertNotIn("tunnel_credential", serialized)

    def test_secure_remote_tunnel_install_fails_closed_when_cloudflared_missing(self):
        route_id = "r_abcdefghijklmnopqrstuvwxyz123456"
        tunnel_id = "tun_abcdefghijklmnopqrstuvwxyz123456"
        self._patch_cloudflared_start(missing=True)
        try:
            with self._server() as base_url:
                provision_status, _ = self._request_json("POST", base_url, "/secure-remote/provision", {
                    "protocol_version": 1,
                    "route_id": route_id,
                    "tunnel_binding_id": tunnel_id,
                    "home_reference": "home_ref",
                    "device_reference": "device_ref",
                    "device_public_key_fingerprint": "device_fp",
                    "companion_public_key_fingerprint": "companion_key_fp",
                    "companion_identity_fingerprint": "companion_identity_fp",
                    "credential_version": 1
                })
                install_status, install = self._request_json("POST", base_url, "/secure-remote/tunnel/install", {
                    "protocol_version": 1,
                    "route_id": route_id,
                    "credential_version": 1,
                    "tunnel_credential": "secret-tunnel-credential"
                })
                status_code, status = self._request_json("GET", base_url, "/secure-remote/status")
        finally:
            self._restore_cloudflared_start()

        self.assertEqual(provision_status, 200)
        self.assertEqual(install_status, 503)
        self.assertEqual(status_code, 200)
        self.assertFalse(install["tunnel_configured"])
        self.assertFalse(status["tunnel_configured"])
        self.assertEqual(install["tunnel_state"], "failed")
        self.assertEqual(install["failure_stage"], "binaryLookup")
        self.assertEqual(install["failure_reason"], "cloudflaredMissing")
        serialized = json.dumps(install) + json.dumps(status)
        self.assertNotIn("secret-tunnel-credential", serialized)
        self.assertNotIn("tunnel_credential", serialized)

    def test_secure_remote_tunnel_stderr_sanitizer_redacts_credential_material(self):
        stderr = app.sanitized_secure_remote_tunnel_stderr(
            "cloudflared failed token=secret-tunnel-credential suffix=credential",
            "secret-tunnel-credential"
        )

        self.assertNotIn("secret-tunnel-credential", stderr)
        self.assertNotIn("credential", stderr)
        self.assertIn("[redacted]", stderr)

    def test_secure_remote_tunnel_install_fails_closed_when_process_exits(self):
        route_id = "r_abcdefghijklmnopqrstuvwxyz123456"
        tunnel_id = "tun_abcdefghijklmnopqrstuvwxyz123456"
        self._patch_cloudflared_start(
            running=False,
            stderr_message="cloudflared failed token=secret-tunnel-credential"
        )
        try:
            with self._server() as base_url:
                provision_status, _ = self._request_json("POST", base_url, "/secure-remote/provision", {
                    "protocol_version": 1,
                    "route_id": route_id,
                    "tunnel_binding_id": tunnel_id,
                    "home_reference": "home_ref",
                    "device_reference": "device_ref",
                    "device_public_key_fingerprint": "device_fp",
                    "companion_public_key_fingerprint": "companion_key_fp",
                    "companion_identity_fingerprint": "companion_identity_fp",
                    "credential_version": 1
                })
                install_status, install = self._request_json("POST", base_url, "/secure-remote/tunnel/install", {
                    "protocol_version": 1,
                    "route_id": route_id,
                    "credential_version": 1,
                    "tunnel_credential": "secret-tunnel-credential"
                })
        finally:
            self._restore_cloudflared_start()

        self.assertEqual(provision_status, 200)
        self.assertEqual(install_status, 503)
        self.assertFalse(install["tunnel_configured"])
        self.assertEqual(install["tunnel_state"], "failed")
        self.assertEqual(install["failure_stage"], "immediateExit")

    def test_secure_remote_tunnel_install_fails_closed_when_credential_missing(self):
        route_id = "r_abcdefghijklmnopqrstuvwxyz123456"
        tunnel_id = "tun_abcdefghijklmnopqrstuvwxyz123456"
        with self._server() as base_url:
            provision_status, _ = self._request_json("POST", base_url, "/secure-remote/provision", {
                "protocol_version": 1,
                "route_id": route_id,
                "tunnel_binding_id": tunnel_id,
                "home_reference": "home_ref",
                "device_reference": "device_ref",
                "device_public_key_fingerprint": "device_fp",
                "companion_public_key_fingerprint": "companion_key_fp",
                "companion_identity_fingerprint": "companion_identity_fp",
                "credential_version": 1
            })
            install_status, install = self._request_json("POST", base_url, "/secure-remote/tunnel/install", {
                "protocol_version": 1,
                "route_id": route_id,
                "credential_version": 1
            })

        self.assertEqual(provision_status, 200)
        self.assertEqual(install_status, 503)
        self.assertFalse(install["tunnel_configured"])
        self.assertFalse(install["cloudflared_running"])
        self.assertEqual(install["tunnel_state"], "failed")
        self.assertEqual(install["failure_stage"], "credential")
        self.assertEqual(install["failure_reason"], "credentialMissing")

    def test_secure_remote_tunnel_install_fails_closed_when_process_spawn_raises(self):
        route_id = "r_abcdefghijklmnopqrstuvwxyz123456"
        tunnel_id = "tun_abcdefghijklmnopqrstuvwxyz123456"
        self._patch_cloudflared_start(raise_start=True)
        try:
            with self._server() as base_url:
                provision_status, _ = self._request_json("POST", base_url, "/secure-remote/provision", {
                    "protocol_version": 1,
                    "route_id": route_id,
                    "tunnel_binding_id": tunnel_id,
                    "home_reference": "home_ref",
                    "device_reference": "device_ref",
                    "device_public_key_fingerprint": "device_fp",
                    "companion_public_key_fingerprint": "companion_key_fp",
                    "companion_identity_fingerprint": "companion_identity_fp",
                    "credential_version": 1
                })
                install_status, install = self._request_json("POST", base_url, "/secure-remote/tunnel/install", {
                    "protocol_version": 1,
                    "route_id": route_id,
                    "credential_version": 1,
                    "tunnel_credential": "secret-tunnel-credential"
                })
        finally:
            self._restore_cloudflared_start()

        self.assertEqual(provision_status, 200)
        self.assertEqual(install_status, 503)
        self.assertFalse(install["tunnel_configured"])
        self.assertEqual(install["tunnel_state"], "failed")
        self.assertEqual(install["failure_stage"], "processStart")

    def test_secure_remote_status_corrects_stale_configured_without_process(self):
        binding = app.make_secure_remote_binding({
            "protocol_version": 1,
            "route_id": "r_abcdefghijklmnopqrstuvwxyz123456",
            "tunnel_binding_id": "tun_abcdefghijklmnopqrstuvwxyz123456",
            "home_reference": "home_ref",
            "device_reference": "device_ref",
            "device_public_key_fingerprint": "device_fp",
            "companion_public_key_fingerprint": "companion_key_fp",
            "companion_identity_fingerprint": "companion_identity_fp",
            "credential_version": 1
        })
        binding["tunnel_configured"] = True
        binding["tunnel_state"] = "configured"
        app.write_json_file_secure(app.SECURE_REMOTE_BINDING_FILE, binding)
        app.SECURE_REMOTE_TUNNEL_PROCESS = None

        status = app.secure_remote_public_status()

        self.assertFalse(status["tunnel_configured"])
        self.assertFalse(status["cloudflared_running"])
        self.assertEqual(status["tunnel_state"], "notConfigured")

    def test_secure_remote_tunnel_install_uses_worker_connector_token_mode(self):
        route_id = "r_abcdefghijklmnopqrstuvwxyz123456"
        tunnel_id = "tun_abcdefghijklmnopqrstuvwxyz123456"
        captured = {}
        self._patch_cloudflared_start(running=True, captured=captured)
        try:
            with self._server() as base_url:
                self._request_json("POST", base_url, "/secure-remote/provision", {
                    "protocol_version": 1,
                    "route_id": route_id,
                    "tunnel_binding_id": tunnel_id,
                    "home_reference": "home_ref",
                    "device_reference": "device_ref",
                    "device_public_key_fingerprint": "device_fp",
                    "companion_public_key_fingerprint": "companion_key_fp",
                    "companion_identity_fingerprint": "companion_identity_fp",
                    "credential_version": 1
                })
                install_status, install = self._request_json("POST", base_url, "/secure-remote/tunnel/install", {
                    "protocol_version": 1,
                    "route_id": route_id,
                    "credential_version": 1,
                    "tunnel_credential": "secret-tunnel-credential"
                })
        finally:
            self._restore_cloudflared_start()

        self.assertEqual(install_status, 200)
        self.assertEqual(install["tunnel_state"], "running")
        self.assertEqual(captured["args"][0][-2:], ["--token", "secret-tunnel-credential"])

    def test_secure_remote_rejects_semantic_route_and_stale_rotation(self):
        route_id = "r_abcdefghijklmnopqrstuvwxyz123456"
        with self._server() as base_url:
            bad_status, _ = self._request_json("POST", base_url, "/secure-remote/provision", {
                "protocol_version": 1,
                "route_id": "basjir-home",
                "tunnel_binding_id": "tun_abcdefghijklmnopqrstuvwxyz123456",
                "home_reference": "home_ref",
                "device_reference": "device_ref",
                "device_public_key_fingerprint": "device_fp",
                "companion_public_key_fingerprint": "companion_key_fp",
                "companion_identity_fingerprint": "companion_identity_fp",
                "credential_version": 1
            })
            self._request_json("POST", base_url, "/secure-remote/provision", {
                "protocol_version": 1,
                "route_id": route_id,
                "tunnel_binding_id": "tun_abcdefghijklmnopqrstuvwxyz123456",
                "home_reference": "home_ref",
                "device_reference": "device_ref",
                "device_public_key_fingerprint": "device_fp",
                "companion_public_key_fingerprint": "companion_key_fp",
                "companion_identity_fingerprint": "companion_identity_fp",
                "credential_version": 2
            })
            stale_status, _ = self._request_json("POST", base_url, "/secure-remote/tunnel/rotate", {
                "protocol_version": 1,
                "route_id": route_id,
                "credential_version": 1,
                "tunnel_credential": "stale"
            })

        self.assertEqual(bad_status, 400)
        self.assertEqual(stale_status, 409)

    def _patch_paths(self, data_dir):
        app.DATA_DIR = data_dir
        app.REMOTE_TOKEN_FILE = os.path.join(data_dir, "besmart_remote_token")
        app.HA_UPSTREAM_FILE = os.path.join(data_dir, "besmart_ha_upstream")
        app.SERVER_ID_FILE = os.path.join(data_dir, "besmart_server_id")
        app.REMOTE_URL_FILE = os.path.join(data_dir, "besmart_remote_url")
        app.HOME_PROFILE_FILE = os.path.join(data_dir, "besmart_home_profile.json")
        app.ADDON_OPTIONS_FILE = os.path.join(data_dir, "options.json")
        app.COMPANION_IDENTITY_FILE = os.path.join(data_dir, "besmart_companion_identity.json")
        app.PAIRINGS_FILE = os.path.join(data_dir, "besmart_pairings.json")
        app.E2EE_IDENTITY_FILE = os.path.join(data_dir, "besmart_e2ee_identity.json")
        app.E2EE_PAIRINGS_FILE = os.path.join(data_dir, "besmart_e2ee_pairings.json")
        app.SECURE_REMOTE_BINDING_FILE = os.path.join(data_dir, "besmart_secure_remote_binding.json")
        app.CONSUMED_PACKAGES_FILE = os.path.join(data_dir, "besmart_consumed_setup_packages.json")

    def _patch_tailscale(self):
        app.read_tailscale_status = lambda: {"BackendState": "Running", "Self": {"DNSName": "besmart-home.example.ts.net."}}
        app.read_tailscale_ip = lambda: "100.64.0.1"
        app.run_tailscale_up = lambda auth_key, hostname, enable_funnel: {"ok": True}
        app.enable_tailscale_funnel = lambda target: {"ok": True}

    def _patch_cloudflared_start(self, running=False, missing=False, stderr_message="", captured=None, raise_start=False):
        self._original_shutil_which = app.shutil.which
        self._original_popen = app.subprocess.Popen
        self._original_run = app.subprocess.run
        app.SECURE_REMOTE_TUNNEL_PROCESS = None
        app.shutil.which = lambda binary: None if missing else "/usr/local/bin/cloudflared"
        app.subprocess.run = lambda *args, **kwargs: type("Completed", (), {"returncode": 0, "stdout": "cloudflared version 2026.8.2", "stderr": ""})()

        class FakeProcess:
            pid = 1234

            def poll(self):
                return None if running else 1

            def terminate(self):
                return None

            def wait(self, timeout=None):
                return 0

            def kill(self):
                return None

        def fake_popen(*args, **kwargs):
            if raise_start:
                raise OSError("spawn denied")
            if captured is not None:
                captured["args"] = args
            stderr = kwargs.get("stderr")
            if stderr_message and stderr is not None:
                stderr.write(stderr_message.encode("utf-8"))
                stderr.flush()
            return FakeProcess()

        app.subprocess.Popen = fake_popen

    def _restore_cloudflared_start(self):
        app.SECURE_REMOTE_TUNNEL_PROCESS = None
        if hasattr(self, "_original_shutil_which"):
            app.shutil.which = self._original_shutil_which
        if hasattr(self, "_original_popen"):
            app.subprocess.Popen = self._original_popen
        if hasattr(self, "_original_run"):
            app.subprocess.run = self._original_run

    def _write_options(self, value):
        Path(app.ADDON_OPTIONS_FILE).write_text(json.dumps(value), encoding="utf-8")

    def _make_setup_package(self, identity, backend_private_key, server_id, package_id="pkg-1", connect_id="connect-1"):
        suite = app.hpke_suite()
        recipient = suite.kem.deserialize_public_key(app.base64url_decode(identity["encryption_public_key"]))
        aad = app.canonicalize({
            "protocol_version": 1,
            "package_id": package_id,
            "companion_id": identity["companion_id"],
            "server_id": server_id
        })
        plaintext = {
            "protocol_version": 1,
            "connect_id": connect_id,
            "server_id": server_id,
            "hostname": "besmart-home",
            "tailscale_auth_key": "tskey-secure",
            "tailscale_auth_key_reusable": False,
            "tailscale_auth_key_preauthorized": True,
            "tailscale_auth_key_expires_at": app.iso_from_now(600),
            "remote_token": "secure-token",
            "serve_target_url": "http://127.0.0.1:8765",
            "ha_upstream_url": "http://127.0.0.1:8123",
            "expected_url": "https://besmart-home.example.ts.net/remote/ha",
            "issued_at": app.iso_now(),
            "expires_at": app.iso_from_now(600)
        }
        enc, context = suite.create_sender_context(
            recipient,
            info=app.SETUP_PACKAGE_INFO
        )
        ciphertext = context.seal(
            json.dumps(plaintext, separators=(",", ":")).encode("utf-8"),
            aad=aad.encode("utf-8")
        )
        envelope = {
            "protocol_version": 1,
            "package_id": package_id,
            "companion_id": identity["companion_id"],
            "server_id": server_id,
            "issued_at": app.iso_now(),
            "expires_at": app.iso_from_now(600),
            "encryption_alg": app.SETUP_PACKAGE_ENCRYPTION_ALG,
            "signature_alg": app.SETUP_PACKAGE_SIGNATURE_ALG,
            "encapsulated_key": app.base64url_encode(enc),
            "ciphertext": app.base64url_encode(ciphertext),
            "aad": aad,
            "backend_signature": ""
        }
        envelope["backend_signature"] = app.base64url_encode(
            backend_private_key.sign(app.canonical_bytes(app.envelope_canonical_payload(envelope)))
        )
        return envelope

    class _server:
        def __init__(self_outer):
            self_outer.server = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
            self_outer.thread = threading.Thread(target=self_outer.server.serve_forever, daemon=True)

        def __enter__(self_outer):
            self_outer.thread.start()
            host, port = self_outer.server.server_address
            return f"{host}:{port}"

        def __exit__(self_outer, exc_type, exc, tb):
            self_outer.server.shutdown()
            self_outer.thread.join(timeout=2)

    def _request_json(self, method, base_url, path, body=None, headers=None):
        host, port = base_url.split(":")
        conn = HTTPConnection(host, int(port), timeout=5)
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        request_headers = {"Content-Type": "application/json"}
        if headers:
            request_headers.update(headers)
        conn.request(method, path, body=payload, headers=request_headers)
        response = conn.getresponse()
        raw = response.read()
        response.close()
        conn.close()
        return response.status, json.loads(raw.decode("utf-8") or "{}")


if __name__ == "__main__":
    unittest.main()
