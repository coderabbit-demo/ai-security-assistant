import datetime
import importlib
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import bcrypt
import jwt


ROOT = Path(__file__).resolve().parents[1]


class SigningKeyConfigurationTests(unittest.TestCase):
    def test_application_refuses_missing_or_weak_keys(self):
        for value in (None, "", "short", "x" * 31, " " * 64):
            with self.subTest(value=value):
                environment = os.environ.copy()
                environment.pop("JWT_SECRET", None)
                if value is not None:
                    environment["JWT_SECRET"] = value
                result = subprocess.run(
                    [sys.executable, "-c", "import app"],
                    cwd=ROOT, env=environment, capture_output=True, text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("JWT_SECRET must be configured", result.stderr)


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.key = secrets.token_hex(32)
        self.addCleanup(patch.stopall)
        patch.dict(os.environ, {"JWT_SECRET": self.key}).start()
        patch.dict(sys.modules).start()
        for module in ("app", "auth", "config"):
            sys.modules.pop(module, None)
        self.auth = importlib.import_module("auth")

    def test_tokens_use_the_configured_key(self):
        token = self.auth.generate_token(42)
        self.assertEqual(jwt.decode(token, self.key, algorithms=["HS256"])["user_id"], 42)
        self.assertEqual(self.auth.verify_token(token), {"id": 42})
        # Environment changes do not silently change a running worker's key.
        with patch.dict(os.environ, {"JWT_SECRET": secrets.token_hex(32)}):
            self.assertEqual(self.auth.verify_token(token), {"id": 42})

    def test_rotation_invalidates_previous_tokens(self):
        token = self.auth.generate_token(42)
        with patch.dict(os.environ, {"JWT_SECRET": secrets.token_hex(32)}):
            importlib.reload(sys.modules["config"])
            importlib.reload(self.auth)
        self.assertIsNone(self.auth.verify_token(token))
        self.assertEqual(self.auth.verify_token(self.auth.generate_token(42)), {"id": 42})

    def test_exposed_keys_cannot_access_protected_routes(self):
        app_module = importlib.import_module("app")
        client = app_module.app.test_client()
        exposed_keys = (
            "super-secret-jwt-key-change-in-production",
            "p@ssw0rd-jwt-d0-n0t-sh@re",
        )
        for key in exposed_keys:
            forged = jwt.encode(
                {"user_id": 42, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
                key, algorithm="HS256",
            )
            self.assertIsNone(self.auth.verify_token(forged))
            with patch.object(app_module, "get_db_connection") as connect:
                response = client.get("/incidents", headers={"Authorization": "Bearer " + forged})
                self.assertEqual(response.status_code, 401)
                connect.assert_not_called()
            with patch.object(app_module, "scan_incident") as scan:
                response = client.post(
                    "/scan", json={"incident": "test"},
                    headers={"Authorization": "Bearer " + forged},
                )
                self.assertEqual(response.status_code, 401)
                scan.assert_not_called()

    def test_login_and_authenticated_scan(self):
        app_module = importlib.import_module("app")
        db = importlib.import_module("db")
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(db, "DB_PATH", str(Path(directory) / "test.db")):
                db.init_db()
                with db.get_db_connection() as connection:
                    connection.execute(
                        "INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
                        (42, "analyst", bcrypt.hashpw(b"test-password", bcrypt.gensalt()).decode()),
                    )
                client = app_module.app.test_client()
                response = client.post("/login", json={"username": "analyst", "password": "test-password"})
                self.assertEqual(response.status_code, 200)
                token = response.get_json()["token"]
                self.assertEqual(self.auth.verify_token(token), {"id": 42})
                response = client.post(
                    "/scan", json={"incident": "nmap port scan"},
                    headers={"Authorization": "Bearer " + token},
                )
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.get_json()["result"]["severity"], "medium")

    def test_expired_malformed_and_wrong_algorithm_tokens_are_rejected(self):
        expired = jwt.encode(
            {"user_id": 42, "exp": datetime.datetime.utcnow() - datetime.timedelta(seconds=1)},
            self.key, algorithm="HS256",
        )
        other_algorithm = jwt.encode({"user_id": 42}, self.key, algorithm="HS384")
        for token in (expired, other_algorithm, "invalid", ""):
            with self.subTest(token_kind=token.split(".")[0]):
                self.assertIsNone(self.auth.verify_token(token))


if __name__ == "__main__":
    unittest.main()
