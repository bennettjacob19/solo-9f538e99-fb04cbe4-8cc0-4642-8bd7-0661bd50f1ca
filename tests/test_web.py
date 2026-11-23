"""HTTP-level integration tests using Flask's test client.

These exercise the real app stack including the background RotationWorker,
upload parsing, downloads and flash-driven redirects.
"""

import io
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backup_app.config import Config  # noqa: E402
from backup_app.web import create_app  # noqa: E402


def make_config(base: str) -> Config:
    return Config(
        keystore_dir=os.path.join(base, "keystore"),
        volume_dir=os.path.join(base, "volumes"),
        db_path=os.path.join(base, "keystore", "backup.db"),
        rotation_interval=0.05,
        rotation_batch=2,
        max_content_length=1024 * 1024,
        recovery_chunk_size=64 * 1024,
    )


class WebFlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = create_app(make_config(self.tmp.name))
        self.client = self.app.test_client()
        self.svc = self.app.extensions["backup_service"]

    def tearDown(self):
        import threading

        # The worker thread is a daemon; stop it explicitly for clean output.
        for t in threading.enumerate():
            if t.name == "rotation-worker":
                t.request_stop()
                t.join(timeout=2)
        self.tmp.cleanup()

    def test_health_and_index(self):
        self.assertEqual(200, self.client.get("/healthz").status_code)
        page = self.client.get("/")
        self.assertEqual(200, page.status_code)
        self.assertIn("加密备份控制台".encode(), page.data)

    def test_upload_then_download_restores_bytes(self):
        payload = b"web roundtrip\n" * 32
        resp = self.client.post(
            "/backups",
            data={"file": (io.BytesIO(payload), "docs.txt")},
            content_type="multipart/form-data",
            follow_redirects=False,
        )
        self.assertEqual(302, resp.status_code)

        backups = self.svc.list_backups()
        self.assertEqual(1, len(backups))
        bid = backups[0]["id"]

        dl = self.client.get(f"/backups/{bid}/download")
        self.assertEqual(200, dl.status_code)
        self.assertEqual(payload, dl.data)
        self.assertIn("docs.txt", dl.headers["Content-Disposition"])

    def test_rotation_progress_and_key_removal_via_http(self):
        for i in range(4):
            self.client.post(
                "/backups",
                data={"file": (io.BytesIO(f"p{i}".encode() * 16), f"f{i}")},
                content_type="multipart/form-data",
            )

        # Start rotation via HTTP; the background worker drives it to done.
        resp = self.client.post("/rotations")
        self.assertEqual(302, resp.status_code)

        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.svc.current_rotation() is None:
                break
            time.sleep(0.05)
        self.assertIsNone(self.svc.current_rotation(), "worker did not finish rotation")

        keys = self.svc.list_keys()
        retired = next(k["id"] for k in keys if k["state"] == "retired")
        self.assertIn(retired, self.svc.removable_keys())

        # Removal through the real endpoint must redirect (not 500).
        resp = self.client.post(f"/keys/{retired}/remove")
        self.assertEqual(302, resp.status_code)
        self.assertEqual(1, len(self.svc.list_keys()))

        # Every backup is still downloadable with only the new master key.
        for b in self.svc.list_backups():
            dl = self.client.get(f"/backups/{b['id']}/download")
            self.assertEqual(200, dl.status_code)
            self.assertEqual(len(dl.data), 16 * 2)

    def test_starting_second_rotation_is_rejected(self):
        self.svc.start_rotation()
        resp = self.client.post("/rotations", follow_redirects=True)
        self.assertEqual(200, resp.status_code)
        self.assertIn("already in progress".encode(), resp.data)

    def test_download_unknown_id_returns_404(self):
        self.assertEqual(404, self.client.get("/backups/" + "0" * 32 + "/download").status_code)

    def test_upload_without_file_is_rejected(self):
        resp = self.client.post("/backups", data={}, content_type="multipart/form-data")
        self.assertEqual(302, resp.status_code)
        self.assertEqual(0, len(self.svc.list_backups()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
