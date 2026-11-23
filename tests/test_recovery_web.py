"""HTTP-level integration tests for recovery-credential export/import.

Drives the real Flask stack including background recovery threads and the
rotation worker.

Run with the project virtualenv::

    .venv/bin/python -I tests/test_recovery_web.py
"""

import io
import os
import sys
import tempfile
import threading
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


def wait_job(svc, job_id, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = svc.get_recovery_job(job_id)
        if job["status"] != "running":
            return job
        time.sleep(0.02)
    raise AssertionError("recovery job did not finish")


class RecoveryWebTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = create_app(make_config(self.tmp.name))
        self.client = self.app.test_client()
        self.svc = self.app.extensions["backup_service"]
        self.cfg = self.app.extensions["backup_service"].config

    def tearDown(self):
        for t in threading.enumerate():
            if t.name in ("rotation-worker",) or t.name.startswith("recovery-"):
                if hasattr(t, "request_stop"):
                    t.request_stop()
        # Give daemon recovery threads a moment to wind down.
        time.sleep(0.05)
        self.tmp.cleanup()

    def _upload(self, name, data):
        before = {b["id"] for b in self.svc.list_backups()}
        resp = self.client.post(
            "/backups",
            data={"file": (io.BytesIO(data), name)},
            content_type="multipart/form-data",
        )
        self.assertEqual(302, resp.status_code)
        new_ids = [b["id"] for b in self.svc.list_backups() if b["id"] not in before]
        self.assertEqual(1, len(new_ids))
        return new_ids[0]

    def _export_credential(self, bid, passphrase):
        resp = self.client.post(
            f"/backups/{bid}/recovery-credential",
            data={"passphrase": passphrase},
        )
        self.assertEqual(200, resp.status_code)
        self.assertIn("attachment", resp.headers["Content-Disposition"])
        self.assertIn(f"recovery-{bid[:8]}", resp.headers["Content-Disposition"])
        return resp.data

    def _lose_keystore(self):
        # Model a replacement keystore volume in place: same Service instance
        # (Flask routes keep their closure), fresh KEK + empty metadata,
        # blobs on the backup volume untouched.
        self.svc.reset_for_keystore_loss()
        self.assertEqual(0, len(self.svc.list_backups()))
        self.assertEqual(1, len(self.svc.list_keys()))

    def test_export_requires_passphrase(self):
        bid = self._upload("a", b"aaa")
        resp = self.client.post(
            f"/backups/{bid}/recovery-credential", data={"passphrase": ""},
            follow_redirects=True,
        )
        self.assertEqual(200, resp.status_code)
        self.assertIn("口令不能为空".encode(), resp.data)

    def test_full_recovery_flow_via_http_restores_download(self):
        payload = b"http-level disaster recovery\n" * 200
        bid = self._upload("report.bin", payload)
        cred = self._export_credential(bid, "p@ss")
        self._lose_keystore()

        resp = self.client.post(
            "/recovery/imports",
            data={
                "credential": (io.BytesIO(cred), "recovery.credential"),
                "passphrase": "p@ss",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(302, resp.status_code)

        jobs = self.client.get("/recovery/imports").get_json()["jobs"]
        self.assertEqual(1, len(jobs))
        job_id = jobs[0]["id"]
        final = wait_job(self.svc, job_id)
        self.assertEqual("completed", final["status"])
        self.assertEqual(bid, final["registered_id"])

        # The JSON status endpoint reflects completion.
        status = self.client.get(f"/recovery/imports/{job_id}").get_json()
        self.assertEqual("completed", status["status"])
        self.assertEqual(status["total_bytes"], status["read_bytes"])

        # Original download link works again with the original id/filename.
        dl = self.client.get(f"/backups/{bid}/download")
        self.assertEqual(200, dl.status_code)
        self.assertEqual(payload, dl.data)
        self.assertIn("report.bin", dl.headers["Content-Disposition"])

        # The index page renders the job panel and the recovered row.
        page = self.client.get("/").data
        self.assertIn("已恢复登记".encode(), page)
        self.assertIn("下载恢复凭据".encode(), page)

    def test_wrong_passphrase_reports_failed_job(self):
        bid = self._upload("a", b"aaaa")
        cred = self._export_credential(bid, "right")
        self._lose_keystore()
        resp = self.client.post(
            "/recovery/imports",
            data={
                "credential": (io.BytesIO(cred), "c.credential"),
                "passphrase": "wrong",
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        self.assertEqual(200, resp.status_code)
        self.assertIn("凭据校验未通过".encode(), resp.data)
        self.assertEqual(0, len(self.svc.list_backups()))

    def test_missing_credential_file_or_passphrase_is_rejected(self):
        resp = self.client.post(
            "/recovery/imports", data={"passphrase": "x"},
            content_type="multipart/form-data",
        )
        self.assertEqual(302, resp.status_code)
        self.assertEqual(0, len(self.svc.list_recovery_jobs()))

        resp = self.client.post(
            "/recovery/imports",
            data={"credential": (io.BytesIO(b"abc"), "c")},
            content_type="multipart/form-data",
        )
        self.assertEqual(302, resp.status_code)
        self.assertEqual(0, len(self.svc.list_recovery_jobs()))

    def test_reimport_same_credential_returns_original_id(self):
        payload = b"duplicate upload" * 128
        bid = self._upload("dup.bin", payload)
        cred = self._export_credential(bid, "pw")
        self._lose_keystore()

        first = wait_job(
            self.svc,
            self.svc.start_recovery_import(cred, "pw"),
        )
        self.assertFalse(first["idempotent"])
        # The first job genuinely created the registration.
        self.assertEqual(bid, first["registered_id"])

        before = {j["id"] for j in self.svc.list_recovery_jobs()}
        resp = self.client.post(
            "/recovery/imports",
            data={
                "credential": (io.BytesIO(cred), "c.credential"),
                "passphrase": "pw",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(302, resp.status_code)
        new_jobs = [
            j for j in self.client.get("/recovery/imports").get_json()["jobs"]
            if j["id"] not in before
        ]
        self.assertEqual(1, len(new_jobs))
        second = wait_job(self.svc, new_jobs[0]["id"])
        self.assertEqual("completed", second["status"])
        # The re-import resolves idempotently against the existing registration
        # and creates no duplicate row or wrapper.
        self.assertTrue(second["idempotent"])
        self.assertEqual(bid, second["registered_id"])
        self.assertEqual(1, len(self.svc.list_backups()))
        wrappers = self.svc._conn().execute(
            "SELECT COUNT(*) AS n FROM wrapped_keys WHERE backup_id = ?", (bid,)
        ).fetchone()
        self.assertEqual(1, wrappers["n"])

    def test_conflict_is_surfaced_as_job_status(self):
        import hashlib

        bid = self._upload("orig", b"original" * 64)
        cred = self._export_credential(bid, "pw")
        self._lose_keystore()

        from backup_app import crypto as crypto_mod

        other = b"different content entirely" * 32
        active = self.svc.list_keys()[0]
        dek = crypto_mod.generate_key()
        wrapped = crypto_mod.wrap_dek(
            self.svc.keystore.load(active["id"]), dek, bid, active["id"]
        )
        with self.svc._conn() as conn:
            conn.execute(
                "INSERT INTO backups (id, filename, blob_path, size_bytes,"
                " sha256, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (bid, "squatter",
                 os.path.join(self.cfg.volume_dir, bid + ".blob"),
                 len(other), hashlib.sha256(other).hexdigest(),
                 "2020-01-01T00:00:00+00:00"),
            )
            conn.execute(
                "INSERT INTO wrapped_keys (backup_id, kek_id, wrapped_dek, created_at)"
                " VALUES (?, ?, ?, ?)",
                (bid, active["id"], wrapped, "2020-01-01T00:00:00+00:00"),
            )
            conn.commit()

        job = wait_job(self.svc, self.svc.start_recovery_import(cred, "pw"))
        self.assertEqual("conflict", job["status"])
        self.assertIn("已被另一份备份登记占用", job["error"])
        # The conflict shows up on the rendered page too.
        page = self.client.get("/").data
        self.assertIn("编号冲突".encode(), page)

    def test_unknown_job_returns_404(self):
        self.assertEqual(404, self.client.get("/recovery/imports/" + "0" * 32).status_code)

    def test_four_concurrent_imports_complete_with_pause_control(self):
        # Four backups ~256 KiB each, imported concurrently; pause one via the
        # HTTP control endpoints and confirm the other three finish first.
        bids, creds = [], {}
        for i in range(4):
            data = (f"backup-{i}-" .encode()) * 40000
            bid = self._upload(f"v{i}.dat", data)
            bids.append(bid)
            creds[bid] = self._export_credential(bid, "pw")
        self._lose_keystore()

        job_ids = {}
        paused_bid = bids[1]
        gate_seen = threading.Event()

        def gate(job):
            # Deterministically hold the chosen job at its first streaming
            # chunk; pause/resume control is still exercised through the HTTP
            # endpoints below.
            if job["backup_id"] != paused_bid:
                return
            gate_seen.set()
            event = job["_pause_event"]
            original_wait = event.wait
            state = {"n": 0}

            def wait_after_first_chunk(timeout=None):
                state["n"] += 1
                if state["n"] == 2:
                    event.clear()
                    job["paused"] = True
                return original_wait(timeout)

            event.wait = wait_after_first_chunk

        self.svc._recovery_gate = gate
        for bid, cred in creds.items():
            job_ids[bid] = self.svc.start_recovery_import(cred, "pw")
        paused_job = job_ids[paused_bid]
        self.assertTrue(gate_seen.wait(10))

        # Observe and confirm the paused state over the HTTP control API.
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            j = self.svc.get_recovery_job(paused_job)
            if j["paused"]:
                break
            time.sleep(0.01)
        r = self.client.post(f"/recovery/imports/{paused_job}/pause")
        self.assertEqual(200, r.status_code)
        self.assertTrue(r.get_json()["paused"])

        # The other three reach completion while the paused one stays running.
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            states = {bid: self.svc.get_recovery_job(jid)["status"]
                      for bid, jid in job_ids.items()}
            if all(states[b] == "completed" for b in bids if b != paused_bid):
                break
            time.sleep(0.05)
        for bid in bids:
            state = self.svc.get_recovery_job(job_ids[bid])["status"]
            if bid == paused_bid:
                self.assertEqual("running", state)
            else:
                self.assertEqual("completed", state)

        # Ordinary small-file traffic proceeds while the job is paused.
        small = self.client.post(
            "/backups",
            data={"file": (io.BytesIO(b"tiny"), "tiny.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(302, small.status_code)

        r = self.client.post(f"/recovery/imports/{paused_job}/resume")
        self.assertEqual(200, r.status_code)
        final = wait_job(self.svc, paused_job)
        self.assertEqual("completed", final["status"])

        # Every original download link is restored with matching bytes.
        for i, bid in enumerate(bids):
            expected = (f"backup-{i}-".encode()) * 40000
            dl = self.client.get(f"/backups/{bid}/download")
            self.assertEqual(200, dl.status_code)
            self.assertEqual(expected, dl.data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
