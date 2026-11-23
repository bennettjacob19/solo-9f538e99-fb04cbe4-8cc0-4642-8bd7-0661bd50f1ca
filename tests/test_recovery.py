"""Service-level tests for recovery credentials and disaster-recovery imports.

Run with the project virtualenv::

    .venv/bin/python -I tests/test_recovery.py
"""

import os
import sys
import threading
import time
import tracemalloc
import unittest
from builtins import open as builtins_open

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backup_app import recovery  # noqa: E402
from backup_app.service import RecoveryExportError  # noqa: E402
from tests.test_service import ServiceTestBase  # noqa: E402


def wait_terminal(svc, job_id, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = svc.get_recovery_job(job_id)
        if job["status"] != "running":
            return job
        time.sleep(0.02)
    raise AssertionError(f"recovery job {job_id} did not finish in time")


class CredentialExportTests(ServiceTestBase):
    def test_credential_roundtrip_open_with_correct_passphrase(self):
        payload = b"disaster recovery payload\n" * 50
        bid = self.upload("docs.txt", payload)
        _, cred = self.svc.export_recovery_credential(bid, "s3cret pass")

        fields = recovery.open_credential("s3cret pass", cred)
        self.assertEqual(bid, fields["backup_id"])
        self.assertEqual("docs.txt", fields["filename"])
        self.assertEqual(len(payload), fields["size_bytes"])
        import hashlib

        self.assertEqual(hashlib.sha256(payload).hexdigest(), fields["sha256"])
        self.assertEqual(32, len(fields["dek"]))

    def test_wrong_passphrase_is_rejected(self):
        bid = self.upload("a", b"aaa")
        _, cred = self.svc.export_recovery_credential(bid, "right one")
        with self.assertRaises(recovery.CredentialError):
            recovery.open_credential("wrong one", cred)

    def test_tampered_credential_is_rejected(self):
        bid = self.upload("a", b"aaa")
        _, cred = self.svc.export_recovery_credential(bid, "pw")
        tampered = bytearray(cred)
        tampered[-1] ^= 0xFF  # flip an authenticated ciphertext byte
        with self.assertRaises(recovery.CredentialError):
            recovery.open_credential("pw", bytes(tampered))

    def test_credential_contains_no_master_key_material(self):
        bid = self.upload("a", b"aaa")
        kek_path = os.path.join(
            self.cfg.keystore_dir, self.svc.list_keys()[0]["id"] + ".kek"
        )
        kek = open(kek_path, "rb").read()
        _, cred = self.svc.export_recovery_credential(bid, "pw")
        self.assertNotIn(kek, cred)

    def test_export_requires_passphrase_and_existing_backup(self):
        bid = self.upload("a", b"aaa")
        with self.assertRaises(RecoveryExportError):
            self.svc.export_recovery_credential(bid, "")
        with self.assertRaises(RecoveryExportError):
            self.svc.export_recovery_credential("0" * 32, "pw")


class DisasterRecoveryTests(ServiceTestBase):
    def _lose_keystore_and_rebuild(self):
        """Simulate keystore-volume loss: keep blobs, wipe keys + DB, new KEK."""
        # Sanity check: blobs survive on the separate backup volume.
        surviving = set(os.listdir(self.cfg.volume_dir))
        self.assertTrue(surviving)
        self.svc.reset_for_keystore_loss()
        self.assertEqual(surviving, set(os.listdir(self.cfg.volume_dir)))
        svc2 = self.svc
        self.assertEqual(0, len(svc2.list_backups()))
        self.assertEqual(1, len(svc2.list_keys()))
        return svc2

    def test_full_recovery_restores_registration_and_download_link(self):
        payload = b"recover me after the keystore burned down" * 100
        bid = self.upload("important.bin", payload)
        _, cred = self.svc.export_recovery_credential(bid, "open sesame")
        blob_before = open(
            os.path.join(self.cfg.volume_dir, bid + ".blob"), "rb"
        ).read()

        svc2 = self._lose_keystore_and_rebuild()
        job_id = svc2.start_recovery_import(cred, "open sesame")
        job = wait_terminal(svc2, job_id)

        self.assertEqual("completed", job["status"])
        self.assertEqual(bid, job["registered_id"])
        self.assertFalse(job["idempotent"])

        backups = svc2.list_backups()
        self.assertEqual(1, len(backups))
        self.assertEqual(bid, backups[0]["id"])
        self.assertEqual("important.bin", backups[0]["filename"])
        # The original ciphertext is preserved byte-for-byte.
        blob_after = open(
            os.path.join(self.cfg.volume_dir, bid + ".blob"), "rb"
        ).read()
        self.assertEqual(blob_before, blob_after)
        # The download link works again under the new master key.
        name, restored = svc2.download_backup(bid)
        self.assertEqual("important.bin", name)
        self.assertEqual(payload, restored)
        active = svc2.list_keys()[0]["id"]
        self.assertEqual([active], backups[0]["kek_ids"])

    def test_wrong_passphrase_import_fails_and_registers_nothing(self):
        bid = self.upload("a", b"aaaa")
        _, cred = self.svc.export_recovery_credential(bid, "pw")
        svc2 = self._lose_keystore_and_rebuild()

        job_id = svc2.start_recovery_import(cred, "nope")
        job = wait_terminal(svc2, job_id)
        self.assertEqual("failed", job["status"])
        self.assertIn("认证失败", job["error"])
        self.assertEqual(0, len(svc2.list_backups()))

    def test_tampered_blob_fails_authentication_and_registers_nothing(self):
        payload = b"x" * 5000
        bid = self.upload("f", payload)
        _, cred = self.svc.export_recovery_credential(bid, "pw")
        # Damage the surviving ciphertext after the "keystore loss".
        path = os.path.join(self.cfg.volume_dir, bid + ".blob")
        with open(path, "r+b") as fh:
            fh.seek(40)
            fh.write(b"\xff" * 8)
        svc2 = self._lose_keystore_and_rebuild()

        job = wait_terminal(svc2, svc2.start_recovery_import(cred, "pw"))
        self.assertEqual("failed", job["status"])
        self.assertIn("认证失败", job["error"])
        self.assertEqual(0, len(svc2.list_backups()))

    def test_digest_mismatch_fails_when_credential_disagrees_with_plaintext(self):
        payload = b"y" * 4096
        bid = self.upload("f", payload)
        _, cred = self.svc.export_recovery_credential(bid, "pw")
        # Forge a credential claiming a different digest; the GCM layer only
        # authenticates the blob, so the digest cross-check must catch this.
        fields = recovery.open_credential("pw", cred)
        fields["sha256"] = "0" * 64
        forged = recovery.seal_credential("pw", fields)
        svc2 = self._lose_keystore_and_rebuild()

        job = wait_terminal(svc2, svc2.start_recovery_import(forged, "pw"))
        self.assertEqual("failed", job["status"])
        self.assertIn("摘要", job["error"])
        self.assertEqual(0, len(svc2.list_backups()))

    def test_missing_blob_fails_cleanly(self):
        bid = self.upload("a", b"aaaa")
        _, cred = self.svc.export_recovery_credential(bid, "pw")
        svc2 = self._lose_keystore_and_rebuild()
        os.remove(os.path.join(self.cfg.volume_dir, bid + ".blob"))
        job = wait_terminal(svc2, svc2.start_recovery_import(cred, "pw"))
        self.assertEqual("failed", job["status"])
        self.assertIn("密文不存在", job["error"])

    def test_reimport_same_credential_is_idempotent_and_returns_original_id(self):
        payload = b"same cred twice" * 64
        bid = self.upload("dup.bin", payload)
        _, cred = self.svc.export_recovery_credential(bid, "pw")
        svc2 = self._lose_keystore_and_rebuild()

        first = wait_terminal(svc2, svc2.start_recovery_import(cred, "pw"))
        self.assertEqual("completed", first["status"])
        second = wait_terminal(svc2, svc2.start_recovery_import(cred, "pw"))
        self.assertEqual("completed", second["status"])
        self.assertTrue(second["idempotent"])
        self.assertEqual(bid, second["registered_id"])
        # No duplicate rows or duplicate wrappers.
        self.assertEqual(1, len(svc2.list_backups()))
        rows = svc2._conn().execute(
            "SELECT COUNT(*) AS n FROM wrapped_keys WHERE backup_id = ?", (bid,)
        ).fetchone()
        self.assertEqual(1, rows["n"])
        self.assertEqual(payload, svc2.download_backup(bid)[1])

    def test_occupied_id_with_different_content_reports_conflict(self):
        import hashlib

        bid = self.upload("original", b"original content" * 32)
        _, cred = self.svc.export_recovery_credential(bid, "pw")
        svc2 = self._lose_keystore_and_rebuild()

        # Simulate the original id being occupied by a *different*
        # registration: insert a squatter row directly with the target id and
        # a distinct digest, wrapped under the new active KEK.
        other = b"totally unrelated content" * 32
        active = svc2.list_keys()[0]
        from backup_app import crypto as crypto_mod

        dek = crypto_mod.generate_key()
        wrapped = crypto_mod.wrap_dek(
            svc2.keystore.load(active["id"]), dek, bid, active["id"]
        )
        blob_path = os.path.join(self.cfg.volume_dir, bid + ".blob")
        with svc2._conn() as conn:
            conn.execute(
                "INSERT INTO backups (id, filename, blob_path, size_bytes,"
                " sha256, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (bid, "squatter.bin", blob_path, len(other),
                 hashlib.sha256(other).hexdigest(), "2020-01-01T00:00:00+00:00"),
            )
            conn.execute(
                "INSERT INTO wrapped_keys (backup_id, kek_id, wrapped_dek, created_at)"
                " VALUES (?, ?, ?, ?)",
                (bid, active["id"], wrapped, "2020-01-01T00:00:00+00:00"),
            )
            conn.commit()

        job = wait_terminal(svc2, svc2.start_recovery_import(cred, "pw"))
        self.assertEqual("conflict", job["status"])
        self.assertIn("已被另一份备份登记占用", job["error"])
        # The squatter registration is untouched (same digest, same filename).
        remaining = svc2.list_backups()
        self.assertEqual(1, len(remaining))
        self.assertEqual("squatter.bin", remaining[0]["filename"])
        self.assertEqual(
            hashlib.sha256(other).hexdigest(), remaining[0]["sha256"]
        )

    def test_blob_is_read_once_and_streaming_memory_is_bounded(self):
        # 3 MiB payload with a tiny chunk size forces many streaming chunks.
        payload = os.urandom(3 * 1024 * 1024)
        bid = self.upload("big.bin", payload)
        _, cred = self.svc.export_recovery_credential(bid, "pw")
        svc2 = self._lose_keystore_and_rebuild()

        real_open = builtins_open
        read_count = {"n": 0}

        def counting_open(path, *args, **kwargs):
            if isinstance(path, str) and path.startswith(self.cfg.volume_dir):
                read_count["n"] += 1
            return real_open(path, *args, **kwargs)

        import builtins
        builtins.open = counting_open
        tracemalloc.start()
        try:
            job = wait_terminal(svc2, svc2.start_recovery_import(cred, "pw"))
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
            builtins.open = real_open

        self.assertEqual("completed", job["status"])
        # Exactly one file handle for the ciphertext body (single pass).
        self.assertEqual(1, read_count["n"])
        # Python-level peak allocations stay far below one whole 15 MiB backup;
        # with 64 KiB chunks only small buffers plus crypto state are held.
        self.assertLess(peak, 4 * 1024 * 1024, f"peak allocations {peak} too high")

    def test_paused_import_lets_other_imports_uploads_downloads_and_rotation_run(self):
        # Four ~1 MiB backups, four concurrent recovery jobs.
        payloads = {f"vol{i}.dat": os.urandom(1024 * 1024 + i * 37) for i in range(4)}
        creds = {}
        bids = {}
        for name, data in payloads.items():
            bid = self.upload(name, data)
            bids[name] = bid
            _, creds[name] = self.svc.export_recovery_credential(bid, "pw")
        svc2 = self._lose_keystore_and_rebuild()

        paused_name = "vol1.dat"
        gate_seen = threading.Event()
        target_id = bids[paused_name]

        def gate(job):
            if job["backup_id"] != target_id:
                return
            gate_seen.set()

            # Wrap the job's pause event: leave the first chunk untouched, then
            # clear the event so the second chunk blocks mid-read.
            original_event = job["_pause_event"]
            calls = {"n": 0}
            original_wait = original_event.wait

            def wait_then_pause(timeout=None):
                calls["n"] += 1
                if calls["n"] == 2:
                    original_event.clear()
                    job["paused"] = True
                return original_wait(timeout)

            original_event.wait = wait_then_pause

        svc2._recovery_gate = gate

        jobs = {
            name: svc2.start_recovery_import(cred, "pw")
            for name, cred in creds.items()
        }
        self.assertTrue(gate_seen.wait(5), "pause gate never fired")

        # The other three imports must complete while one sits paused mid-read.
        deadline = time.monotonic() + 20
        done = set()
        while time.monotonic() < deadline and len(done) < 3:
            for name, job_id in jobs.items():
                if name == paused_name:
                    continue
                job = svc2.get_recovery_job(job_id)
                if job["status"] != "running" and name not in done:
                    self.assertEqual("completed", job["status"])
                    done.add(name)
            time.sleep(0.05)
        self.assertEqual(3, len(done), "three imports should finish while one pauses")

        paused_job = svc2.get_recovery_job(jobs[paused_name])
        self.assertEqual("running", paused_job["status"])
        self.assertTrue(paused_job["paused"])
        self.assertGreater(paused_job["read_bytes"], 0)
        self.assertLess(paused_job["read_bytes"], paused_job["total_bytes"])

        # Meanwhile, ordinary traffic and a full key rotation do not block.
        small_id = svc2.upload_backup("small.txt", b"small file during recovery")
        self.assertEqual(b"small file during recovery",
                         svc2.download_backup(small_id)[1])
        svc2.start_rotation()
        while svc2.current_rotation() is not None:
            svc2.rotation_tick()
        # Rotation can complete and the old key remains removable per the
        # existing rule (every backup has a new-KEK wrapper).
        retired = next(k["id"] for k in svc2.list_keys() if k["state"] == "retired")
        self.assertIn(retired, svc2.removable_keys())

        # Resume the paused import; it finishes and restores the download link.
        svc2.resume_recovery_job(jobs[paused_name])
        final = wait_terminal(svc2, jobs[paused_name])
        self.assertEqual("completed", final["status"])
        self.assertEqual(payloads[paused_name],
                         svc2.download_backup(bids[paused_name])[1])

        # All four original backups are back with their original ids.
        recovered = {b["id"] for b in svc2.list_backups()}
        self.assertTrue(set(bids.values()).issubset(recovered))
        # And removing the old KEK still works after the paused import.
        svc2.remove_key(retired)
        for name, data in payloads.items():
            self.assertEqual(data, svc2.download_backup(bids[name])[1])


if __name__ == "__main__":
    unittest.main(verbosity=2)
