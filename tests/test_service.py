"""End-to-end tests for the encrypted backup service.

Run with the project virtualenv::

    .venv/bin/python -I -m unittest -v tests.test_service
"""

import os
import sys
import tempfile
import unittest

# Keep the suite usable under ``python -I`` (isolated mode): the tests
# directory's parent is the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backup_app.config import Config  # noqa: E402
from backup_app.service import (  # noqa: E402
    KeyRemovalError,
    RotationInProgress,
    Service,
)


def make_config(base: str) -> Config:
    return Config(
        keystore_dir=os.path.join(base, "keystore"),
        volume_dir=os.path.join(base, "volumes"),
        db_path=os.path.join(base, "keystore", "backup.db"),
        rotation_interval=0.05,
        rotation_batch=2,
        max_content_length=16 * 1024 * 1024,
        recovery_chunk_size=64 * 1024,
    )


class ServiceTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = make_config(self.tmp.name)
        self.svc = Service(self.cfg)

    def tearDown(self):
        self.tmp.cleanup()

    def upload(self, name, content):
        return self.svc.upload_backup(name, content)


class RoundtripTests(ServiceTestBase):
    def test_bootstrap_creates_single_active_kek(self):
        keys = self.svc.list_keys()
        self.assertEqual(1, len(keys))
        self.assertEqual("active", keys[0]["state"])
        # Raw key file exists with restricted permissions; DB holds no keys.
        files = os.listdir(self.cfg.keystore_dir)
        kek_files = [f for f in files if f.endswith(".kek")]
        self.assertEqual(1, len(kek_files))
        mode = os.stat(os.path.join(self.cfg.keystore_dir, kek_files[0])).st_mode & 0o777
        self.assertEqual(0o600, mode)

    def test_upload_download_roundtrip_restores_original(self):
        payload = b"hello encrypted world\n" * 100
        backup_id = self.upload("report.txt", payload)
        filename, restored = self.svc.download_backup(backup_id)
        self.assertEqual("report.txt", filename)
        self.assertEqual(payload, restored)

    def test_each_backup_has_independent_dek_and_distinct_blob(self):
        ids = [self.upload(f"f{i}.dat", b"same content" * 10) for i in range(3)]
        blobs = [
            open(os.path.join(self.cfg.volume_dir, bid + ".blob"), "rb").read()
            for bid in ids
        ]
        # GCM random nonce + unique DEK: identical plaintexts differ on disk.
        self.assertEqual(len(set(blobs)), 3)
        # Every blob lives on the volume, every wrapped DEK on the keystore DB.
        self.assertEqual([], [f for f in os.listdir(self.cfg.keystore_dir) if f.endswith(".blob")])
        self.assertEqual(3, len(os.listdir(self.cfg.volume_dir)))

    def test_tampered_blob_is_rejected(self):
        backup_id = self.upload("f.bin", b"integrity matters")
        path = os.path.join(self.cfg.volume_dir, backup_id + ".blob")
        with open(path, "r+b") as fh:
            fh.seek(-5, os.SEEK_END)
            fh.write(b"XXXXX")
        with self.assertRaises(Exception):
            self.svc.download_backup(backup_id)


class RotationTests(ServiceTestBase):
    def test_rotation_does_not_rewrite_ciphertext_blobs(self):
        payload = b"rotation must not touch my body" * 50
        backup_id = self.upload("body.txt", payload)
        blob_path = os.path.join(self.cfg.volume_dir, backup_id + ".blob")
        before = open(blob_path, "rb").read()
        mtime_before = os.stat(blob_path).st_mtime_ns

        self.svc.start_rotation()
        while self.svc.current_rotation() is not None:
            self.svc.rotation_tick()

        after = open(blob_path, "rb").read()
        self.assertEqual(before, after)
        self.assertEqual(mtime_before, os.stat(blob_path).st_mtime_ns)
        # Still restores perfectly.
        _, restored = self.svc.download_backup(backup_id)
        self.assertEqual(payload, restored)

    def test_full_rotation_wraps_every_backup_with_new_kek(self):
        for i in range(5):
            self.upload(f"f{i}.log", f"payload-{i}".encode() * 20)

        job = self.svc.start_rotation()
        # Drive the worker logic manually in small batches.
        ticks = 0
        while self.svc.current_rotation() is not None:
            self.svc.rotation_tick()
            ticks += 1
            self.assertLess(ticks, 100)

        job_row = self.svc.get_key  # sanity: method exists
        self.assertIsNotNone(job_row)
        keys = {k["id"]: k for k in self.svc.list_keys()}
        self.assertEqual(2, len(keys))
        active = [k for k in keys.values() if k["state"] == "active"]
        retired = [k for k in keys.values() if k["state"] == "retired"]
        self.assertEqual(1, len(active))
        self.assertEqual(1, len(retired))

        # Each backup is recoverable under BOTH KEKs while the old file exists.
        for b in self.svc.list_backups():
            self.assertEqual(2, len(b["kek_ids"]))
            self.assertIn(active[0]["id"], b["kek_ids"])
            self.assertIn(retired[0]["id"], b["kek_ids"])
            # Recovery explicitly through the new KEK works.
            self._assert_recoverable_with(b["id"], active[0]["id"])

    def _assert_recoverable_with(self, backup_id, kek_id):
        import sqlite3

        from backup_app import crypto
        from backup_app.db import connect

        conn = connect(self.cfg.db_path)
        try:
            row = conn.execute(
                "SELECT * FROM backups WHERE id = ?", (backup_id,)
            ).fetchone()
            wrap = conn.execute(
                "SELECT * FROM wrapped_keys WHERE backup_id = ? AND kek_id = ?",
                (backup_id, kek_id),
            ).fetchone()
            self.assertIsNotNone(wrap, "new KEK wrapper missing")
            kek = self.svc.keystore.load(kek_id)
            dek = crypto.unwrap_dek(kek, wrap["wrapped_dek"], backup_id, kek_id)
            with open(row["blob_path"], "rb") as fh:
                plaintext = crypto.decrypt(dek, fh.read(), crypto.file_aad(backup_id))
            self.assertGreater(len(plaintext), 0)
        finally:
            conn.close()

    def test_upload_during_rotation_uses_only_new_kek(self):
        old_backup = self.upload("old.txt", b"before rotation")
        self.svc.start_rotation()
        # Rotation exists but nothing processed yet.
        self.svc.rotation_tick(limit=1)

        # New upload while rotation is running: must go straight to the new KEK.
        new_backup = self.upload("new.txt", b"after rotation start")
        new_meta = next(b for b in self.svc.list_backups() if b["id"] == new_backup)
        old_meta = next(b for b in self.svc.list_backups() if b["id"] == old_backup)

        active = next(k for k in self.svc.list_keys() if k["state"] == "active")
        retired = next(k for k in self.svc.list_keys() if k["state"] == "retired")
        self.assertEqual([active["id"]], new_meta["kek_ids"])
        self.assertNotIn(retired["id"], new_meta["kek_ids"])

        # Finish the rotation; the new backup must not have been counted into it.
        while self.svc.current_rotation() is not None:
            self.svc.rotation_tick()
        job = self.svc._conn().execute(
            "SELECT * FROM rotation_jobs ORDER BY created_at LIMIT 1"
        ).fetchone()
        self.assertEqual(1, job["total_backups"])  # only the pre-rotation backup
        self.assertEqual(1, job["processed"])
        # And both downloads still work.
        self.assertEqual(b"before rotation", self.svc.download_backup(old_backup)[1])
        self.assertEqual(b"after rotation start", self.svc.download_backup(new_backup)[1])

    def test_cannot_start_two_rotations(self):
        self.upload("a.txt", b"a")
        self.svc.start_rotation()
        with self.assertRaises(RotationInProgress):
            self.svc.start_rotation()

    def test_rotation_resumes_after_simulated_process_restart(self):
        for i in range(6):
            self.upload(f"f{i}.dat", f"x{i}".encode() * 32)
        self.svc.start_rotation()
        self.svc.rotation_tick(limit=2)  # partial progress, then "crash"

        # A brand-new Service instance over the same files = process restart.
        svc2 = Service(self.cfg)
        job = svc2.current_rotation()
        self.assertIsNotNone(job, "rotation must survive restart")
        self.assertEqual("running", job["state"])
        self.assertEqual(2, job["processed"])

        while svc2.current_rotation() is not None:
            svc2.rotation_tick()

        for b in svc2.list_backups():
            active = next(k for k in svc2.list_keys() if k["state"] == "active")
            self.assertIn(active["id"], b["kek_ids"])
            svc2.download_backup(b["id"])  # full recovery works post-restart

    def test_interrupted_tick_is_idempotent(self):
        # Two backups; run a tick of one, then repeat: wrappers must not
        # duplicate and counters stay consistent.
        self.upload("a", b"aa")
        self.upload("b", b"bb")
        self.svc.start_rotation()
        self.svc.rotation_tick(limit=1)
        self.svc.rotation_tick(limit=1)
        self.svc.rotation_tick(limit=10)  # completion tick

        conn = self.svc._conn()
        counts = conn.execute(
            "SELECT backup_id, COUNT(*) AS n FROM wrapped_keys GROUP BY backup_id"
        ).fetchall()
        self.assertTrue(all(r["n"] == 2 for r in counts))
        job = conn.execute("SELECT * FROM rotation_jobs").fetchone()
        self.assertEqual("completed", job["state"])
        self.assertEqual(2, job["processed"])


class KeyRemovalTests(ServiceTestBase):
    def test_old_kek_cannot_be_removed_before_rotation_finishes(self):
        self.upload("a", b"a")
        self.svc.start_rotation()
        retired = next(k for k in self.svc.list_keys() if k["state"] == "retired")
        with self.assertRaises(KeyRemovalError):
            self.svc.remove_key(retired["id"])
        self.assertNotIn(retired["id"], self.svc.removable_keys())

    def test_old_kek_removable_only_after_all_backups_have_new_wrapper(self):
        for i in range(3):
            self.upload(f"f{i}", f"p{i}".encode() * 8)
        self.svc.start_rotation()
        retired = next(k for k in self.svc.list_keys() if k["state"] == "retired")
        active = next(k for k in self.svc.list_keys() if k["state"] == "active")
        self.assertNotIn(retired["id"], self.svc.removable_keys())

        self.svc.rotation_tick(limit=1)
        self.assertNotIn(retired["id"], self.svc.removable_keys())

        while self.svc.current_rotation() is not None:
            self.svc.rotation_tick()
        self.assertIn(retired["id"], self.svc.removable_keys())
        self.assertNotIn(active["id"], self.svc.removable_keys())  # active stays protected

    def test_removal_shreds_key_and_recovery_still_works_with_new_kek(self):
        payload = b"recover me after old key is gone"
        bid = self.upload("keep.bin", payload)
        self.svc.start_rotation()
        while self.svc.current_rotation() is not None:
            self.svc.rotation_tick()
        retired = next(k for k in self.svc.list_keys() if k["state"] == "retired")
        old_path = self.svc.keystore._path(retired["id"])
        self.assertTrue(os.path.exists(old_path))

        self.svc.remove_key(retired["id"])

        self.assertFalse(os.path.exists(old_path))
        keys = self.svc.list_keys()
        self.assertEqual(1, len(keys))
        self.assertEqual("active", keys[0]["state"])
        # No wrapped row still references the destroyed KEK.
        leftovers = self.svc._conn().execute(
            "SELECT COUNT(*) AS n FROM wrapped_keys WHERE kek_id = ?", (retired["id"],)
        ).fetchone()["n"]
        self.assertEqual(0, leftovers)
        # The backup is still fully recoverable with the new master key.
        name, restored = self.svc.download_backup(bid)
        self.assertEqual(payload, restored)

    def test_active_kek_cannot_be_removed(self):
        active = next(k for k in self.svc.list_keys() if k["state"] == "active")
        with self.assertRaises(KeyRemovalError):
            self.svc.remove_key(active["id"])

    def test_remove_unknown_key(self):
        with self.assertRaises(KeyRemovalError):
            self.svc.remove_key("deadbeef" * 4)


class StorageSeparationTests(ServiceTestBase):
    def test_keystore_and_volume_hold_disjoint_material(self):
        self.upload("a", b"a" * 64)
        self.upload("b", b"b" * 64)
        keystore = set(os.listdir(self.cfg.keystore_dir))
        volume = set(os.listdir(self.cfg.volume_dir))
        # Ciphertext payloads only on the backup volume.
        self.assertTrue(all(f.endswith(".blob") for f in volume))
        self.assertEqual(2, len(volume))
        # Master keys + SQLite files only in the keystore.
        self.assertTrue(any(f.endswith(".kek") for f in keystore))
        self.assertIn("backup.db", keystore)
        self.assertTrue(keystore.isdisjoint(volume))

    def test_second_generation_rotation_then_remove_first_kek(self):
        # KEK1 -> rotate to KEK2, remove KEK1 -> rotate to KEK3, remove KEK2.
        first = self.upload("gen1", b"first generation")
        self.svc.start_rotation()
        while self.svc.current_rotation() is not None:
            self.svc.rotation_tick()
        kek1_id = next(k["id"] for k in self.svc.list_keys() if k["state"] == "retired")
        self.svc.remove_key(kek1_id)

        second = self.upload("gen2", b"second generation")
        self.svc.start_rotation()
        while self.svc.current_rotation() is not None:
            self.svc.rotation_tick()
        kek2_id = next(k["id"] for k in self.svc.list_keys() if k["state"] == "retired")
        # gen1 backup was wrapped under KEK2 and now needs a KEK3 wrapper before
        # KEK2 removal — the rotation job covers it automatically.
        self.svc.remove_key(kek2_id)

        self.assertEqual(b"first generation", self.svc.download_backup(first)[1])
        self.assertEqual(b"second generation", self.svc.download_backup(second)[1])
        self.assertEqual(1, len(self.svc.list_keys()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
