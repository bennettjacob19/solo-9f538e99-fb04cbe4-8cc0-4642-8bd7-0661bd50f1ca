"""Backup service: upload/download plus master-key rotation lifecycle.

Design summary
--------------
* Each backup gets a unique DEK; the ciphertext blob is written once and is
  never rewritten during rotation.
* A DEK may have several wrapped copies, one per KEK that can recover the
  backup.  Rotation adds a copy under the new KEK; removing an old KEK deletes
  the copies under it.
* Rotation progress is fully persisted in ``rotation_jobs`` and
  ``wrapped_keys``.  A process restart resumes the same job; rewrapping a
  backup is idempotent thanks to the ``(backup_id, kek_id)`` unique index.
* Backups created after a rotation starts are encrypted directly under the
  new active KEK and never count into the rotation totals.
"""

import hashlib
import logging
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

from . import crypto, recovery
from .db import connect, init_db
from .keystore import KeyStore

log = logging.getLogger(__name__)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_id() -> str:
    return uuid.uuid4().hex


class RotationInProgress(Exception):
    pass


class KeyRemovalError(Exception):
    pass


class RecoveryConflict(Exception):
    """The original backup id is already registered by different content."""


class RecoveryExportError(Exception):
    pass


class Service:
    def __init__(self, config):
        self.config = config
        os.makedirs(config.volume_dir, exist_ok=True)
        self.keystore = KeyStore(config.keystore_dir)
        # Serializes writer transactions across request threads and the
        # background rotation worker. SQLite serializes the file itself; this
        # lock keeps multi-statement workflows coherent at the application
        # level.
        self._write_lock = threading.RLock()
        with connect(config.db_path) as conn:
            init_db(conn)
        self.bootstrap()

        # In-flight recovery-import jobs. These are intentionally *not*
        # persisted: an import is a short, idempotent operator, and a restart
        # simply lets the operator upload the same credential again.
        self._recovery_lock = threading.Lock()
        self._recovery_jobs = {}
        # Optional test/ops hook: called with the job dict right before the
        # streaming pass so a specific backup can be paused mid-read.
        self._recovery_gate = None

    # ------------------------------------------------------------------ basics

    def _conn(self):
        return connect(self.config.db_path)

    def bootstrap(self) -> None:
        """Create the first master key on a brand-new deployment."""
        with self._write_lock, self._conn() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM master_keys").fetchone()
            if row["n"] == 0:
                key_id = new_id()
                self.keystore.generate(key_id)
                conn.execute(
                    "INSERT INTO master_keys (id, created_at, state) VALUES (?, ?, 'active')",
                    (key_id, utcnow()),
                )
                conn.commit()
                log.info("bootstrapped initial master key %s", key_id)

    def reset_for_keystore_loss(self) -> None:
        """Wipe keys + metadata and re-bootstrap, keeping this instance usable.

        Test/ops helper that models a fresh keystore volume mounted while the
        backup volume (blobs) is untouched: all KEK files, the SQLite database
        and any in-flight recovery jobs are discarded, then a brand-new active
        KEK is generated.  Blob files on the backup volume are left alone.
        """
        import glob

        with self._write_lock:
            for path in glob.glob(os.path.join(self.config.keystore_dir, "*")):
                if os.path.isfile(path):
                    os.remove(path)
            # Recreate the schema in a fresh database file.
            with connect(self.config.db_path) as conn:
                init_db(conn)
            with self._recovery_lock:
                self._recovery_jobs.clear()
        self.bootstrap()

    def list_keys(self):
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT mk.*,
                       (SELECT COUNT(*) FROM wrapped_keys wk WHERE wk.kek_id = mk.id) AS wrap_count
                FROM master_keys mk ORDER BY mk.created_at
                """
            ).fetchall()
            return [dict(r) for r in rows]

    def get_active_kek(self, conn):
        row = conn.execute(
            "SELECT * FROM master_keys WHERE state = 'active' ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        if row is None:
            raise RuntimeError("no active master key available")
        return dict(row)

    def get_key(self, key_id: str):
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM master_keys WHERE id = ?", (key_id,)
            ).fetchone()
            return dict(row) if row else None

    # ------------------------------------------------------------------ upload

    def upload_backup(self, filename: str, data: bytes) -> str:
        if not filename:
            raise ValueError("filename is required")
        if len(data) == 0:
            raise ValueError("empty uploads are not allowed")
        filename = os.path.basename(filename)
        backup_id = new_id()

        with self._write_lock, self._conn() as conn:
            active = self.get_active_kek(conn)
            kek = self.keystore.load(active["id"])

            # Independent DEK per backup.
            dek = crypto.generate_key()
            blob = crypto.encrypt(dek, data, crypto.file_aad(backup_id))
            digest = hashlib.sha256(data).hexdigest()

            blob_path = os.path.join(self.config.volume_dir, backup_id + ".blob")
            self._write_blob(blob_path, blob)

            wrapped = crypto.wrap_dek(kek, dek, backup_id, active["id"])
            conn.execute(
                "INSERT INTO backups (id, filename, blob_path, size_bytes, sha256, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (backup_id, filename, blob_path, len(data), digest, utcnow()),
            )
            conn.execute(
                "INSERT INTO wrapped_keys (backup_id, kek_id, wrapped_dek, created_at)"
                " VALUES (?, ?, ?, ?)",
                (backup_id, active["id"], wrapped, utcnow()),
            )
            conn.commit()
        return backup_id

    @staticmethod
    def _write_blob(path: str, blob: bytes) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, blob)
            os.fsync(fd)
        finally:
            os.close(fd)

    # ---------------------------------------------------------------- download

    def list_backups(self):
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT b.*,
                       (SELECT GROUP_CONCAT(wk.kek_id)
                          FROM wrapped_keys wk WHERE wk.backup_id = b.id) AS kek_ids
                FROM backups b ORDER BY b.created_at DESC
                """
            ).fetchall()
            result = []
            for r in rows:
                item = dict(r)
                item["kek_ids"] = (r["kek_ids"] or "").split(",") if r["kek_ids"] else []
                result.append(item)
            return result

    def download_backup(self, backup_id: str):
        with self._write_lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM backups WHERE id = ?", (backup_id,)
            ).fetchone()
            if row is None:
                return None
            backup = dict(row)
            wraps = conn.execute(
                "SELECT * FROM wrapped_keys WHERE backup_id = ? ORDER BY id",
                (backup_id,),
            ).fetchall()
            if not wraps:
                raise RuntimeError(f"backup {backup_id} has no wrapped data keys")

            dek = None
            last_error = None
            # Try every wrapper: with a rotation in progress the newest KEK may
            # not yet cover an old backup, so prefer whatever is locally
            # available and valid.
            for wrap in wraps:
                if not self.keystore.exists(wrap["kek_id"]):
                    continue
                try:
                    kek = self.keystore.load(wrap["kek_id"])
                    dek = crypto.unwrap_dek(
                        kek, wrap["wrapped_dek"], backup_id, wrap["kek_id"]
                    )
                    break
                except Exception as exc:  # InvalidTag etc.
                    last_error = exc
                    continue
            if dek is None:
                raise RuntimeError(
                    f"no usable master key for backup {backup_id}: {last_error}"
                )

            with open(backup["blob_path"], "rb") as fh:
                stored = fh.read()
            plaintext = crypto.decrypt(dek, stored, crypto.file_aad(backup_id))
            if hashlib.sha256(plaintext).hexdigest() != backup["sha256"]:
                raise RuntimeError(f"integrity check failed for backup {backup_id}")
            return backup["filename"], plaintext

    # ---------------------------------------------------------------- rotation

    def current_rotation(self):
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM rotation_jobs WHERE state = 'running' ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            return dict(row) if row else None

    def start_rotation(self):
        with self._write_lock, self._conn() as conn:
            existing = conn.execute(
                "SELECT id FROM rotation_jobs WHERE state = 'running'"
            ).fetchone()
            if existing is not None:
                raise RotationInProgress("a rotation is already in progress")

            old = self.get_active_kek(conn)
            fresh_kek_id = new_id()
            self.keystore.generate(fresh_kek_id)
            conn.execute(
                "INSERT INTO master_keys (id, created_at, state) VALUES (?, ?, 'active')",
                (fresh_kek_id, utcnow()),
            )
            conn.execute(
                "UPDATE master_keys SET state = 'retired' WHERE id = ?", (old["id"],)
            )

            total = conn.execute(
                "SELECT COUNT(*) AS n FROM wrapped_keys WHERE kek_id = ?", (old["id"],)
            ).fetchone()["n"]
            job_id = new_id()
            conn.execute(
                "INSERT INTO rotation_jobs (id, old_kek_id, new_kek_id, state,"
                " total_backups, processed, created_at) VALUES (?, ?, ?, 'running', ?, 0, ?)",
                (job_id, old["id"], fresh_kek_id, total, utcnow()),
            )
            conn.commit()
            log.info(
                "rotation %s started: %s -> %s (%d backups)",
                job_id, old["id"], new_id, total,
            )
            return job_id

    def rotation_tick(self, limit: int = None) -> int:
        """Rewrap up to ``limit`` backups for the current rotation.

        Returns the number of backups processed in this tick.  Fully
        idempotent: re-execution after a crash only fills missing wrappers.
        """
        limit = limit or self.config.rotation_batch
        done = 0
        with self._write_lock, self._conn() as conn:
            job = conn.execute(
                "SELECT * FROM rotation_jobs WHERE state = 'running' ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            if job is None:
                return 0
            job = dict(job)

            if not self.keystore.exists(job["old_kek_id"]):
                # The old KEK is mandatory for rewrapping; keep the job alive
                # and surface the problem loudly instead of corrupting state.
                log.error("rotation %s cannot proceed: old KEK file missing", job["id"])
                return 0

            old_kek = self.keystore.load(job["old_kek_id"])
            new_kek = self.keystore.load(job["new_kek_id"])

            # Only pick backups that still lack a new-KEK wrapper. Once a
            # wrapper exists the backup leaves this set forever, so the job
            # is guaranteed to converge even if every tick is interrupted.
            targets = conn.execute(
                """
                SELECT DISTINCT old_w.backup_id
                FROM wrapped_keys old_w
                WHERE old_w.kek_id = ?
                  AND NOT EXISTS (
                        SELECT 1 FROM wrapped_keys new_w
                        WHERE new_w.backup_id = old_w.backup_id
                          AND new_w.kek_id = ?
                  )
                LIMIT ?
                """,
                (job["old_kek_id"], job["new_kek_id"], limit),
            ).fetchall()

            for t in targets:
                backup_id = t["backup_id"]
                wrap_row = conn.execute(
                    "SELECT * FROM wrapped_keys WHERE backup_id = ? AND kek_id = ?",
                    (backup_id, job["old_kek_id"]),
                ).fetchone()
                dek = crypto.unwrap_dek(
                    old_kek, wrap_row["wrapped_dek"], backup_id, job["old_kek_id"]
                )
                new_wrapped = crypto.wrap_dek(
                    new_kek, dek, backup_id, job["new_kek_id"]
                )
                # The unique (backup_id, kek_id) index makes a duplicate insert
                # from a crashed tick fail safely instead of double-wrapping.
                conn.execute(
                    "INSERT OR IGNORE INTO wrapped_keys (backup_id, kek_id, wrapped_dek, created_at)"
                    " VALUES (?, ?, ?, ?)",
                    (backup_id, job["new_kek_id"], new_wrapped, utcnow()),
                )
                conn.execute(
                    "UPDATE rotation_jobs SET processed = processed + 1 WHERE id = ?",
                    (job["id"],),
                )
                done += 1

            # processed equals the number of backups that now carry a new-KEK
            # wrapper; recompute it defensively in case a crash left the
            # counter behind.
            covered = conn.execute(
                """
                SELECT COUNT(DISTINCT old_w.backup_id) AS n
                FROM wrapped_keys old_w
                WHERE old_w.kek_id = ?
                  AND EXISTS (
                        SELECT 1 FROM wrapped_keys new_w
                        WHERE new_w.backup_id = old_w.backup_id
                          AND new_w.kek_id = ?
                  )
                """,
                (job["old_kek_id"], job["new_kek_id"]),
            ).fetchone()["n"]
            conn.execute(
                "UPDATE rotation_jobs SET processed = ? WHERE id = ?",
                (covered, job["id"]),
            )

            # A backup is "remaining" while it has an old-KEK wrapper but no
            # new-KEK wrapper yet. Old wrappers are intentionally retained
            # until the KEK is explicitly removed, so we cannot count on them
            # disappearing.
            remaining = conn.execute(
                """
                SELECT COUNT(*) AS n
                FROM wrapped_keys old_w
                WHERE old_w.kek_id = ?
                  AND NOT EXISTS (
                        SELECT 1 FROM wrapped_keys new_w
                        WHERE new_w.backup_id = old_w.backup_id
                          AND new_w.kek_id = ?
                  )
                """,
                (job["old_kek_id"], job["new_kek_id"]),
            ).fetchone()["n"]
            if remaining == 0:
                conn.execute(
                    "UPDATE rotation_jobs SET state = 'completed', completed_at = ? WHERE id = ?",
                    (utcnow(), job["id"]),
                )
                log.info("rotation %s completed", job["id"])
            conn.commit()
        return done

    # -------------------------------------------------------------- key removal

    def removable_keys(self):
        """KEKs that every dependent backup can recover without them."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT mk.id
                FROM master_keys mk
                WHERE mk.state = 'retired'
                  AND NOT EXISTS (SELECT 1 FROM rotation_jobs rj WHERE rj.state = 'running')
                  AND NOT EXISTS (
                        SELECT 1
                        FROM wrapped_keys wk
                        WHERE wk.kek_id = mk.id
                          AND NOT EXISTS (
                                SELECT 1 FROM wrapped_keys alt
                                WHERE alt.backup_id = wk.backup_id
                                  AND alt.kek_id <> mk.id
                                  AND EXISTS (SELECT 1 FROM master_keys m2 WHERE m2.id = alt.kek_id)
                          )
                  )
                """
            ).fetchall()
            return [r["id"] for r in rows]

    def remove_key(self, key_id: str) -> None:
        with self._write_lock, self._conn() as conn:
            key = conn.execute(
                "SELECT * FROM master_keys WHERE id = ?", (key_id,)
            ).fetchone()
            if key is None:
                raise KeyRemovalError("master key not found")
            if key["state"] == "active":
                raise KeyRemovalError("the active master key cannot be removed")
            running = conn.execute(
                "SELECT 1 FROM rotation_jobs WHERE state = 'running'"
            ).fetchone()
            if running:
                raise KeyRemovalError(
                    "wait for the running rotation to finish before removing a master key"
                )

            # Every backup wrapped by this KEK must have another wrapper whose
            # KEK still exists in the metadata table.
            stranded = conn.execute(
                """
                SELECT wk.backup_id
                FROM wrapped_keys wk
                WHERE wk.kek_id = ?
                  AND NOT EXISTS (
                        SELECT 1 FROM wrapped_keys alt
                        JOIN master_keys mk ON mk.id = alt.kek_id
                        WHERE alt.backup_id = wk.backup_id AND alt.kek_id <> ?
                  )
                """,
                (key_id, key_id),
            ).fetchall()
            if stranded:
                raise KeyRemovalError(
                    f"{len(stranded)} backup(s) still depend exclusively on this key"
                )

            conn.execute("DELETE FROM wrapped_keys WHERE kek_id = ?", (key_id,))
            conn.execute("DELETE FROM master_keys WHERE id = ?", (key_id,))
            conn.commit()

        # Metadata is gone first; only then shred the raw key material.
        self.keystore.destroy(key_id)
        log.info("master key %s removed", key_id)

    # ------------------------------------------------- recovery: export side

    def export_recovery_credential(self, backup_id: str, passphrase: str) -> tuple:
        """Build a passphrase-encrypted recovery credential for one backup.

        Returns ``(download_filename, credential_bytes)``.  The credential
        contains only this backup's DEK plus its registration metadata; no KEK
        material is included.
        """
        if not passphrase:
            raise RecoveryExportError("口令不能为空")
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM backups WHERE id = ?", (backup_id,)
            ).fetchone()
            if row is None:
                raise RecoveryExportError("备份不存在")
            backup = dict(row)
            wrap = conn.execute(
                "SELECT * FROM wrapped_keys WHERE backup_id = ? ORDER BY id LIMIT 1",
                (backup_id,),
            ).fetchone()
            if wrap is None:
                raise RecoveryExportError("该备份没有可导出的数据密钥包装")

            dek = None
            last_error = None
            # Unwrap with any KEK file still available, exactly like download.
            for w in conn.execute(
                "SELECT * FROM wrapped_keys WHERE backup_id = ? ORDER BY id",
                (backup_id,),
            ).fetchall():
                if not self.keystore.exists(w["kek_id"]):
                    continue
                try:
                    kek = self.keystore.load(w["kek_id"])
                    dek = crypto.unwrap_dek(
                        kek, w["wrapped_dek"], backup_id, w["kek_id"]
                    )
                    break
                except Exception as exc:  # InvalidTag etc.
                    last_error = exc
            if dek is None:
                raise RecoveryExportError(
                    f"当前没有可用主密钥解包该备份的数据密钥：{last_error}"
                )

        blob = recovery.seal_credential(
            passphrase,
            {
                "backup_id": backup["id"],
                "filename": backup["filename"],
                "size_bytes": backup["size_bytes"],
                "sha256": backup["sha256"],
                "dek": dek,
                "created_at": backup["created_at"],
            },
        )
        download_name = f"recovery-{backup['id'][:8]}.credential"
        return download_name, blob

    # ------------------------------------------------- recovery: import side

    # Internal-only fields never exposed through the API/UI.
    _JOB_INTERNAL = ("_pause_event",)

    def _public_job(self, job: dict) -> dict:
        return {k: v for k, v in job.items() if k not in self._JOB_INTERNAL}

    def list_recovery_jobs(self):
        with self._recovery_lock:
            # Newest first; return copies so callers cannot mutate internals.
            return [
                self._public_job(j)
                for j in sorted(
                    self._recovery_jobs.values(),
                    key=lambda j: j["started_at"],
                    reverse=True,
                )
            ][:50]

    def get_recovery_job(self, job_id: str):
        with self._recovery_lock:
            job = self._recovery_jobs.get(job_id)
            return self._public_job(job) if job else None

    def pause_recovery_job(self, job_id: str) -> None:
        """Block the streaming pass of one job (test/ops hook)."""
        with self._recovery_lock:
            job = self._recovery_jobs.get(job_id)
            if job is None:
                raise KeyError("recovery job not found")
            job["_pause_event"].clear()
            job["paused"] = True

    def resume_recovery_job(self, job_id: str) -> None:
        with self._recovery_lock:
            job = self._recovery_jobs.get(job_id)
            if job is None:
                raise KeyError("recovery job not found")
            job["_pause_event"].set()
            job["paused"] = False

    # Keep the in-memory job history bounded across a long-lived process.
    # Running jobs are never evicted.
    MAX_RECOVERY_JOBS = 100

    def _prune_jobs_locked(self) -> None:
        if len(self._recovery_jobs) <= self.MAX_RECOVERY_JOBS:
            return
        finished = sorted(
            (j for j in self._recovery_jobs.values() if j["status"] != "running"),
            key=lambda j: j["started_at"],
        )
        excess = len(self._recovery_jobs) - self.MAX_RECOVERY_JOBS
        for job in finished[:excess]:
            self._recovery_jobs.pop(job["id"], None)

    def start_recovery_import(self, credential_bytes: bytes, passphrase: str) -> str:
        """Authenticate a credential up front and run the blob verification in
        a background thread.  Returns the new job id.
        """
        # Credential-level authentication happens synchronously so a wrong
        # passphrase or malformed upload is reported immediately as a failed
        # job rather than polluting the registry with noisy background work.
        try:
            fields = recovery.open_credential(passphrase, credential_bytes)
        except recovery.CredentialError as exc:
            job_id = new_id()
            self._record_job(
                job_id, fields=None, status="failed", error=str(exc),
                total_bytes=0,
            )
            return job_id

        blob_path = os.path.join(
            self.config.volume_dir, fields["backup_id"] + ".blob"
        )
        job_id = new_id()
        with self._recovery_lock:
            self._recovery_jobs[job_id] = {
                "id": job_id,
                "backup_id": fields["backup_id"],
                "filename": fields["filename"],
                "status": "running",
                "total_bytes": max(fields["size_bytes"], 0),
                "read_bytes": 0,
                "error": None,
                "started_at": utcnow(),
                "finished_at": None,
                "registered_id": None,
                "idempotent": False,
                "paused": False,
                "_pause_event": threading.Event(),
            }
            job = self._recovery_jobs[job_id]
            job["_pause_event"].set()
            self._prune_jobs_locked()

        if self._recovery_gate is not None:
            try:
                self._recovery_gate(job)
            except Exception:
                log.exception("recovery gate hook raised; continuing")

        worker = threading.Thread(
            target=self._run_recovery,
            name=f"recovery-{job_id[:8]}",
            args=(job_id, fields, blob_path),
            daemon=True,
        )
        worker.start()
        return job_id

    def _record_job(self, job_id, fields, status, error, total_bytes,
                    registered_id=None, idempotent=False):
        with self._recovery_lock:
            existing = self._recovery_jobs.get(job_id)
            if existing is not None:
                existing.update({
                    "status": status,
                    "error": error,
                    "finished_at": utcnow(),
                    "registered_id": registered_id,
                    "idempotent": idempotent,
                })
                if status != "running":
                    existing["paused"] = False
                    existing["_pause_event"].set()
                return dict(existing)
            job = {
                "id": job_id,
                "backup_id": fields["backup_id"] if fields else None,
                "filename": fields["filename"] if fields else None,
                "status": status,
                "total_bytes": total_bytes,
                "read_bytes": 0,
                "error": error,
                "started_at": utcnow(),
                "finished_at": utcnow(),
                "registered_id": registered_id,
                "idempotent": idempotent,
                "paused": False,
                "_pause_event": threading.Event(),
            }
            job["_pause_event"].set()
            self._recovery_jobs[job_id] = job
            self._prune_jobs_locked()
            return dict(job)

    def _run_recovery(self, job_id: str, fields: dict, blob_path: str) -> None:
        try:
            with self._recovery_lock:
                job = self._recovery_jobs[job_id]
                pause_event = job["_pause_event"]

            def progress(read, total):
                # Waiting here pauses only this one import; other imports,
                # uploads, downloads and rotations keep running.
                pause_event.wait()
                with self._recovery_lock:
                    job["read_bytes"] = read
                    job["total_bytes"] = total or job["total_bytes"]

            # 1. Authenticate the surviving ciphertext and prove the decrypted
            #    digest matches the credential — one sequential read, streamed.
            recovery.verify_blob_stream(
                blob_path,
                fields["dek"],
                fields["backup_id"],
                fields["size_bytes"],
                fields["sha256"],
                chunk_size=self.config.recovery_chunk_size,
                progress_callback=progress,
            )

            # 2. Only after verification succeeds, register under the original
            #    id/filename. The DEK is wrapped with whichever KEK is active
            #    *at registration time*.
            registered_id, idempotent = self._register_recovered_backup(fields)

            with self._recovery_lock:
                job["read_bytes"] = job["total_bytes"]
            self._record_job(
                job_id, fields,
                status="completed",
                error=None,
                total_bytes=fields["size_bytes"],
                registered_id=registered_id,
                idempotent=idempotent,
            )
            log.info(
                "recovery job %s completed for backup %s (idempotent=%s)",
                job_id, registered_id, idempotent,
            )
        except recovery.CredentialError as exc:
            log.warning("recovery job %s failed: %s", job_id, exc)
            self._record_job(
                job_id, fields, status="failed", error=str(exc),
                total_bytes=fields["size_bytes"],
            )
        except RecoveryConflict as exc:
            log.warning("recovery job %s conflicted: %s", job_id, exc)
            self._record_job(
                job_id, fields, status="conflict", error=str(exc),
                total_bytes=fields["size_bytes"],
            )
        except Exception:
            log.exception("recovery job %s crashed", job_id)
            self._record_job(
                job_id, fields, status="failed",
                error="导入过程发生内部错误，登记未变更",
                total_bytes=fields["size_bytes"],
            )

    def _register_recovered_backup(self, fields: dict) -> tuple:
        """Insert the recovered backup row + a fresh DEK wrapper.

        Returns ``(backup_id, idempotent)``.  Raises :class:`RecoveryConflict`
        when the original id is already occupied by a different registration.
        On any failure nothing is written, so existing registrations stay
        untouched.
        """
        with self._write_lock, self._conn() as conn:
            existing = conn.execute(
                "SELECT * FROM backups WHERE id = ?", (fields["backup_id"],)
            ).fetchone()
            if existing is not None:
                # Re-importing the same credential must return the original id.
                if existing["sha256"] == fields["sha256"]:
                    return existing["id"], True
                raise RecoveryConflict(
                    f"编号 {fields['backup_id']} 已被另一份备份登记占用"
                    f"（现有 {existing['filename']}，"
                    f"凭据 {fields['filename']}），无法按原编号恢复"
                )

            active = self.get_active_kek(conn)
            kek = self.keystore.load(active["id"])
            wrapped = crypto.wrap_dek(
                kek, fields["dek"], fields["backup_id"], active["id"]
            )
            blob_path = os.path.join(
                self.config.volume_dir, fields["backup_id"] + ".blob"
            )
            try:
                conn.execute(
                    "INSERT INTO backups (id, filename, blob_path, size_bytes,"
                    " sha256, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        fields["backup_id"],
                        os.path.basename(fields["filename"]),
                        blob_path,
                        fields["size_bytes"],
                        fields["sha256"],
                        fields["created_at"],
                    ),
                )
            except sqlite3.IntegrityError as exc:
                # A concurrent import of the same credential registered the id
                # while this job was streaming. Re-read and treat as idempotent
                # on digest match, otherwise surface a conflict.
                raced = conn.execute(
                    "SELECT * FROM backups WHERE id = ?", (fields["backup_id"],)
                ).fetchone()
                if raced is not None and raced["sha256"] == fields["sha256"]:
                    return raced["id"], True
                raise RecoveryConflict(
                    f"编号 {fields['backup_id']} 已被另一份备份登记占用"
                ) from exc
            conn.execute(
                "INSERT OR IGNORE INTO wrapped_keys (backup_id, kek_id, wrapped_dek, created_at)"
                " VALUES (?, ?, ?, ?)",
                (fields["backup_id"], active["id"], wrapped, utcnow()),
            )
            conn.commit()
            return fields["backup_id"], False

    # ------------------------------------------------------------- dashboard

    def dashboard(self):
        with self._conn() as conn:
            stats = conn.execute(
                "SELECT COUNT(*) AS backups, COALESCE(SUM(size_bytes),0) AS total_bytes FROM backups"
            ).fetchone()
        return {
            "backups": self.list_backups(),
            "keys": self.list_keys(),
            "rotation": self.current_rotation(),
            "removable": set(self.removable_keys()),
            "recovery_jobs": self.list_recovery_jobs(),
            "backup_count": stats["backups"],
            "total_bytes": stats["total_bytes"],
        }
