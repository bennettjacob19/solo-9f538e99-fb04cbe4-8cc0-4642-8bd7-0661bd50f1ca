"""Runtime configuration loaded from environment variables.

Two storage locations are deliberately kept separate so they can be mounted
from different Docker volumes:

* ``KEYSTORE_DIR`` holds the master-key files and the SQLite metadata database
  (which contains wrapped data keys).
* ``VOLUME_DIR`` holds only the encrypted backup payloads (ciphertext blobs).
"""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    keystore_dir: str
    volume_dir: str
    db_path: str
    rotation_interval: float
    rotation_batch: int
    max_content_length: int


def config_from_env() -> Config:
    keystore_dir = os.environ.get("KEYSTORE_DIR", "/data/keystore")
    volume_dir = os.environ.get("VOLUME_DIR", "/data/volumes")
    db_path = os.environ.get("DB_PATH", os.path.join(keystore_dir, "backup.db"))
    return Config(
        keystore_dir=keystore_dir,
        volume_dir=volume_dir,
        db_path=db_path,
        rotation_interval=float(os.environ.get("ROTATION_INTERVAL", "1")),
        rotation_batch=int(os.environ.get("ROTATION_BATCH", "10")),
        max_content_length=int(os.environ.get("MAX_UPLOAD_MB", "16")) * 1024 * 1024,
    )
