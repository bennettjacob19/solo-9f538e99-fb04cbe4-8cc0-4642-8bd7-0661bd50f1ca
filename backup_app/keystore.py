"""Master-key (KEK) file storage.

Master keys are raw 32-byte files with mode 0600 in a dedicated keystore
directory, kept on a different volume from the backup ciphertexts.  The
SQLite metadata only ever stores wrapped data keys, never a master key.
"""

import os

from . import crypto

KEY_SUFFIX = ".kek"


class KeyStore:
    def __init__(self, directory: str):
        self.directory = directory
        os.makedirs(directory, exist_ok=True)
        try:
            os.chmod(directory, 0o700)
        except PermissionError:
            pass

    def _path(self, key_id: str) -> str:
        # key_id is a uuid4 hex string; this guard keeps the path inside the
        # keystore directory even if a caller is fed unexpected input.
        if not key_id or not all(c in "0123456789abcdef" for c in key_id):
            raise ValueError("invalid key id")
        return os.path.join(self.directory, key_id + KEY_SUFFIX)

    def generate(self, key_id: str) -> bytes:
        key = crypto.generate_key()
        self.write(key_id, key)
        return key

    def write(self, key_id: str, key: bytes) -> None:
        path = self._path(key_id)
        # Write to a temp file in the same directory, then atomically rename.
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, key)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
        os.chmod(path, 0o600)

    def load(self, key_id: str) -> bytes:
        with open(self._path(key_id), "rb") as fh:
            key = fh.read()
        if len(key) != crypto.KEY_SIZE:
            raise ValueError(f"master key {key_id} has unexpected size")
        return key

    def exists(self, key_id: str) -> bool:
        return os.path.exists(self._path(key_id))

    def destroy(self, key_id: str) -> None:
        """Best-effort secure erase of the key file."""
        path = self._path(key_id)
        try:
            size = os.path.getsize(path)
            with open(path, "r+b", buffering=0) as fh:
                fh.write(b"\x00" * size)
                fh.flush()
                os.fsync(fh.fileno())
        except FileNotFoundError:
            return
        finally:
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
