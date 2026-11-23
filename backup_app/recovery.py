"""Recovery credentials for disaster recovery after keystore-volume loss.

A recovery credential is a single self-contained, passphrase-encrypted file
that holds *one* backup's data key (DEK) plus the minimum metadata needed to
re-register the backup against a freshly built keystore volume:

* the original backup id (so the original download link is restored);
* the original filename, size, SHA-256 digest and creation timestamp;
* the raw DEK that decrypts the untouched ciphertext blob on the backup
  volume.

It never contains master-key (KEK) material: losing or leaking a credential
does not compromise any other backup, and the new keystore volume does not
need any of the old KEKs.

File layout (all integers big-endian)::

    MAGIC (27B) | version (1B) | salt (16B) | iterations (4B uint32)
    | nonce (12B) | AES-256-GCM( JSON payload )

The passphrase is stretched with PBKDF2-HMAC-SHA256 (memory-light, so several
imports run concurrently inside a 160 MiB container); the GCM AAD binds the
header so magic/version/salt/iteration counts cannot be tampered with without
failing authentication.
"""

import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

from . import crypto

MAGIC = b"BACKUP-RECOVERY-CREDENTIAL\n"
VERSION = 1
PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 16
ITER_SIZE = 4
HEADER_SIZE = len(MAGIC) + 1 + SALT_SIZE + ITER_SIZE
# MAGIC | version | salt | iterations, i.e. every authenticated header byte.
_AAD_END = HEADER_SIZE

# Payload schema version stored inside the encrypted JSON document.
PAYLOAD_VERSION = 1


class CredentialError(Exception):
    """Raised when a recovery credential is malformed or fails authentication."""


def _derive_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    if not isinstance(passphrase, str) or not passphrase:
        raise CredentialError("passphrase is required")
    if iterations < 100_000:
        # Refuse absurdly low iteration counts even if the header were forged;
        # authentication would fail anyway, this gives a clearer error.
        raise CredentialError("unsupported credential parameters")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=crypto.KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def seal_credential(passphrase: str, fields: dict) -> bytes:
    """Encrypt one backup's DEK and metadata into a recovery credential."""
    required = ("backup_id", "filename", "size_bytes", "sha256", "dek", "created_at")
    missing = [k for k in required if k not in fields]
    if missing:
        raise CredentialError(f"credential payload missing fields: {missing}")
    if len(fields["dek"]) != crypto.KEY_SIZE:
        raise CredentialError("data key has unexpected size")

    salt = os.urandom(SALT_SIZE)
    iterations = PBKDF2_ITERATIONS
    payload = {
        "v": PAYLOAD_VERSION,
        "id": fields["backup_id"],
        "fn": fields["filename"],
        "sz": int(fields["size_bytes"]),
        "sha": fields["sha256"],
        "dek": base64.b64encode(fields["dek"]).decode("ascii"),
        "ts": fields["created_at"],
    }
    key = _derive_key(passphrase, salt, iterations)
    nonce = os.urandom(crypto.NONCE_SIZE)
    header = (
        MAGIC
        + bytes([VERSION])
        + salt
        + iterations.to_bytes(ITER_SIZE, "big")
    )
    body = AESGCM(key).encrypt(nonce, json.dumps(payload).encode("utf-8"), header)
    return header + nonce + body


def open_credential(passphrase: str, blob: bytes) -> dict:
    """Authenticate and decrypt a recovery credential.

    Raises :class:`CredentialError` for any structural problem or for a wrong
    passphrase (GCM authentication failure).
    """
    if not isinstance(blob, (bytes, bytearray)):
        raise CredentialError("credential must be a binary file")
    if len(blob) < HEADER_SIZE + crypto.NONCE_SIZE + 16:
        raise CredentialError("credential file is truncated")
    if not blob.startswith(MAGIC):
        raise CredentialError("not a recovery credential (bad magic header)")
    offset = len(MAGIC)
    version = blob[offset]
    if version != VERSION:
        raise CredentialError(f"unsupported credential version {version}")
    offset += 1
    salt = blob[offset:offset + SALT_SIZE]
    offset += SALT_SIZE
    iterations = int.from_bytes(blob[offset:offset + ITER_SIZE], "big")
    offset += ITER_SIZE
    aad = bytes(blob[:_AAD_END])
    nonce = blob[offset:offset + crypto.NONCE_SIZE]
    sealed = blob[offset + crypto.NONCE_SIZE:]

    try:
        key = _derive_key(passphrase, salt, iterations)
        raw = AESGCM(key).decrypt(nonce, sealed, aad)
    except (InvalidTag, ValueError) as exc:
        raise CredentialError("口令错误或凭据已损坏（认证失败）") from exc

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CredentialError("凭据内容无法解析") from exc

    try:
        fields = {
            "backup_id": payload["id"],
            "filename": payload["fn"],
            "size_bytes": int(payload["sz"]),
            "sha256": payload["sha"],
            "dek": base64.b64decode(payload["dek"], validate=True),
            "created_at": payload["ts"],
            "payload_version": payload["v"],
        }
    except (KeyError, TypeError, ValueError) as exc:
        raise CredentialError("凭据元数据不完整") from exc

    if len(fields["dek"]) != crypto.KEY_SIZE:
        raise CredentialError("凭据中的数据密钥长度不正确")
    if not isinstance(fields["backup_id"], str) or len(fields["backup_id"]) != 32:
        raise CredentialError("凭据中的备份编号无效")
    if not all(c in "0123456789abcdef" for c in fields["backup_id"]):
        raise CredentialError("凭据中的备份编号无效")
    if not isinstance(fields["sha256"], str) or len(fields["sha256"]) != 64:
        raise CredentialError("凭据中的摘要无效")
    return fields


class BlobVerificationError(CredentialError):
    """The surviving ciphertext blob cannot be authenticated or does not match."""


def verify_blob_stream(
    blob_path,
    dek,
    backup_id,
    expected_size,
    expected_sha256,
    chunk_size=256 * 1024,
    progress_callback=None,
):
    """Stream-decrypt a blob exactly once and authenticate it against metadata.

    The ciphertext body is read through a single sequential pass in fixed-size
    chunks; the plaintext is never buffered wholesale — only a running SHA-256
    digest and the byte counter are retained, so a 15 MiB backup costs roughly
    one chunk of heap regardless of file size.

    Authentication is threefold:

    1. AES-GCM proves the ciphertext and its ``backup_id`` AAD were not
       tampered with (the tag is checked at ``finalize()``);
    2. the decrypted length must equal the size recorded in the credential;
    3. the decrypted SHA-256 must equal the digest recorded in the credential.

    ``progress_callback(bytes_read, total_bytes)`` is invoked after every
    chunk; it may block, which lets an operator (or a test) pause one import
    without stopping the others.
    """
    aad = crypto.file_aad(backup_id)
    try:
        fh = open(blob_path, "rb")
    except FileNotFoundError as exc:
        raise BlobVerificationError(f"原卷密文不存在：{os.path.basename(blob_path)}") from exc

    with fh:
        file_size = os.fstat(fh.fileno()).st_size
        # On-disk layout of ``AESGCM.encrypt``: nonce (12B) || ciphertext
        # (same length as plaintext) || GCM tag (16B).  The tag lives at the
        # END, so read the nonce first and the tag last, and stream only the
        # middle ciphertext region in a single sequential pass.
        framing = crypto.NONCE_SIZE + 16
        if file_size < framing:
            raise BlobVerificationError("密文文件过短，已损坏或并非该备份的正文")
        nonce = fh.read(crypto.NONCE_SIZE)
        fh.seek(-16, os.SEEK_END)
        tag = fh.read(16)
        cipher_total = file_size - framing

        # Reopen the read cursor at the start of the ciphertext.  No bytes
        # beyond the nonce/tag framing have been read into memory yet, so the
        # ciphertext body is still consumed exactly once.
        fh.seek(crypto.NONCE_SIZE)
        decryptor = Cipher(
            algorithms.AES(dek), modes.GCM(nonce, tag)
        ).decryptor()
        decryptor.authenticate_additional_data(aad)
        digest = hashlib.sha256()
        plain_size = 0
        read_total = 0
        remaining = cipher_total

        while remaining > 0:
            chunk = fh.read(min(chunk_size, remaining))
            if not chunk:
                raise BlobVerificationError("密文读取意外中断，文件可能已损坏")
            remaining -= len(chunk)
            read_total += len(chunk)
            # Not trustworthy until finalize() succeeds; only feed the hash.
            plain_chunk = decryptor.update(chunk)
            digest.update(plain_chunk)
            plain_size += len(plain_chunk)
            if progress_callback is not None:
                progress_callback(read_total, cipher_total)

        try:
            decryptor.finalize()
        except InvalidTag as exc:
            raise BlobVerificationError("密文认证失败（GCM tag 不匹配，密文可能已损坏）") from exc

    if plain_size != expected_size:
        raise BlobVerificationError(
            f"解密后的大小 {plain_size} 与凭据记录 {expected_size} 不符"
        )
    actual = digest.hexdigest()
    if actual != expected_sha256:
        raise BlobVerificationError("解密原文摘要与凭据记录不符")
    return actual
