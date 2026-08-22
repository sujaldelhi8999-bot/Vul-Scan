"""Data exfiltration module.

Collects everything looted during the engagement (DB dumps, config files,
SSH keys, command outputs, network maps) into a single ZIP archive, then
encrypts it with AES-256-GCM before storing it on disk. The key is derived
from BRUTAL_EXFIL_PASSWORD (or SECRET_KEY + session_id when unset), so the
server can always decrypt its own archives. Only the admin who owns the
session can download the archive, and its name/checksum is logged to the
audit trail.
"""

import hashlib
import io
import logging
import os
import tempfile
import time
import zipfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.brutal_sessions import BrutalSession
from app.config import get_settings

logger = logging.getLogger("phantomscan.brutal_exfil")

_MAGIC = b"PHSC"
_ACCEPTED_SUFFIXES = (".zip", ".enc")


def _archive_key(session_id: str) -> bytes:
    """AES-256 key: BRUTAL_EXFIL_PASSWORD if set, else SECRET_KEY + session_id."""
    settings = get_settings()
    secret = settings.brutal_exfil_password or f"{settings.secret_key}:{session_id}"
    return hashlib.sha256(secret.encode()).digest()


def _encrypt(plain: bytes, session_id: str) -> bytes:
    key = _archive_key(session_id)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plain, None)
    return _MAGIC + nonce + ciphertext


def decrypt_archive(payload: bytes, session_id: str) -> bytes:
    """Decrypt a loot archive. session_id is derived from the .enc filename."""
    if not payload.startswith(_MAGIC) or len(payload) <= len(_MAGIC) + 12:
        raise ValueError("Not a PhantomScan encrypted archive")
    nonce = payload[len(_MAGIC):len(_MAGIC) + 12]
    ciphertext = payload[len(_MAGIC) + 12:]
    try:
        return AESGCM(_archive_key(session_id)).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise ValueError("Decryption failed — wrong key or corrupted archive") from exc


def resolve_archive(file_id: str) -> Path | None:
    """Resolve an archive id to a path, guarding against traversal."""
    settings = get_settings()
    root = Path(settings.brutal_exfil_dir).resolve()
    candidate = (root / file_id).resolve()
    if candidate.parent != root or not candidate.exists() or not candidate.is_file():
        return None
    if candidate.suffix.lower() not in _ACCEPTED_SUFFIXES:
        return None
    return candidate


def session_id_from_archive(file_id: str) -> str:
    """Recover the session id embedded in an archive filename like brutal-loot-<sid>-<stamp>.enc."""
    stem = Path(file_id).stem
    return stem.split("-")[2]


class ExfiltrationAgent:
    """Packs session loot into an AES-256-GCM encrypted archive (ZIP inside)."""

    def __init__(self, session: BrutalSession) -> None:
        self.session = session
        self.settings = get_settings()

    def exfil_dir(self) -> Path:
        directory = Path(self.settings.brutal_exfil_dir)
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    async def pack(self) -> dict:
        """Zip + encrypt all loot. Returns file metadata for the download endpoint."""
        if not self.session.loot:
            raise ValueError("No loot collected yet — run exploitation steps first")

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            seen: set[str] = set()
            for index, item in enumerate(self.session.loot):
                safe_name = "".join(ch for ch in item["name"] if ch.isalnum() or ch in "._- /").strip().replace(" ", "_")
                if not safe_name or safe_name in seen:
                    safe_name = f"loot_{index}_{item['kind']}.txt"
                seen.add(safe_name)
                archive.writestr(safe_name, item.get("content", ""))
            archive.writestr(
                "MANIFEST.txt",
                "\n".join(
                    f"{item['ts']} [{item['kind']}] {item['name']} <- {item['source']}"
                    for item in self.session.loot
                ),
            )

        stamp = time.strftime("%Y%m%d-%H%M%S")
        archive_name = f"brutal-loot-{self.session.session_id[:8]}-{stamp}.enc"
        archive_path = self.exfil_dir() / archive_name
        archive_path.write_bytes(_encrypt(buffer.getvalue(), self.session.session_id))

        sha256 = hashlib.sha256(archive_path.read_bytes()).hexdigest()
        op_id = await self.session.log_op(
            "exfil_complete",
            "success",
            f"Exfiltrated {len(self.session.loot)} loot items to {archive_name} (AES-256-GCM, SHA256 {sha256[:16]}…)",
            output=str(archive_path),
        )
        return {
            "file_id": archive_name,
            "filename": archive_name,
            "size_bytes": archive_path.stat().st_size,
            "loot_count": len(self.session.loot),
            "encrypted": True,
            "cipher": "AES-256-GCM",
            "sha256": sha256,
            "op_id": op_id,
        }

    def resolve(self, file_id: str) -> Path | None:
        """Resolve an archive id to a path, guarding against traversal."""
        return resolve_archive(file_id)


def decrypt_to_temp(file_id: str) -> Path | None:
    """Decrypt an .enc archive to a temp .zip. Caller must delete the file."""
    path = resolve_archive(file_id)
    if path is None or path.suffix.lower() != ".enc":
        return None
    try:
        plain = decrypt_archive(path.read_bytes(), session_id_from_archive(file_id))
    except ValueError:
        logger.exception("Failed to decrypt archive %s", file_id)
        return None
    fd, tmp = tempfile.mkstemp(suffix=".zip")
    os.close(fd)
    with open(tmp, "wb") as handle:
        handle.write(plain)
    return Path(tmp)