"""
Secure ZIP upload & extraction service.

Extracts uploaded archives to an isolated temp directory, guarding against
Zip Slip / path traversal (including Windows backslash variants).
"""

import logging
import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path

from fastapi import HTTPException

logger = logging.getLogger("phantomscan.upload_service")

MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # 200 MB


def _is_safe_zip_path(member: str) -> bool:
    """Reject absolute paths and path traversal in zip entry names (both separators)."""
    normalized = member.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        return False
    parts = [p for p in normalized.split("/") if p not in ("", ".")]
    return ".." not in parts


def _cleanup(work_dir: Path) -> None:
    shutil.rmtree(work_dir, ignore_errors=True)


async def extract_uploaded_zip(
    source: Path,
    *,
    max_bytes: int = MAX_UPLOAD_BYTES,
    work_dir: Path | None = None,
    prefix: str = "upload-",
) -> str:
    """Validate, save, and securely extract an uploaded zip.

    Args:
        source: Path to the zip file (already saved) OR UploadFile object
        max_bytes: Maximum allowed size
        work_dir: Existing work directory to use (if None, creates new one)
        prefix: Prefix for temp directory name

    Returns the normalized absolute path to the extracted codebase
    (the single root directory if the archive contains one).
    """
    # Handle UploadFile object (backward compatibility)
    if hasattr(source, 'filename') and hasattr(source, 'read'):
        file: 'UploadFile' = source
        if not file.filename or not file.filename.lower().endswith(".zip"):
            raise HTTPException(status_code=400, detail="Only .zip files are supported")

        content = await file.read()
        if len(content) > max_bytes:
            raise HTTPException(status_code=413, detail="File exceeds 200 MB limit")

        if work_dir is None:
            work_dir = Path(tempfile.mkdtemp(prefix=prefix))
        else:
            work_dir.mkdir(parents=True, exist_ok=True)

        temp_zip_path = work_dir / "source.zip"
        temp_zip_path.write_bytes(content)
    else:
        # source is a Path to existing zip file
        temp_zip_path = Path(source)
        if not temp_zip_path.exists():
            raise HTTPException(status_code=400, detail="Zip file not found")
        if work_dir is None:
            work_dir = temp_zip_path.parent

    try:
        with zipfile.ZipFile(temp_zip_path) as zf:
            for info in zf.infolist():
                member = info.filename.replace("\\", "/")
                if not _is_safe_zip_path(member):
                    _cleanup(work_dir)
                    raise HTTPException(status_code=400, detail="Zip contains unsafe paths")
                target = (work_dir / member).resolve()
                if not target.is_relative_to(work_dir.resolve()):
                    _cleanup(work_dir)
                    raise HTTPException(status_code=400, detail="Zip contains unsafe paths")
                zf.extract(info, work_dir)
    except zipfile.BadZipFile:
        _cleanup(work_dir)
        raise HTTPException(status_code=400, detail="Invalid or corrupted zip file")
    finally:
        if temp_zip_path.exists() and temp_zip_path.name == "source.zip":
            temp_zip_path.unlink(missing_ok=True)

    entries = [e for e in work_dir.iterdir() if e.name != "source.zip"]
    if len(entries) == 1 and entries[0].is_dir():
        scan_root = str(entries[0])
    else:
        scan_root = str(work_dir)

    return os.path.normpath(scan_root)