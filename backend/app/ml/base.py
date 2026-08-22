from __future__ import annotations

import importlib.util
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("phantomscan.ml")


def _module_available(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


SKLEARN_AVAILABLE = _module_available("sklearn")
NUMPY_AVAILABLE = _module_available("numpy")
JOBLIB_AVAILABLE = _module_available("joblib")
ML_AVAILABLE = SKLEARN_AVAILABLE and NUMPY_AVAILABLE and JOBLIB_AVAILABLE


def ml_status() -> dict[str, bool]:
    return {
        "sklearn": SKLEARN_AVAILABLE,
        "numpy": NUMPY_AVAILABLE,
        "joblib": JOBLIB_AVAILABLE,
        "ml_ready": ML_AVAILABLE,
    }


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def default_model_dir() -> Path:
    from app.config import get_settings

    configured = get_settings().ml_model_dir
    if configured:
        return Path(configured)
    return Path(__file__).resolve().parent / "models"


def model_path(name: str) -> Path:
    return default_model_dir() / f"{name}.pkl"


class ModelRegistry:
    """Lazy singleton loader/persister for trained ML artifacts."""

    _cache: dict[str, Any] = {}

    @classmethod
    def get(cls, name: str) -> Any | None:
        if name in cls._cache:
            return cls._cache[name]
        if not JOBLIB_AVAILABLE:
            return None
        path = model_path(name)
        if not path.exists():
            return None
        try:
            import joblib

            model = joblib.load(path)
            cls._cache[name] = model
            return model
        except Exception as exc:
            logger.warning("Failed to load ML model %s: %s", name, exc)
            return None

    @classmethod
    def put(cls, name: str, obj: Any) -> Path | None:
        if not JOBLIB_AVAILABLE:
            return None
        path = model_path(name)
        try:
            import joblib

            path.parent.mkdir(parents=True, exist_ok=True)
            joblib.dump(obj, path)
            cls._cache[name] = obj
            return path
        except Exception as exc:
            logger.warning("Failed to save ML model %s: %s", name, exc)
            return None

    @classmethod
    def reset(cls) -> None:
        cls._cache.clear()
