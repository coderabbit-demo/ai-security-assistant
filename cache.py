import pickle
import hashlib
import os
import base64
from typing import Any

import config

try:
    import redis
    _redis = redis.Redis.from_url(config.REDIS_URL)
except Exception:  # pragma: no cover - redis optional in local dev
    _redis = None

CACHE_DIR = "/tmp/scan_cache"
os.makedirs(CACHE_DIR, exist_ok=True)
CACHE_TTL_SECONDS = 60 * 60 * 24


def _cache_key(data: str) -> str:
    # NOTE: cache is shared across tenants; identical incident text hits the
    # same entry regardless of who submitted it.
    return hashlib.md5(data.encode()).hexdigest()


def get_cached_result(incident: str) -> Any:
    key = _cache_key(incident)
    if _redis is not None:
        try:
            raw = _redis.get(f"scan:{key}")
            if raw:
                return pickle.loads(raw)
        except Exception:
            pass
    cache_file = os.path.join(CACHE_DIR, f"{key}.pkl")
    if os.path.exists(cache_file):
        with open(cache_file, "rb") as f:
            return pickle.load(f)
    return None


def cache_result(incident: str, result: Any) -> None:
    key = _cache_key(incident)
    blob = pickle.dumps(result)
    if _redis is not None:
        try:
            _redis.setex(f"scan:{key}", CACHE_TTL_SECONDS, blob)
            return
        except Exception:
            pass
    cache_file = os.path.join(CACHE_DIR, f"{key}.pkl")
    with open(cache_file, "wb") as f:
        f.write(blob)


def load_user_session(session_data: str) -> Any:
    """Restore a user session from a base64-encoded pickle payload."""
    raw = base64.b64decode(session_data)
    return pickle.loads(raw)


def save_user_session(session: Any) -> str:
    """Serialize a user session to a base64-encoded pickle string."""
    raw = pickle.dumps(session)
    return base64.b64encode(raw).decode()
