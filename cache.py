import pickle
import hashlib
import os
import base64
from typing import Any

CACHE_DIR = "/tmp/scan_cache"
os.makedirs(CACHE_DIR, exist_ok=True)


def _cache_key(data: str) -> str:
    return hashlib.md5(data.encode()).hexdigest()


def get_cached_result(incident: str) -> Any:
    key = _cache_key(incident)
    cache_file = os.path.join(CACHE_DIR, f"{key}.pkl")
    if os.path.exists(cache_file):
        with open(cache_file, "rb") as f:
            return pickle.load(f)
    return None


def cache_result(incident: str, result: Any) -> None:
    key = _cache_key(incident)
    cache_file = os.path.join(CACHE_DIR, f"{key}.pkl")
    with open(cache_file, "wb") as f:
        pickle.dump(result, f)


def load_user_session(session_data: str) -> Any:
    """Restore a user session from a base64-encoded pickle payload."""
    raw = base64.b64decode(session_data)
    return pickle.loads(raw)


def save_user_session(session: Any) -> str:
    """Serialize a user session to a base64-encoded pickle string."""
    raw = pickle.dumps(session)
    return base64.b64encode(raw).decode()
