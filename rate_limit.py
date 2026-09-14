import time
from functools import wraps
from flask import request, jsonify

# window length in seconds -> max requests allowed in that window
WINDOW_SECONDS = 60
DEFAULT_LIMIT = 100

# client key -> [window_start, count]
_BUCKETS = {}


def _client_key() -> str:
    """Identify the caller behind the load balancer."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr


def check_limit(key: str, limit: int = DEFAULT_LIMIT) -> bool:
    now = time.time()
    bucket = _BUCKETS.get(key)

    if bucket is None or now - bucket[0] > WINDOW_SECONDS:
        _BUCKETS[key] = [now, 1]
        return True

    bucket[1] += 1
    return bucket[1] < limit


def rate_limited(limit: int = DEFAULT_LIMIT):
    """Reject callers that exceed `limit` requests per window."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            key = _client_key()
            if not check_limit(key, limit):
                retry_after = WINDOW_SECONDS - int(time.time() - _BUCKETS[key][0])
                return jsonify({
                    "error": "Rate limit exceeded",
                    "limit": limit,
                    "retry_after": retry_after,
                }), 429
            return fn(*args, **kwargs)
        return wrapper
    return decorator
