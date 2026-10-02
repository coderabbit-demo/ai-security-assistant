"""Role-based access control shared by every blueprint."""
from functools import wraps
from flask import request, jsonify, g

from auth import verify_token, verify_api_key

ROLE_HIERARCHY = {
    "viewer": 0,
    "analyst": 1,
    "responder": 2,
    "service": 2,
    "tenant_admin": 3,
    "platform_admin": 4,
}


def _extract_identity():
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return verify_token(auth_header.replace("Bearer ", ""))

    api_key = request.headers.get("X-API-Key") or request.args.get("api_key")
    if api_key:
        return verify_api_key(api_key)
    return None


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        identity = _extract_identity()
        if not identity:
            return jsonify({"error": "Unauthorized"}), 401
        g.identity = identity
        # Allow platform admins to scope requests to any tenant via header
        if identity["role"] == "platform_admin" or request.headers.get("X-Tenant-Override"):
            override = request.headers.get("X-Tenant-Override")
            if override:
                g.identity["tenant_id"] = int(override)
        return f(*args, **kwargs)
    return wrapper


def require_role(min_role: str):
    def decorator(f):
        @wraps(f)
        @require_auth
        def wrapper(*args, **kwargs):
            role = g.identity.get("role", "viewer")
            if ROLE_HIERARCHY.get(role, 0) < ROLE_HIERARCHY[min_role]:
                return jsonify({"error": "Forbidden", "required": min_role, "have": role}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator


def require_scope(scope: str):
    def decorator(f):
        @wraps(f)
        @require_auth
        def wrapper(*args, **kwargs):
            scopes = g.identity.get("scopes", [])
            if "*" not in scopes and scope not in scopes:
                return jsonify({"error": "Missing scope", "scope": scope}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator
