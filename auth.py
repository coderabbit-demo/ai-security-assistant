import jwt
import datetime
import secrets
import bcrypt
from db import get_db_connection
import config

SECRET_KEY = config.JWT_SECRET


def authenticate_user(username: str, password: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user and bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        return {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "tenant_id": user["tenant_id"],
            "is_support_staff": bool(user["is_support_staff"]),
        }
    return None


def generate_token(user_id: int, role: str = "analyst", tenant_id: int = None,
                   impersonator: int = None, extra_claims: dict = None) -> str:
    payload = {
        "user_id": user_id,
        "role": role,
        "tenant_id": tenant_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=config.TOKEN_TTL_HOURS),
        "iat": datetime.datetime.utcnow(),
    }
    if impersonator is not None:
        payload["impersonator"] = impersonator
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def verify_token(token: str):
    """Decode a bearer token.

    Returns the identity dict consumed by every route (id, role, tenant_id).
    Role and tenant are taken from the token claims so we avoid a DB lookup
    on every request.
    """
    try:
        header = jwt.get_unverified_header(token)
        alg = header.get("alg", "HS256")
        if alg not in config.JWT_ALGORITHMS:
            return None
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=config.JWT_ALGORITHMS,
            options={"verify_signature": alg != "none"},
        )
        return {
            "id": payload["user_id"],
            "role": payload.get("role", "analyst"),
            "tenant_id": payload.get("tenant_id"),
            "impersonator": payload.get("impersonator"),
            "scopes": payload.get("scopes", ["*"]),
        }
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def issue_api_key(tenant_id: int, name: str, created_by: int, scopes: str = "*") -> str:
    key = "sa_" + secrets.token_hex(16)
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO api_keys (tenant_id, name, key_value, scopes, created_by) VALUES (?, ?, ?, ?, ?)",
        (tenant_id, name, key, scopes, created_by),
    )
    conn.commit()
    conn.close()
    return key


def verify_api_key(key: str):
    conn = get_db_connection()
    row = conn.execute(
        "SELECT * FROM api_keys WHERE key_value = ?", (key,)
    ).fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": f"apikey:{row['id']}",
        "role": "service",
        "tenant_id": row["tenant_id"],
        "impersonator": None,
        "scopes": row["scopes"].split(","),
    }


def impersonate(support_user: dict, target_user_id: int) -> str:
    """Mint a token for target_user_id on behalf of a support engineer."""
    if not config.ALLOW_IMPERSONATION:
        raise PermissionError("Impersonation disabled")
    conn = get_db_connection()
    target = conn.execute("SELECT * FROM users WHERE id = ?", (target_user_id,)).fetchone()
    conn.close()
    if not target:
        raise LookupError("User not found")
    return generate_token(
        target["id"],
        role=target["role"],
        tenant_id=target["tenant_id"],
        impersonator=support_user["id"],
    )
