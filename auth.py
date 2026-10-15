import jwt
import datetime
import bcrypt
from db import get_db_connection
from config import JWT_SECRET


def authenticate_user(username: str, password: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user and bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        return {"id": user["id"], "username": user["username"]}
    return None


def generate_token(user_id: int) -> str:
    payload = {
        "user_id": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24),
        "iat": datetime.datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def verify_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return {"id": payload["user_id"]}
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
