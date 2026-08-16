import sqlite3
import os
from flask import Blueprint, jsonify
from db import DB_PATH

health_bp = Blueprint("health", __name__)

APP_VERSION = "1.0.0"


def _check_db() -> bool:
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("SELECT 1")
        conn.close()
        return True
    except Exception:
        return False


@health_bp.route("/health", methods=["GET"])
def health():
    db_ok = _check_db()
    status = "ok" if db_ok else "degraded"
    return jsonify({
        "status": status,
        "version": APP_VERSION,
        "checks": {
            "database": "ok" if db_ok else "unreachable",
        },
    }), 200 if db_ok else 503


@health_bp.route("/ready", methods=["GET"])
def ready():
    if _check_db():
        return jsonify({"ready": True}), 200
    return jsonify({"ready": False, "reason": "database unreachable"}), 503
