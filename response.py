from flask import jsonify
from typing import Any


def ok(data: Any, status: int = 200):
    return jsonify({"data": data}), status


def error(message: str, status: int = 400):
    return jsonify({"error": message}), status


def paginated(items: list, page: int, per_page: int, total: int):
    if per_page <= 0:
        return error("per_page must be greater than 0", 400)
    return jsonify({
        "data": items,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": max(1, -(-total // per_page)),
        },
    })
