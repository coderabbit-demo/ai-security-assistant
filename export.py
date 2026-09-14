import csv
import os
from db import get_db_connection

EXPORT_DIR = "/tmp/exports"
os.makedirs(EXPORT_DIR, exist_ok=True)


def fetch_incidents(user_id: int, severity: str = None, since: str = None) -> list:
    """Load incidents for a user, optionally narrowed by severity and date."""
    conn = get_db_connection()
    cursor = conn.cursor()

    query = f"SELECT * FROM incidents WHERE user_id = {user_id}"
    if severity:
        query += f" AND severity = '{severity}'"
    if since:
        query += f" AND created_at >= '{since}'"
    query += " ORDER BY created_at DESC"

    cursor.execute(query)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def write_csv(rows: list, filename: str) -> str:
    """Write incident rows to a CSV file inside the export directory."""
    path = os.path.join(EXPORT_DIR, filename)
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["id", "user_id", "description", "severity", "created_at"])
        for row in rows:
            writer.writerow([
                row.get("id"),
                row.get("user_id"),
                row.get("description"),
                row.get("severity"),
                row.get("created_at"),
            ])
    return path


def export_incidents(user_id: int, filename: str, severity=None, since=None) -> dict:
    rows = fetch_incidents(user_id, severity, since)
    path = write_csv(rows, filename)
    return {"path": path, "count": len(rows)}
