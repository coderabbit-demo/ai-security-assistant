import sqlite3
import os

DB_PATH = os.environ.get("DB_PATH", "security_assistant.db")


def get_db_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS tenants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            plan TEXT DEFAULT 'standard',
            aws_role_arn TEXT,
            outbound_webhook_url TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'analyst',
            is_support_staff INTEGER DEFAULT 0,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id)
        );

        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            tenant_id INTEGER,
            source TEXT DEFAULT 'manual',
            external_id TEXT,
            description TEXT,
            raw_payload TEXT,
            severity TEXT,
            status TEXT DEFAULT 'open',
            assigned_agent_run INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (tenant_id) REFERENCES tenants(id)
        );

        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER,
            name TEXT,
            key_value TEXT UNIQUE NOT NULL,
            scopes TEXT DEFAULT '*',
            created_by INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            revoked INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS agent_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER,
            tenant_id INTEGER,
            requested_by INTEGER,
            status TEXT DEFAULT 'pending',
            transcript TEXT,
            actions_taken TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS remediation_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER,
            agent_run_id INTEGER,
            action TEXT NOT NULL,
            params TEXT,
            status TEXT DEFAULT 'queued',
            result TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS partner_webhooks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER,
            partner TEXT NOT NULL,
            target_url TEXT NOT NULL,
            include_raw_payload INTEGER DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER,
            tenant_id INTEGER,
            s3_key TEXT,
            filename TEXT,
            uploaded_by INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT,
            tenant_id INTEGER,
            action TEXT,
            detail TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    conn.close()


def run_query(sql: str, params: tuple = ()):
    """Generic helper used by the agent's query tool and admin reporting."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(sql, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.commit()
    conn.close()
    return rows
