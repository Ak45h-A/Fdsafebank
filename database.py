"""
database.py — Database connection for SafeBank
FIXED:
  - DB_FILE is now ABSOLUTE (based on this file's directory) so data is
    never lost regardless of which directory you run `python app.py` from.
  - SQLite WAL (Write-Ahead Logging) mode enabled — data is fully committed
    to disk even if the app is killed mid-operation (Ctrl+C, crash, etc).
  - PRAGMA synchronous=NORMAL — safe and fast writes.
  - PRAGMA cache_size increased for better performance.
"""
import os
import sqlite3

DATABASE_URL = os.environ.get("DATABASE_URL")
USING_POSTGRES = DATABASE_URL is not None

if USING_POSTGRES:
    import pg8000.native
    print("[✓] Using PostgreSQL")
else:
    print("[✓] Using SQLite (local)")

# ── ABSOLUTE path — never changes no matter where you run the app from ────────
_HERE = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(_HERE, "safebank_web.db")
print(f"[✓] Database file: {DB_FILE}")


def get_connection():
    if USING_POSTGRES:
        import urllib.parse as up
        url = up.urlparse(DATABASE_URL)
        conn = pg8000.native.Connection(
            user=url.username, password=url.password,
            host=url.hostname, port=url.port or 5432,
            database=url.path[1:], ssl_context=True
        )
        conn.run("BEGIN")
        return conn
    else:
        conn = sqlite3.connect(DB_FILE, check_same_thread=False, timeout=30)
        conn.row_factory = sqlite3.Row
        # WAL mode: commits survive Ctrl+C / crashes — data is NEVER lost
        conn.execute("PRAGMA journal_mode=WAL")
        # NORMAL sync: safe without being slow
        conn.execute("PRAGMA synchronous=NORMAL")
        # Respect FK constraints
        conn.execute("PRAGMA foreign_keys=ON")
        # Larger cache = fewer disk reads
        conn.execute("PRAGMA cache_size=-16000")
        # Keep WAL file small
        conn.execute("PRAGMA wal_autocheckpoint=100")
        return conn


def fetchone_as_dict(cursor_or_conn, query, params=()):
    if USING_POSTGRES:
        rows = cursor_or_conn.run(query, **_params_to_kwargs(query, params))
        if not rows: return None
        cols = [c["name"] for c in cursor_or_conn.columns]
        return dict(zip(cols, rows[0]))
    else:
        cursor_or_conn.execute(query, params)
        row = cursor_or_conn.fetchone()
        return dict(row) if row else None


def fetchall_as_dict(cursor_or_conn, query, params=()):
    if USING_POSTGRES:
        rows = cursor_or_conn.run(query, **_params_to_kwargs(query, params))
        if not rows: return []
        cols = [c["name"] for c in cursor_or_conn.columns]
        return [dict(zip(cols, r)) for r in rows]
    else:
        cursor_or_conn.execute(query, params)
        return [dict(r) for r in cursor_or_conn.fetchall()]


def execute_query(cursor_or_conn, query, params=()):
    if USING_POSTGRES:
        cursor_or_conn.run(query, **_params_to_kwargs(query, params))
    else:
        cursor_or_conn.execute(query, params)


def _params_to_kwargs(query, params):
    return {}


def adapt_query(query):
    if not USING_POSTGRES:
        return query
    result, i = "", 1
    for ch in query:
        if ch == "?":
            result += f":p{i}"; i += 1
        else:
            result += ch
    return result


def params_to_pg(params):
    return {f"p{i+1}": v for i, v in enumerate(params)}


def begin(conn):
    if USING_POSTGRES:
        try: conn.run("BEGIN")
        except: pass


def commit(conn):
    if USING_POSTGRES:
        conn.run("COMMIT"); conn.run("BEGIN")
    else:
        conn.commit()


def rollback(conn):
    if USING_POSTGRES:
        try: conn.run("ROLLBACK"); conn.run("BEGIN")
        except: pass
    else:
        conn.rollback()


def close(conn):
    if USING_POSTGRES:
        try: conn.run("COMMIT")
        except: pass
        conn.close()
    else:
        conn.close()


def initialize_database():
    """
    Creates all tables IF NOT EXISTS.
    Safe to call on every startup — never drops or truncates existing data.
    """
    if USING_POSTGRES:
        conn = get_connection()
        ts = "(to_char(NOW(), 'YYYY-MM-DD HH24:MI:SS'))"
        conn.run(f"""CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY, full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
            phone TEXT, is_admin INTEGER DEFAULT 0,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TEXT,
            created_at TEXT DEFAULT {ts})""")
        conn.run(f"""CREATE TABLE IF NOT EXISTS accounts (
            account_id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
            balance REAL DEFAULT 0.0, status TEXT DEFAULT 'active')""")
        conn.run(f"""CREATE TABLE IF NOT EXISTS transactions (
            txn_id TEXT PRIMARY KEY, account_id TEXT NOT NULL,
            txn_type TEXT NOT NULL, amount REAL NOT NULL,
            balance_after REAL NOT NULL, description TEXT,
            merchant TEXT, location TEXT, fraud_score INTEGER DEFAULT 0,
            status TEXT DEFAULT 'success', timestamp TEXT DEFAULT {ts})""")
        conn.run(f"""CREATE TABLE IF NOT EXISTS fraud_reports (
            report_id TEXT PRIMARY KEY, txn_id TEXT NOT NULL,
            account_id TEXT NOT NULL, user_id TEXT NOT NULL,
            reason TEXT NOT NULL, evidence TEXT,
            status TEXT DEFAULT 'pending', fraud_score INTEGER DEFAULT 0,
            submitted_at TEXT DEFAULT {ts},
            reviewed_at TEXT, reviewed_by TEXT,
            admin_notes TEXT, refund_txn_id TEXT)""")
        conn.run(f"""CREATE TABLE IF NOT EXISTS verifications (
            verification_id  TEXT PRIMARY KEY,
            report_id        TEXT NOT NULL,
            txn_id           TEXT NOT NULL,
            account_id       TEXT NOT NULL,
            merchant         TEXT NOT NULL,
            amount           REAL NOT NULL,
            status           TEXT DEFAULT 'pending',
            document_type    TEXT,
            document_name    TEXT,
            video_requested  INTEGER DEFAULT 0,
            created_at       TEXT DEFAULT {ts},
            deadline_at      TEXT NOT NULL,
            resolved_at      TEXT,
            admin_notes      TEXT,
            last_reminder_sent TEXT)""")
        conn.run(f"""CREATE TABLE IF NOT EXISTS admin_audit_log (
            log_id TEXT PRIMARY KEY, admin_id TEXT NOT NULL,
            action TEXT NOT NULL, target_id TEXT, detail TEXT,
            performed_at TEXT DEFAULT {ts})""")
        conn.run(f"""CREATE TABLE IF NOT EXISTS password_resets (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used INTEGER DEFAULT 0,
            created_at TEXT DEFAULT {ts})""")
        conn.run(f"""CREATE TABLE IF NOT EXISTS login_log (
            log_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            ip_address TEXT,
            status TEXT NOT NULL,
            created_at TEXT DEFAULT {ts})""")
        conn.run(f"""CREATE TABLE IF NOT EXISTS blacklisted_merchants (
            id TEXT PRIMARY KEY,
            merchant_name TEXT UNIQUE NOT NULL,
            reason TEXT,
            added_by TEXT NOT NULL,
            added_at TEXT DEFAULT {ts})""")
        conn.run("COMMIT")
        conn.close()
    else:
        conn = sqlite3.connect(DB_FILE)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY, full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
            phone TEXT, is_admin INTEGER DEFAULT 0,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TEXT,
            created_at TEXT DEFAULT (datetime('now')))""")
        c.execute("""CREATE TABLE IF NOT EXISTS accounts (
            account_id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
            balance REAL DEFAULT 0.0, status TEXT DEFAULT 'active',
            FOREIGN KEY (user_id) REFERENCES users(user_id))""")
        c.execute("""CREATE TABLE IF NOT EXISTS transactions (
            txn_id TEXT PRIMARY KEY, account_id TEXT NOT NULL,
            txn_type TEXT NOT NULL, amount REAL NOT NULL,
            balance_after REAL NOT NULL, description TEXT,
            merchant TEXT, location TEXT, fraud_score INTEGER DEFAULT 0,
            status TEXT DEFAULT 'success',
            timestamp TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (account_id) REFERENCES accounts(account_id))""")
        c.execute("""CREATE TABLE IF NOT EXISTS fraud_reports (
            report_id TEXT PRIMARY KEY, txn_id TEXT NOT NULL,
            account_id TEXT NOT NULL, user_id TEXT NOT NULL,
            reason TEXT NOT NULL, evidence TEXT,
            status TEXT DEFAULT 'pending', fraud_score INTEGER DEFAULT 0,
            submitted_at TEXT DEFAULT (datetime('now')),
            reviewed_at TEXT, reviewed_by TEXT,
            admin_notes TEXT, refund_txn_id TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS verifications (
            verification_id  TEXT PRIMARY KEY,
            report_id        TEXT NOT NULL,
            txn_id           TEXT NOT NULL,
            account_id       TEXT NOT NULL,
            merchant         TEXT NOT NULL,
            amount           REAL NOT NULL,
            status           TEXT DEFAULT 'pending',
            document_type    TEXT,
            document_name    TEXT,
            document_path    TEXT,
            video_requested  INTEGER DEFAULT 0,
            created_at       TEXT DEFAULT (datetime('now')),
            deadline_at      TEXT NOT NULL,
            resolved_at      TEXT,
            admin_notes      TEXT,
            last_reminder_sent TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS admin_audit_log (
            log_id TEXT PRIMARY KEY, admin_id TEXT NOT NULL,
            action TEXT NOT NULL, target_id TEXT, detail TEXT,
            performed_at TEXT DEFAULT (datetime('now')))""")
        c.execute("""CREATE TABLE IF NOT EXISTS password_resets (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')))""")
        c.execute("""CREATE TABLE IF NOT EXISTS login_log (
            log_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            ip_address TEXT,
            status TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')))""")
        c.execute("""CREATE TABLE IF NOT EXISTS blacklisted_merchants (
            id TEXT PRIMARY KEY,
            merchant_name TEXT UNIQUE NOT NULL,
            reason TEXT,
            added_by TEXT NOT NULL,
            added_at TEXT DEFAULT (datetime('now')))""")
        conn.commit()
        conn.close()
    print("[✓] Database ready.")


def migrate_database():
    """
    Safely adds new columns/tables to an existing DB.
    Uses ALTER TABLE ADD COLUMN — never drops data.
    Safe to run on every startup.
    """
    if USING_POSTGRES:
        conn = get_connection()
        pg_migrations = [
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_attempts INTEGER DEFAULT 0",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TEXT",
            "ALTER TABLE verifications ADD COLUMN IF NOT EXISTS last_reminder_sent TEXT",
            """CREATE TABLE IF NOT EXISTS password_resets (
                token TEXT PRIMARY KEY, user_id TEXT NOT NULL,
                expires_at TEXT NOT NULL, used INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (to_char(NOW(),'YYYY-MM-DD HH24:MI:SS')))""",
            """CREATE TABLE IF NOT EXISTS login_log (
                log_id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
                ip_address TEXT, status TEXT NOT NULL,
                created_at TEXT DEFAULT (to_char(NOW(),'YYYY-MM-DD HH24:MI:SS')))""",
            """CREATE TABLE IF NOT EXISTS blacklisted_merchants (
                id TEXT PRIMARY KEY, merchant_name TEXT UNIQUE NOT NULL,
                reason TEXT, added_by TEXT NOT NULL,
                added_at TEXT DEFAULT (to_char(NOW(),'YYYY-MM-DD HH24:MI:SS')))""",
        ]
        for sql in pg_migrations:
            try: conn.run(sql)
            except Exception as e: print(f"[migrate] skipped: {e}")
        conn.run("COMMIT")
        conn.close()
    else:
        conn = sqlite3.connect(DB_FILE)
        conn.execute("PRAGMA journal_mode=WAL")
        c = conn.cursor()

        def add_col(table, col, defn):
            try:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {defn}")
                print(f"[migrate] Added {table}.{col}")
            except sqlite3.OperationalError:
                pass  # column already exists — safe to ignore

        add_col("users", "failed_attempts", "INTEGER DEFAULT 0")
        add_col("users", "locked_until", "TEXT")
        add_col("verifications", "last_reminder_sent", "TEXT")
        add_col("verifications", "reminder_sent", "TEXT")  # legacy compat
        add_col("verifications", "document_path", "TEXT")  # stored file path

        # New tables (IF NOT EXISTS = safe if they already exist)
        c.execute("""CREATE TABLE IF NOT EXISTS password_resets (
            token TEXT PRIMARY KEY, user_id TEXT NOT NULL,
            expires_at TEXT NOT NULL, used INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')))""")
        c.execute("""CREATE TABLE IF NOT EXISTS login_log (
            log_id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
            ip_address TEXT, status TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')))""")
        c.execute("""CREATE TABLE IF NOT EXISTS blacklisted_merchants (
            id TEXT PRIMARY KEY, merchant_name TEXT UNIQUE NOT NULL,
            reason TEXT, added_by TEXT NOT NULL,
            added_at TEXT DEFAULT (datetime('now')))""")

        conn.commit()
        conn.close()
    print("[✓] Migration complete.")


if __name__ == "__main__":
    initialize_database()
    migrate_database()