import sqlite3
import json
from typing import Optional, Tuple
#A constant with the filename (relative path) of the SQLite database. When you call sqlite3.connect(DB_FILE) it will create the file if it doesn’t exist.
DB_FILE = "users.db"   

#A small helper that returns a new sqlite3.Connection connected to users.db. Every call creates a new connection object.
def get_connection():
    return sqlite3.connect(DB_FILE)

def init_db():
    conn = get_connection()   #obtains a connection
    c = conn.cursor()         #creates a cursor

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            salt TEXT,
            hash TEXT,
            algo TEXT,
            cost_params TEXT,
            pepper_used INTEGER DEFAULT 0,
            mfa_enabled INTEGER DEFAULT 0,
            mfa_meta_json TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS mfa_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            method TEXT,
            success INTEGER NOT NULL DEFAULT 0,
            detail TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS webauthn_credentials(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            rp_id TEXT NOT NULL,
            credential_id BLOB NOT NULL,
            public_key BLOB NOT NULL,
            sign_count INTEGER DEFAULT 0,
            UNIQUE(user_id, credential_id)
        )
    """)


    conn.commit()
    conn.close()

def query_one(sql: str, params: tuple = ()):
    with get_connection() as conn:
        cur = conn.execute(sql, params)
        return cur.fetchone()  # returns sqlite3.Row or None

def query_all(sql: str, params: tuple = ()):
    with get_connection() as conn:
        cur = conn.execute(sql, params)
        return cur.fetchall()  # list[sqlite3.Row]

def exec_sql(sql: str, params: tuple = ()):
    with get_connection() as conn:
        conn.execute(sql, params)
        conn.commit()

def mfa_log(user_id: int, method: str, success: bool, detail: str = "") -> None:
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO mfa_logs(user_id,method,success,detail) VALUES(?,?,?,?)",
            (user_id, method, 1 if success else 0, detail)
        )

def get_user_by_username(username: str) -> Optional[dict]:
    row = query_one(""" SELECT id, username, salt, hash, algo, cost_params, pepper_used, mfa_enabled, mfa_meta_json
                        FROM users WHERE username=? """,
                        (username,))
    if not row:
        return None

    cols = ["id","username","salt","hash","algo","cost_params","pepper_used","mfa_enabled","mfa_meta_json"]
    d = dict(zip(cols, row))

    try:
        d["mfa_meta"] = json.loads(d["mfa_meta_json"] or "{}")
    except Exception:
        d["mfa_meta"] = {}
    return d

def update_mfa_meta(user_id: int, meta: dict) -> None:
    exec_sql("UPDATE users SET mfa_meta_json=? WHERE id=?", 
             (json.dumps(meta), user_id))

# WebAuthn helpers
def webauthn_save_credential(user_id: int, rp_id: str, credential_id: bytes, public_key: bytes, sign_count: int) -> None:
    exec_sql("""INSERT OR REPLACE INTO webauthn_credentials(user_id,rp_id,credential_id,public_key,sign_count)
                VALUES(?,?,?,?,?)""", 
                (user_id, rp_id, credential_id, public_key, sign_count))

def webauthn_list_credentials(user_id: int) -> list[bytes]:
    rows = query_all("SELECT credential_id FROM webauthn_credentials WHERE user_id=?", 
                     (user_id,))
    return [r[0] for r in rows]

def webauthn_get_credential(user_id: int, credential_id: bytes) -> Optional[Tuple[bytes,int]]:
    row = query_one("SELECT public_key, sign_count FROM webauthn_credentials WHERE user_id=? AND credential_id=?", 
                    (user_id, credential_id))
    return (row[0], row[1]) if row else None

def webauthn_update_sign_count(user_id: int, credential_id: bytes, new_count: int) -> None:
    exec_sql("UPDATE webauthn_credentials SET sign_count=? WHERE user_id=? AND credential_id=?", 
           (new_count, user_id, credential_id))