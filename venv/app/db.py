import sqlite3

DB_FILE = "users.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
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
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS mfa_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            method TEXT,
            success INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
