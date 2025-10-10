import sqlite3

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
            success INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()
