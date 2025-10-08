from flask import Flask, request, jsonify
from db import init_db
from crypto_utils import hash_password, verify_password
import sqlite3, json

DB_FILE = "users.db"

app = Flask(__name__)
init_db()

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data["username"]
    password = data["password"]
    algo = data.get("algo", "sha256")

    hashed = hash_password(algo, password)
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, hash, algo) VALUES (?, ?, ?)",
                  (username, hashed, algo))
        conn.commit()
        return jsonify({"status": "ok"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "username exists"}), 400
    finally:
        conn.close()

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data["username"]
    password = data["password"]
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT hash FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    if row and verify_password(row[0], password):
        return jsonify({"status": "ok"}), 200
    return jsonify({"error": "invalid credentials"}), 401

if __name__ == "__main__":
    app.run(debug=True)
