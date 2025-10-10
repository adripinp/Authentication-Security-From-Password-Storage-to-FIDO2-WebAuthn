from dotenv import load_dotenv
load_dotenv()                               # load .env in os.environ

from flask import Flask, request, jsonify      #Imports Flask and helpers to receive JSON requests and send JSON responses.
from app.db import init_db, get_connection
from app.crypto_utils import hash_password, verify_password
import sqlite3, json

app = Flask(__name__)      #Creates the Flask app.
init_db()                  #Creates the database/tables at app startup (runs on every process that imports this module).


@app.route("/register", methods=["POST"])     #registration endpoint
def register():                               #Extracts username, password, and algoritm
    data = request.json
    username = data.get("username")
    password = data.get("password")
    algo = data.get("algo", "sha256")

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400  

    hashed = hash_password(algo, password)
    conn = get_connection()
    c = conn.cursor()

    try:       #  Opens DB connection, inserts (username, hashed, algo) into users.
        c.execute("INSERT INTO users (username, hash, algo) VALUES (?, ?, ?)",
                  (username, hashed, algo))
        conn.commit()
        return jsonify({"status": "registered"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "username already exists"}), 400
    finally:
        conn.close()     #ensures the DB connection is closed

@app.route("/login", methods=["POST"])        #login endpoint
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT hash FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()

    if row and verify_password(row[0], password):
        return jsonify({"status": "ok"}), 200
    return jsonify({"error": "invalid credentials"}), 401

if __name__ == "__main__":
    app.run(debug=True)
