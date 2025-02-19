from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import bcrypt
import datetime
import uuid

app = Flask(__name__)
CORS(app)

SECRET_KEY = "MySecretKey123"  # Change this to your own secret key

# Initialize Database
def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            login_at TEXT,
            duration_minutes INTEGER NOT NULL,
            session_token TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ----------------------- LOGIN (Fixed Expiration Handling) -----------------------
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "").encode("utf-8")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, login_at, duration_minutes, session_token FROM users WHERE username=?", (username,))
    result = cursor.fetchone()

    if not result:
        conn.close()
        return jsonify({"error": "Invalid username or password"}), 401  # Username not found

    stored_hash, login_at, duration_minutes, session_token = result

    # Check if the account has expired
    if login_at:
        login_time = datetime.datetime.fromisoformat(login_at)
        expiration_time = login_time + datetime.timedelta(minutes=duration_minutes)

        if datetime.datetime.utcnow() > expiration_time:
            # Mark user as expired (optional: delete account instead)
            cursor.execute("DELETE FROM users WHERE username=?", (username,))
            conn.commit()
            conn.close()
            return jsonify({"error": "This account has expired. Contact the owner."}), 403

    # Prevent duplicate logins (one session per user)
    if session_token:
        conn.close()
        return jsonify({
            "error": "This account is already logged in on another device."
        }), 403  

    # Check password
    if not bcrypt.checkpw(password, stored_hash):
        conn.close()
        return jsonify({"error": "Invalid username or password"}), 401  

    # Generate a new session token
    new_session_token = str(uuid.uuid4())
    login_at = datetime.datetime.utcnow().isoformat()

    cursor.execute("UPDATE users SET session_token=?, login_at=? WHERE username=?", 
                   (new_session_token, login_at, username))
    conn.commit()
    conn.close()

    expiration_time = datetime.datetime.fromisoformat(login_at) + datetime.timedelta(minutes=duration_minutes)
    minutes_remaining = (expiration_time - datetime.datetime.utcnow()).total_seconds() / 60

    return jsonify({
        "message": "✅ Login successful!",
        "session_token": new_session_token,
        "expires_in": round(minutes_remaining)
    }), 200
