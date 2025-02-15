from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import bcrypt
import datetime
import uuid

app = Flask(__name__)
CORS(app)

SECRET_KEY = "MySecretKey123"  # Change this to your own secret

# Initialize Database
def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            session_token TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# Register a New User (Only Owner Can)
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data["username"]
    password = data["password"].encode("utf-8")
    secret = data.get("secret", "")

    # Only allow account creation if secret key is correct
    if secret != SECRET_KEY:
        return jsonify({"error": "Unauthorized access"}), 403

    hashed_pw = bcrypt.hashpw(password, bcrypt.gensalt())
    expires_at = (datetime.datetime.utcnow() + datetime.timedelta(days=30)).isoformat()

    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password_hash, expires_at) VALUES (?, ?, ?)", 
                       (username, hashed_pw, expires_at))
        conn.commit()
        conn.close()
        return jsonify({"message": "User registered successfully"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 400

# Login User (Anyone with an account can log in)
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data["username"]
    password = data["password"].encode("utf-8")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, expires_at, session_token FROM users WHERE username=?", (username,))
    result = cursor.fetchone()
    
    if not result:
        conn.close()
        return jsonify({"error": "Invalid username or password"}), 401
    
    stored_hash, expires_at, session_token = result
    
    # Check if account is expired
    if datetime.datetime.utcnow() > datetime.datetime.fromisoformat(expires_at):
        conn.close()
        return jsonify({"error": "Account has expired"}), 403

    # Check password
    if not bcrypt.checkpw(password, stored_hash):
        conn.close()
        return jsonify({"error": "Invalid username or password"}), 401

    # Enforce single session per user
    if session_token:
        conn.close()
        return jsonify({"error": "User already logged in on another device"}), 403
    
    # Generate new session token
    new_session_token = str(uuid.uuid4())
    cursor.execute("UPDATE users SET session_token=? WHERE username=?", (new_session_token, username))
    conn.commit()
    conn.close()

    return jsonify({"message": "Login successful!", "session_token": new_session_token}), 200

# Logout User
@app.route("/logout", methods=["POST"])
def logout():
    data = request.json
    username = data["username"]
    session_token = data.get("session_token")
    
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT session_token FROM users WHERE username=?", (username,))
    result = cursor.fetchone()
    
    if not result or result[0] != session_token:
        conn.close()
        return jsonify({"error": "Invalid session"}), 401
    
    cursor.execute("UPDATE users SET session_token=NULL WHERE username=?", (username,))
    conn.commit()
    conn.close()
    
    return jsonify({"message": "Logout successful"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
