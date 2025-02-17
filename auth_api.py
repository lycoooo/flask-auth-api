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
            expires_at TEXT NOT NULL,
            session_token TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ----------------------- REGISTER -----------------------
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    secret = data.get("secret", "")
    duration_minutes = int(data.get("expires_in", 43200))  # Default: 30 days (43200 minutes)

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if secret != SECRET_KEY:
        return jsonify({"error": "Unauthorized access"}), 403

    if duration_minutes <= 0:
        return jsonify({"error": "Invalid expiration time"}), 400

    # Convert minutes to expiration timestamp
    expires_at = (datetime.datetime.utcnow() + datetime.timedelta(minutes=duration_minutes)).isoformat()

    # Hash password
    hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password_hash, expires_at) VALUES (?, ?, ?)", 
                       (username, hashed_pw, expires_at))
        conn.commit()
        conn.close()
        return jsonify({"message": "User registered successfully", "expires_in": duration_minutes}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 400

# ----------------------- LOGIN -----------------------
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "").encode("utf-8")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, expires_at, session_token FROM users WHERE username=?", (username,))
    result = cursor.fetchone()
    
    if not result:
        conn.close()
        return jsonify({"error": "Invalid username or password"}), 401
    
    stored_hash, expires_at, session_token = result

    # Convert expiration date
    try:
        expiry_date = datetime.datetime.fromisoformat(expires_at)
    except ValueError:
        conn.close()
        return jsonify({"error": "Invalid expiration date format"}), 500

    minutes_remaining = (expiry_date - datetime.datetime.utcnow()).total_seconds() / 60

    # Check if account is expired
    if minutes_remaining <= 0:
        conn.close()
        return jsonify({"error": "Your account has expired. Please contact My Telegram @lyco0202."}), 403

    # Check password
    if not bcrypt.checkpw(password, stored_hash):
        conn.close()
        return jsonify({"error": "Invalid username or password"}), 401

    # Prevent duplicate logins unless session expires
    if session_token:
        conn.close()
        return jsonify({
            "error": "This account is already logged in on another device. Please log out first."
        }), 403

    # Generate a new session token
    new_session_token = str(uuid.uuid4())
    cursor.execute("UPDATE users SET session_token=? WHERE username=?", (new_session_token, username))
    conn.commit()
    conn.close()

    return jsonify({
        "message": "✅ Login successful!",
        "session_token": new_session_token,
        "expires_in": round(minutes_remaining)  # Convert to minutes
    }), 200

# ----------------------- LOGOUT -----------------------
@app.route("/logout", methods=["POST"])
def logout():
    data = request.json
    username = data.get("username", "").strip()
    session_token = data.get("session_token", "").strip()

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

    return jsonify({"message": "✅ Logout successful"}), 200

# ----------------------- CHECK EXPIRATION -----------------------
@app.route("/check_expiration", methods=["POST"])
def check_expiration():
    data = request.json
    username = data.get("username", "").strip()

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT expires_at FROM users WHERE username=?", (username,))
    result = cursor.fetchone()

    if not result:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    expires_at = result[0]
    expiry_date = datetime.datetime.fromisoformat(expires_at)
    minutes_remaining = (expiry_date - datetime.datetime.utcnow()).total_seconds() / 60

    conn.close()
    
    if minutes_remaining <= 0:
        return jsonify({"error": "Account expired"}), 403
    
    return jsonify({"message": f"Account is active, expires in {round(minutes_remaining)} minutes"}), 200

# ----------------------- RUN THE APP -----------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
