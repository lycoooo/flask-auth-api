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

    hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password_hash, duration_minutes) VALUES (?, ?, ?)", 
                       (username, hashed_pw, duration_minutes))
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
    cursor.execute("SELECT password_hash, login_at, duration_minutes, session_token FROM users WHERE username=?", (username,))
    result = cursor.fetchone()

    if not result:
        conn.close()
        return jsonify({"error": "Invalid username or password"}), 401  # Username not found

    stored_hash, login_at, duration_minutes, session_token = result

    # If the user has logged in before, check expiration
    if login_at:
        login_time = datetime.datetime.fromisoformat(login_at)
        expiration_time = login_time + datetime.timedelta(minutes=duration_minutes)

        if datetime.datetime.utcnow() > expiration_time:
            # Auto-expire account
            cursor.execute("UPDATE users SET session_token=NULL WHERE username=?", (username,))
            conn.commit()
            conn.close()
            return jsonify({"error": "This account has expired. Contact the owner."}), 403

    # Prevent duplicate logins (allow only one active session per user)
    if session_token:
        conn.close()
        return jsonify({
            "error": "This account is already logged in on another device."
        }), 403  # Removed "Please log out first"

    # Check password
    if not bcrypt.checkpw(password, stored_hash):
        conn.close()
        return jsonify({"error": "Invalid username or password"}), 401  # Wrong password

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


# ----------------------- CHECK EXPIRATION -----------------------
@app.route("/check_expiration", methods=["POST"])
def check_expiration():
    data = request.json
    username = data.get("username", "").strip()

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT login_at, duration_minutes FROM users WHERE username=?", (username,))
    result = cursor.fetchone()

    if not result:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    login_at, duration_minutes = result
    if not login_at:
        conn.close()
        return jsonify({"error": "User has not logged in yet"}), 400

    expiry_date = datetime.datetime.fromisoformat(login_at) + datetime.timedelta(minutes=duration_minutes)
    minutes_remaining = (expiry_date - datetime.datetime.utcnow()).total_seconds() / 60

    if minutes_remaining <= 0:
        return jsonify({"error": "Account expired"}), 403

    conn.close()
    return jsonify({"message": f"Account is active, expires in {round(minutes_remaining)} minutes"}), 200

# ----------------------- RUN THE APP -----------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
