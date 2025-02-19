from flask import Flask, request, jsonify
from flask_cors import CORS
import secrets
import datetime

app = Flask(__name__)
CORS(app)  # ✅ Enable CORS for frontend access

# 🔐 Fake database to store accounts
accounts = []

# 🔑 Secret key for authentication
SECRET_KEY = "MySecretKey123"

# 🕒 Expiration mapping in minutes
DURATION_MAPPING = {
    "2m": 2,
    "2h": 120,
    "5h": 300,
    "1d": 1440,
    "3d": 4320,
    "7d": 10080,
    "30d": 43200
}

@app.route("/register", methods=["POST"])
def register():
    try:
        data = request.get_json()

        # ✅ Check if secret key is correct
        if data.get("secret") != SECRET_KEY:
            return jsonify({"error": "Unauthorized access!"}), 403

        password = data.get("password")
        expires_in = int(data.get("expires_in", 1440))  # Default 1 Day

        if not password:
            return jsonify({"error": "Password is required!"}), 400

        # ✅ Generate unique token
        token = secrets.token_hex(16)
        expiration_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=expires_in)

        # 🛠️ Save to in-memory database
        accounts.append({
            "password": password,
            "token": token,
            "expires_at": expiration_time.strftime("%Y-%m-%d %H:%M:%S UTC")
        })

        return jsonify({
            "message": "User registered successfully",
            "password": password,
            "expires_at": expiration_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "token": token
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/accounts", methods=["GET"])
def get_accounts():
    return jsonify({"accounts": accounts})


if __name__ == "__main__":
    app.run(debug=True)
