import os
import jwt
import datetime
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)

# ============================================================
# VULNERABILITY: Hardcoded secret key (should be in Vault)
# ============================================================
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-key-123")
JWT_ALGORITHM = "HS256"

# ============================================================
# VULNERABILITY: Database credentials in environment/hardcoded
# ============================================================
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME", "secureflow_auth"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", "postgres"),
    "host": os.getenv("DB_HOST", "postgres"),
    "port": os.getenv("DB_PORT", "5432"),
}


def get_db():
    """Get database connection."""
    conn = psycopg2.connect(**DB_CONFIG)
    conn.autocommit = True
    return conn


def init_db():
    """Initialize database tables."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(80) UNIQUE NOT NULL,
            email VARCHAR(120) UNIQUE NOT NULL,
            password_hash VARCHAR(256) NOT NULL,
            role VARCHAR(20) DEFAULT 'user',
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reset_pin VARCHAR(10) DEFAULT NULL
        )
    """)
    # VULNERABILITY: Default admin with weak credentials
    admin_exists = cur.execute("SELECT id FROM users WHERE username = 'admin'")
    result = cur.fetchone()
    if not result:
        cur.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (%s, %s, %s, %s)",
            ("admin", "admin@secureflow.local",
             generate_password_hash("admin123"), "admin"),
        )
    conn.close()


def token_required(f):
    """JWT authentication decorator."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            auth_header = request.headers["Authorization"]
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

        if not token:
            return jsonify({"error": "Token is missing"}), 401

        try:
            # VULNERABILITY: No algorithm restriction — allows 'none' algorithm
            data = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM, "none"])
            current_user = data
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        return f(current_user, *args, **kwargs)
    return decorated


# -----------------------------------------------------------
# ROUTES
# -----------------------------------------------------------

@app.route("/api/auth/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "service": "auth-service"})


@app.route("/api/auth/register", methods=["POST"])
def register():
    """Register a new user."""
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not all([username, email, password]):
        return jsonify({"error": "Missing required fields"}), 400

    # VULNERABILITY: No password strength validation
    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s) RETURNING id",
            (username, email, generate_password_hash(password)),
        )
        user_id = cur.fetchone()[0]
        conn.close()
        return jsonify({"message": "User registered", "user_id": user_id}), 201
    except psycopg2.IntegrityError:
        conn.close()
        return jsonify({"error": "Username or email already exists"}), 409


@app.route("/api/auth/login", methods=["POST"])
def login():
    """Authenticate and return JWT."""
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    # ============================================================
    # VULNERABILITY: SQL Injection on login
    # ============================================================
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cur.execute(query)
    user = cur.fetchone()
    conn.close()

    if user and check_password_hash(user["password_hash"], password):
        token = jwt.encode(
            {
                "user_id": user["id"],
                "username": user["username"],
                "role": user["role"],
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24),
            },
            SECRET_KEY,
            algorithm=JWT_ALGORITHM,
        )
        return jsonify({"token": token, "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
        }})

    # VULNERABILITY: Different error messages for invalid user vs wrong password
    if not user:
        return jsonify({"error": "User not found"}), 401
    return jsonify({"error": "Incorrect password"}), 401


@app.route("/api/auth/profile", methods=["GET"])
@token_required
def get_profile(current_user):
    """Get current user's profile."""
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT id, username, email, role, created_at FROM users WHERE id = %s",
                (current_user["user_id"],))
    user = cur.fetchone()
    conn.close()
    return jsonify(user)


@app.route("/api/auth/users/<int:user_id>", methods=["GET"])
@token_required
def get_user(current_user, user_id):
    """Get user by ID."""
    # VULNERABILITY: No authorization check — any authenticated user can view any profile (IDOR)
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT id, username, email, role, created_at FROM users WHERE id = %s",
                (user_id,))
    user = cur.fetchone()
    conn.close()

    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user)


@app.route("/api/auth/forgot-password", methods=["POST"])
def forgot_password():
    """Send password reset PIN."""
    data = request.get_json()
    email = data.get("email")

    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT id FROM users WHERE email = %s", (email,))
    user = cur.fetchone()

    if user:
        # VULNERABILITY: Weak 3-digit PIN, no rate limiting, no expiry
        import random
        pin = str(random.randint(100, 999))
        cur.execute("UPDATE users SET reset_pin = %s WHERE id = %s", (pin, user["id"]))
        conn.close()
        # In production this would send an email. Here it just returns success.
        return jsonify({"message": "Reset PIN sent to email"})

    conn.close()
    return jsonify({"message": "Reset PIN sent to email"})  # No user enumeration


@app.route("/api/auth/reset-password", methods=["POST"])
def reset_password():
    """Reset password with PIN."""
    data = request.get_json()
    email = data.get("email")
    pin = data.get("pin")
    new_password = data.get("new_password")

    # VULNERABILITY: No rate limiting on PIN attempts — brute-forceable (only 900 possibilities)
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT id, reset_pin FROM users WHERE email = %s", (email,))
    user = cur.fetchone()

    if user and user["reset_pin"] == pin:
        cur.execute(
            "UPDATE users SET password_hash = %s, reset_pin = NULL WHERE id = %s",
            (generate_password_hash(new_password), user["id"]),
        )
        conn.close()
        return jsonify({"message": "Password reset successful"})

    conn.close()
    return jsonify({"error": "Invalid PIN"}), 400


@app.route("/api/auth/validate", methods=["POST"])
def validate_token():
    """Internal endpoint: validate JWT for other services."""
    token = request.get_json().get("token")
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return jsonify({"valid": True, "user": data})
    except jwt.InvalidTokenError:
        return jsonify({"valid": False}), 401


# -----------------------------------------------------------
# ADMIN ROUTES
# -----------------------------------------------------------

@app.route("/api/auth/admin/users", methods=["GET"])
@token_required
def admin_list_users(current_user):
    """List all users (admin only)."""
    # VULNERABILITY: Role check uses client-supplied JWT claim, not DB lookup
    if current_user.get("role") != "admin":
        return jsonify({"error": "Admin access required"}), 403

    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT id, username, email, role, is_active, created_at FROM users")
    users = cur.fetchall()
    conn.close()
    return jsonify(users)


# -----------------------------------------------------------
# STARTUP
# -----------------------------------------------------------

if __name__ == "__main__":
    init_db()
    # VULNERABILITY: Debug mode enabled in production
    app.run(host="0.0.0.0", port=5001, debug=True)
