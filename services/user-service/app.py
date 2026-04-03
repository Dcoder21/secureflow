# =============================================================================
# user-service — INTENTIONALLY VULNERABLE
# Role: User registration, login, profile management
#
# Vulnerabilities present (for DevSecOps demo):
#   [VULN-01] SQL injection in /login and /register (string concatenation queries)
#   [VULN-02] Hardcoded JWT secret in source code
#   [VULN-03] MD5 used for password hashing (broken, rainbow-table crackable)
#   [VULN-04] /users endpoint returns ALL users including password hashes — no auth
#   [VULN-05] /debug/cmd — unauthenticated OS command execution (RCE)
#   [VULN-06] Flask debug=True — interactive debugger exposed on errors
#   [VULN-07] Hardcoded DB credentials in source code
#   [VULN-08] No input validation or sanitisation anywhere
#   [VULN-09] JWT tokens have no expiry (iat but no exp claim)
# =============================================================================

import os
import hashlib
import subprocess
from flask import Flask, request, jsonify
import jwt
import psycopg2

app = Flask(__name__)

# [VULN-02] Hardcoded JWT secret — should be a 256-bit random secret from Vault
JWT_SECRET = 'supersecret123'

# [VULN-07] Hardcoded DB credentials — shared across all services, never rotated
DB_CONFIG = {
    'host':     os.environ.get('DB_HOST', 'postgres'),
    'database': 'shopdb',
    'user':     'admin',
    'password': 'admin123',
}


def get_db():
    return psycopg2.connect(**DB_CONFIG)


@app.route('/register', methods=['POST'])
def register():
    data     = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    email    = data.get('email', '')

    # [VULN-03] MD5 — completely broken for password storage
    hashed = hashlib.md5(password.encode()).hexdigest()

    conn = get_db()
    cur  = conn.cursor()

    # [VULN-01] SQL injection — e.g., username: admin', 'x', 'x@x.com', 'admin') --
    query = (
        f"INSERT INTO users (username, password, email, role) "
        f"VALUES ('{username}', '{hashed}', '{email}', 'user')"
    )
    cur.execute(query)
    conn.commit()
    conn.close()
    return jsonify({'message': 'registered'}), 201


@app.route('/login', methods=['POST'])
def login():
    data     = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')

    # [VULN-03] MD5
    hashed = hashlib.md5(password.encode()).hexdigest()

    conn = get_db()
    cur  = conn.cursor()

    # [VULN-01] SQL injection authentication bypass
    # Payload: username = "admin' --"  (skips password check entirely)
    query = (
        f"SELECT id, username, role FROM users "
        f"WHERE username='{username}' AND password='{hashed}'"
    )
    cur.execute(query)
    user = cur.fetchone()
    conn.close()

    if user:
        # [VULN-09] No 'exp' claim — token is valid forever
        token = jwt.encode(
            {'user_id': user[0], 'username': user[1], 'role': user[2]},
            JWT_SECRET,
            algorithm='HS256',
        )
        return jsonify({'token': token})

    return jsonify({'error': 'invalid credentials'}), 401


@app.route('/users', methods=['GET'])
def list_users():
    # [VULN-04] No authentication — anyone can dump all users + password hashes
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT id, username, email, password, role FROM users")
    rows = cur.fetchall()
    conn.close()
    return jsonify([
        {'id': r[0], 'username': r[1], 'email': r[2], 'password': r[3], 'role': r[4]}
        for r in rows
    ])


@app.route('/users/<user_id>', methods=['GET'])
def get_user(user_id):
    # [VULN-01] SQL injection via path parameter, no auth check
    conn = get_db()
    cur  = conn.cursor()
    query = f"SELECT id, username, email, role FROM users WHERE id={user_id}"
    cur.execute(query)
    row = cur.fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'not found'}), 404
    return jsonify({'id': row[0], 'username': row[1], 'email': row[2], 'role': row[3]})


@app.route('/debug/cmd', methods=['GET'])
def debug_cmd():
    # [VULN-05] Unauthenticated RCE — curl http://user-service:5000/debug/cmd?cmd=id
    cmd = request.args.get('cmd', 'whoami')
    result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
    return result, 200, {'Content-Type': 'text/plain'}


if __name__ == '__main__':
    # [VULN-06] debug=True — Flask interactive debugger accessible over the network
    app.run(host='0.0.0.0', port=5000, debug=True)
