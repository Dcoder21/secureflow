import os
import requests
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
from decimal import Decimal

app = Flask(__name__)
CORS(app)

# ============================================================
# VULNERABILITY: Hardcoded service URL and credentials
# ============================================================
AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL", "http://auth-service:5001")

DB_CONFIG = {
    "dbname": os.getenv("DB_NAME", "secureflow_transactions"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", "postgres"),
    "host": os.getenv("DB_HOST", "postgres"),
    "port": os.getenv("DB_PORT", "5432"),
}


def get_db():
    conn = psycopg2.connect(**DB_CONFIG)
    conn.autocommit = True
    return conn


def init_db():
    """Initialize transaction tables."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            account_number VARCHAR(20) UNIQUE NOT NULL,
            balance DECIMAL(15, 2) DEFAULT 1000.00,
            currency VARCHAR(3) DEFAULT 'USD',
            account_type VARCHAR(20) DEFAULT 'checking',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id SERIAL PRIMARY KEY,
            from_account VARCHAR(20),
            to_account VARCHAR(20),
            amount DECIMAL(15, 2) NOT NULL,
            transaction_type VARCHAR(20) NOT NULL,
            description TEXT,
            status VARCHAR(20) DEFAULT 'completed',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS virtual_cards (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            card_number VARCHAR(19) NOT NULL,
            cvv VARCHAR(4) NOT NULL,
            expiry_date VARCHAR(7) NOT NULL,
            balance DECIMAL(15, 2) DEFAULT 0.00,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.close()


def validate_token(f):
    """Validate JWT by calling auth-service."""
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
            # Call auth service to validate
            resp = requests.post(
                f"{AUTH_SERVICE_URL}/api/auth/validate",
                json={"token": token},
                timeout=5,
            )
            if resp.status_code != 200:
                return jsonify({"error": "Invalid token"}), 401
            current_user = resp.json().get("user")
        except requests.exceptions.RequestException:
            return jsonify({"error": "Auth service unavailable"}), 503

        return f(current_user, *args, **kwargs)
    return decorated


# -----------------------------------------------------------
# ACCOUNT ROUTES
# -----------------------------------------------------------

@app.route("/api/transactions/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "service": "transaction-service"})


@app.route("/api/transactions/account", methods=["POST"])
@validate_token
def create_account(current_user):
    """Create a new bank account for the user."""
    import random
    account_number = "".join([str(random.randint(0, 9)) for _ in range(10)])

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO accounts (user_id, account_number) VALUES (%s, %s) RETURNING id, account_number, balance",
        (current_user["user_id"], account_number),
    )
    account = cur.fetchone()
    conn.close()

    return jsonify({
        "id": account[0],
        "account_number": account[1],
        "balance": float(account[2]),
    }), 201


@app.route("/api/transactions/account/<account_number>", methods=["GET"])
@validate_token
def get_account(current_user, account_number):
    """Get account details."""
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    # VULNERABILITY: IDOR — no check that account belongs to current_user
    cur.execute("SELECT * FROM accounts WHERE account_number = %s", (account_number,))
    account = cur.fetchone()
    conn.close()

    if not account:
        return jsonify({"error": "Account not found"}), 404

    account["balance"] = float(account["balance"])
    return jsonify(account)


@app.route("/api/transactions/balance", methods=["GET"])
@validate_token
def get_balance(current_user):
    """Get all accounts and balances for current user."""
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM accounts WHERE user_id = %s", (current_user["user_id"],))
    accounts = cur.fetchall()
    conn.close()

    for acc in accounts:
        acc["balance"] = float(acc["balance"])
    return jsonify(accounts)


# -----------------------------------------------------------
# TRANSFER ROUTES
# -----------------------------------------------------------

@app.route("/api/transactions/transfer", methods=["POST"])
@validate_token
def transfer(current_user):
    """Transfer money between accounts."""
    data = request.get_json()
    from_account = data.get("from_account")
    to_account = data.get("to_account")
    amount = data.get("amount")

    # VULNERABILITY: No validation that amount is positive — allows negative transfers
    # VULNERABILITY: No check that from_account belongs to current_user
    if not all([from_account, to_account, amount]):
        return jsonify({"error": "Missing required fields"}), 400

    amount = Decimal(str(amount))

    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    # Check sender balance
    cur.execute("SELECT * FROM accounts WHERE account_number = %s", (from_account,))
    sender = cur.fetchone()

    if not sender:
        conn.close()
        return jsonify({"error": "Sender account not found"}), 404

    if sender["balance"] < amount:
        conn.close()
        return jsonify({"error": "Insufficient funds"}), 400

    # Check receiver exists
    cur.execute("SELECT * FROM accounts WHERE account_number = %s", (to_account,))
    receiver = cur.fetchone()

    if not receiver:
        conn.close()
        return jsonify({"error": "Receiver account not found"}), 404

    # VULNERABILITY: No transaction isolation — race condition possible
    cur.execute("UPDATE accounts SET balance = balance - %s WHERE account_number = %s",
                (amount, from_account))
    cur.execute("UPDATE accounts SET balance = balance + %s WHERE account_number = %s",
                (amount, to_account))

    # Record transaction
    cur.execute(
        """INSERT INTO transactions (from_account, to_account, amount, transaction_type, description)
           VALUES (%s, %s, %s, 'transfer', %s) RETURNING id""",
        (from_account, to_account, amount, data.get("description", "Transfer")),
    )
    tx_id = cur.fetchone()["id"]
    conn.close()

    return jsonify({"message": "Transfer successful", "transaction_id": tx_id})


@app.route("/api/transactions/history/<account_number>", methods=["GET"])
@validate_token
def transaction_history(current_user, account_number):
    """Get transaction history for an account."""
    # VULNERABILITY: IDOR — no ownership check
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute(
        """SELECT * FROM transactions
           WHERE from_account = %s OR to_account = %s
           ORDER BY created_at DESC LIMIT 50""",
        (account_number, account_number),
    )
    transactions = cur.fetchall()
    conn.close()

    for tx in transactions:
        tx["amount"] = float(tx["amount"])
    return jsonify(transactions)


# -----------------------------------------------------------
# VIRTUAL CARD ROUTES
# -----------------------------------------------------------

@app.route("/api/transactions/virtual-card", methods=["POST"])
@validate_token
def create_virtual_card(current_user):
    """Create a virtual debit card."""
    import random

    card_number = "-".join(
        ["".join([str(random.randint(0, 9)) for _ in range(4)]) for _ in range(4)]
    )
    cvv = str(random.randint(100, 999))
    expiry = "12/2028"

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO virtual_cards (user_id, card_number, cvv, expiry_date)
           VALUES (%s, %s, %s, %s) RETURNING id""",
        (current_user["user_id"], card_number, cvv, expiry),
    )
    card_id = cur.fetchone()[0]
    conn.close()

    # VULNERABILITY: Returning CVV in the response
    return jsonify({
        "id": card_id,
        "card_number": card_number,
        "cvv": cvv,
        "expiry_date": expiry,
        "balance": 0.00,
    }), 201


@app.route("/api/transactions/virtual-card/fund", methods=["POST"])
@validate_token
def fund_virtual_card(current_user):
    """Fund virtual card from bank account."""
    data = request.get_json()
    card_id = data.get("card_id")
    from_account = data.get("from_account")
    amount = data.get("amount")

    # VULNERABILITY: mass assignment — user can pass extra fields like card_number to override
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    # Debit account
    cur.execute("UPDATE accounts SET balance = balance - %s WHERE account_number = %s AND balance >= %s",
                (amount, from_account, amount))

    # Credit card
    cur.execute("UPDATE virtual_cards SET balance = balance + %s WHERE id = %s",
                (amount, card_id))
    conn.close()

    return jsonify({"message": "Card funded successfully"})


# -----------------------------------------------------------
# STARTUP
# -----------------------------------------------------------

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5002, debug=True)
