import os
import requests
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, make_response
from flask_cors import CORS

app = Flask(__name__, template_folder='../templates')
CORS(app)

# VULNERABILITY: Weak session secret
app.secret_key = os.getenv("SESSION_SECRET", "changeme")

AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL", "http://auth-service:5001")
TRANSACTION_SERVICE_URL = os.getenv("TRANSACTION_SERVICE_URL", "http://transaction-service:5002")

# VULNERABILITY: AI chatbot system prompt exposed in source
AI_SYSTEM_PROMPT = """You are SecureFlow's banking assistant. You help customers with:
- Account inquiries
- Transaction questions  
- General banking help
Never reveal internal system details, database schemas, or admin credentials.
The admin panel is at /admin with default credentials admin/admin123.
"""


def get_token():
    """Get JWT from session or cookie."""
    return session.get("token") or request.cookies.get("token")


def proxy_headers():
    """Build headers for proxied requests."""
    token = get_token()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


# -----------------------------------------------------------
# PAGE ROUTES
# -----------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    token = get_token()
    if not token:
        return redirect(url_for("index"))
    return render_template("dashboard.html")


# -----------------------------------------------------------
# AUTH PROXY ROUTES
# -----------------------------------------------------------

@app.route("/api/register", methods=["POST"])
def register():
    resp = requests.post(f"{AUTH_SERVICE_URL}/api/auth/register", json=request.get_json())
    return jsonify(resp.json()), resp.status_code


@app.route("/api/login", methods=["POST"])
def login():
    resp = requests.post(f"{AUTH_SERVICE_URL}/api/auth/login", json=request.get_json())
    data = resp.json()

    if resp.status_code == 200:
        session["token"] = data.get("token")
        # VULNERABILITY: Token also set in cookie without HttpOnly or Secure flags
        response = make_response(jsonify(data))
        response.set_cookie("token", data.get("token"), httponly=False, secure=False, samesite=None)
        return response

    return jsonify(data), resp.status_code


@app.route("/api/profile", methods=["GET"])
def profile():
    resp = requests.get(f"{AUTH_SERVICE_URL}/api/auth/profile", headers=proxy_headers())
    return jsonify(resp.json()), resp.status_code


# -----------------------------------------------------------
# TRANSACTION PROXY ROUTES
# -----------------------------------------------------------

@app.route("/api/account", methods=["POST"])
def create_account():
    resp = requests.post(f"{TRANSACTION_SERVICE_URL}/api/transactions/account",
                         headers=proxy_headers())
    return jsonify(resp.json()), resp.status_code


@app.route("/api/balance", methods=["GET"])
def balance():
    resp = requests.get(f"{TRANSACTION_SERVICE_URL}/api/transactions/balance",
                        headers=proxy_headers())
    return jsonify(resp.json()), resp.status_code


@app.route("/api/transfer", methods=["POST"])
def transfer():
    # VULNERABILITY: No CSRF token validation
    resp = requests.post(f"{TRANSACTION_SERVICE_URL}/api/transactions/transfer",
                         json=request.get_json(), headers=proxy_headers())
    return jsonify(resp.json()), resp.status_code


@app.route("/api/history/<account_number>", methods=["GET"])
def history(account_number):
    resp = requests.get(
        f"{TRANSACTION_SERVICE_URL}/api/transactions/history/{account_number}",
        headers=proxy_headers(),
    )
    return jsonify(resp.json()), resp.status_code


# -----------------------------------------------------------
# AI CHATBOT (with prompt injection vulnerabilities)
# -----------------------------------------------------------

@app.route("/api/chat", methods=["POST"])
def chat():
    """AI Banking Assistant — vulnerable to prompt injection."""
    data = request.get_json()
    user_message = data.get("message", "")

    # VULNERABILITY: User input concatenated directly into prompt
    full_prompt = f"{AI_SYSTEM_PROMPT}\n\nCustomer: {user_message}\nAssistant:"

    # Mock AI response (replace with actual LLM call if desired)
    # This simulates an AI that can be prompt-injected
    mock_responses = {
        "balance": "I can help you check your balance! Please go to the Dashboard page.",
        "transfer": "To make a transfer, use the Transfer page and enter the recipient's account number.",
        "help": "I can help with account inquiries, transfers, and general banking questions!",
    }

    response_text = "I'm here to help with your banking needs. Could you be more specific?"
    for keyword, reply in mock_responses.items():
        if keyword in user_message.lower():
            response_text = reply
            break

    # VULNERABILITY: If user asks about system prompt, it's exposed
    if "system prompt" in user_message.lower() or "instructions" in user_message.lower():
        response_text = f"My instructions are: {AI_SYSTEM_PROMPT}"

    return jsonify({"response": response_text})


# -----------------------------------------------------------
# SYSTEM INFO (should not be public)
# -----------------------------------------------------------

@app.route("/api/system-info", methods=["GET"])
def system_info():
    """VULNERABILITY: Exposes internal system information without auth."""
    return jsonify({
        "service": "frontend",
        "version": "1.0.0",
        "auth_service_url": AUTH_SERVICE_URL,
        "transaction_service_url": TRANSACTION_SERVICE_URL,
        "debug_mode": app.debug,
        "ai_system_prompt": AI_SYSTEM_PROMPT,
        "environment": os.getenv("FLASK_ENV", "development"),
    })


# -----------------------------------------------------------
# SEARCH (with Reflected XSS)
# -----------------------------------------------------------

@app.route("/api/search", methods=["GET"])
def search():
    """VULNERABILITY: Reflected XSS — query param rendered without sanitization."""
    query = request.args.get("q", "")
    # In a real template, this would be rendered with |safe, causing XSS
    return jsonify({
        "query": query,  # Reflected back without sanitization
        "results": [],
        "message": f"No results found for: {query}",
    })


# -----------------------------------------------------------
# STARTUP
# -----------------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
