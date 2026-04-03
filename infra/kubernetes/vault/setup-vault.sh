#!/bin/bash
# ─────────────────────────────────────────────────────────────
# SecureFlow — Vault Configuration Script
# Run this after Vault is installed on the cluster.
# Configures Kubernetes auth, secrets, and policies.
# ─────────────────────────────────────────────────────────────

set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://vault.vault.svc:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-root}"  # Dev mode root token — change for prod
NAMESPACE="secureflow"

echo "═══════════════════════════════════════════════════"
echo "  SecureFlow Vault Configuration"
echo "═══════════════════════════════════════════════════"

export VAULT_ADDR VAULT_TOKEN

# ─────────────────────────────────────────
# Step 1: Enable KV Secrets Engine
# ─────────────────────────────────────────
echo "[1/5] Enabling KV secrets engine..."
vault secrets enable -path=secureflow kv-v2 2>/dev/null || echo "  Already enabled"

# ─────────────────────────────────────────
# Step 2: Store Application Secrets
# ─────────────────────────────────────────
echo "[2/5] Storing application secrets..."

vault kv put secureflow/auth-service \
  db_host="postgres" \
  db_port="5432" \
  db_user="secureflow_auth_user" \
  db_password="$(openssl rand -base64 24)" \
  db_name="secureflow_auth" \
  secret_key="$(openssl rand -base64 32)" \
  jwt_algorithm="HS256"

vault kv put secureflow/transaction-service \
  db_host="postgres" \
  db_port="5432" \
  db_user="secureflow_tx_user" \
  db_password="$(openssl rand -base64 24)" \
  db_name="secureflow_transactions" \
  auth_service_url="http://auth-service:5001"

vault kv put secureflow/frontend \
  session_secret="$(openssl rand -base64 32)" \
  auth_service_url="http://auth-service:5001" \
  transaction_service_url="http://transaction-service:5002"

echo "  Secrets stored successfully"

# ─────────────────────────────────────────
# Step 3: Enable Kubernetes Auth Method
# ─────────────────────────────────────────
echo "[3/5] Configuring Kubernetes auth..."
vault auth enable kubernetes 2>/dev/null || echo "  Already enabled"

# Get the K8s API info from within the cluster
vault write auth/kubernetes/config \
  kubernetes_host="https://kubernetes.default.svc:443"

# ─────────────────────────────────────────
# Step 4: Create Vault Policies
# ─────────────────────────────────────────
echo "[4/5] Creating Vault policies..."

# Auth service policy — can only read its own secrets
vault policy write auth-service-policy - <<EOF
path "secureflow/data/auth-service" {
  capabilities = ["read"]
}
path "secureflow/metadata/auth-service" {
  capabilities = ["read"]
}
EOF

# Transaction service policy
vault policy write transaction-service-policy - <<EOF
path "secureflow/data/transaction-service" {
  capabilities = ["read"]
}
path "secureflow/metadata/transaction-service" {
  capabilities = ["read"]
}
EOF

# Frontend policy
vault policy write frontend-policy - <<EOF
path "secureflow/data/frontend" {
  capabilities = ["read"]
}
path "secureflow/metadata/frontend" {
  capabilities = ["read"]
}
EOF

echo "  Policies created"

# ─────────────────────────────────────────
# Step 5: Bind K8s Service Accounts to Vault Roles
# ─────────────────────────────────────────
echo "[5/5] Binding Kubernetes service accounts to Vault roles..."

vault write auth/kubernetes/role/auth-service \
  bound_service_account_names=auth-service-sa \
  bound_service_account_namespaces=$NAMESPACE \
  policies=auth-service-policy \
  ttl=1h

vault write auth/kubernetes/role/transaction-service \
  bound_service_account_names=transaction-service-sa \
  bound_service_account_namespaces=$NAMESPACE \
  policies=transaction-service-policy \
  ttl=1h

vault write auth/kubernetes/role/frontend \
  bound_service_account_names=frontend-sa \
  bound_service_account_namespaces=$NAMESPACE \
  policies=frontend-policy \
  ttl=1h

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Vault configuration complete!"
echo ""
echo "  Secrets stored at: secureflow/{service-name}"
echo "  K8s auth roles:    auth-service, transaction-service, frontend"
echo "  Each service can only read its own secrets."
echo "═══════════════════════════════════════════════════"
