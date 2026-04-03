# Case Study: Securing a Vulnerable Banking Platform with DevSecOps

## Situation

I joined a fintech startup's platform team as a DevSecOps engineer. The company operated a monolithic banking application built with Python/Flask and PostgreSQL. Security was handled manually — occasional penetration tests, no automated scanning, and secrets scattered across environment files and Kubernetes manifests. The application had never been through a structured security assessment, and the engineering team was shipping features fast without security guardrails.

The codebase had real problems: SQL injection in the login flow, hardcoded JWT secrets, containers running as root, no network segmentation between services, and database credentials stored in plaintext in deployment manifests. Any one of these could have led to a data breach.

## Task

My mandate was to:

1. Decompose the monolith into microservices to reduce blast radius and enable per-service security controls
2. Build an automated security pipeline that catches vulnerabilities before code reaches production
3. Implement runtime security monitoring to detect threats in the live environment
4. Establish secrets management so credentials are never stored in code
5. Create visibility into the organization's security posture through dashboards and reporting

The constraint: everything had to use open-source tooling to keep costs manageable for a startup.

## Action

### Phase 1: Microservices Decomposition

I split the monolith into three services along domain boundaries:

- **Auth Service** — user registration, authentication, JWT management, password reset
- **Transaction Service** — account balances, money transfers, transaction history, virtual cards
- **Frontend/BFF** — web UI, API proxy, AI chatbot

Each service got its own Dockerfile, Kubernetes deployment, and database schema. I defined clear service boundaries: the frontend proxies to backend services, the transaction service calls the auth service for token validation, and no service has direct access to another service's database.

This decomposition wasn't just architectural — it enabled meaningful network policies. In the monolith, everything could talk to everything. Now I could enforce that only the frontend accepts external traffic, only backend services reach PostgreSQL, and the auth service is unreachable from outside the cluster.

### Phase 2: Infrastructure as Code

I provisioned the entire AWS environment with Terraform:

- VPC with public/private subnets across two availability zones
- EKS cluster with managed node groups using Spot instances (cost optimization)
- ECR repositories with immutable tags and scan-on-push enabled
- OIDC provider for IAM Roles for Service Accounts (IRSA)

Every Terraform module is scanned by Checkov in CI. I configured it to fail the pipeline on HIGH and CRITICAL findings, with documented exceptions for accepted risks using inline skip comments.

### Phase 3: CI Security Pipeline

I built a 7-stage GitHub Actions pipeline that runs on every push and pull request:

1. **Gitleaks** scans the full commit history for secrets. I wrote custom rules for Flask secret keys, JWT signing keys, and database connection strings. The intentionally committed `.env` file was the first thing it caught.

2. **SonarQube** performs static analysis on all three Python services. The quality gate requires zero new critical or blocker issues. It immediately flagged the SQL injection in the auth service's login endpoint and several instances of hardcoded credentials.

3. **Trivy** scans each container image after build. The `python:3.9-slim` base image alone had 12 critical CVEs from outdated system libraries. I also run Trivy against the Kubernetes manifests to catch misconfigurations like missing security contexts.

4. **Checkov** scans Terraform files for infrastructure misconfigurations — overly permissive security groups, unencrypted storage, public endpoints that should be private.

5. **Security Gate** — a custom bash script aggregates results from all scanners, produces a summary table, and posts it as a PR comment. If any scanner found critical findings, the merge is blocked. The gate also supports a documented exception process for cases where security and velocity need to be balanced.

6. **Cosign** signs every image that passes the security gate, using a keypair stored in Vault. Only signed images can be deployed to the cluster.

7. **SBOM generation** with Trivy in SPDX format, attached to the image via Cosign for supply chain transparency.

### Phase 4: Runtime Security

**OPA Gatekeeper** enforces four policies at the Kubernetes admission layer:
- No privileged containers or privilege escalation
- No `:latest` image tags — all images must be pinned to a specific SHA
- CPU and memory limits are mandatory on every container
- Every resource must have `app` and `team` labels

When I first applied these policies, the original "insecure" manifests were all rejected. This became a powerful before/after demonstration: the base manifests violate every policy, while the hardened manifests pass cleanly.

**Falco** runs as a DaemonSet and monitors for runtime threats:
- Shell processes spawned inside containers
- Reads to sensitive files like `/etc/shadow`
- Unexpected outbound network connections from backend services
- Binaries executed from `/tmp` (common attacker pattern)
- Package managers or download tools running at runtime

I wrote custom Falco rules specific to the SecureFlow namespace and routed alerts to Prometheus via falco-exporter.

**Network Policies** implement default-deny across the namespace, with explicit whitelists:
- Frontend can reach auth-service (port 5001) and transaction-service (port 5002)
- Auth-service can reach PostgreSQL (port 5432) only
- Transaction-service can reach PostgreSQL and auth-service
- PostgreSQL accepts connections only from the two backend services
- No service can make arbitrary outbound connections

### Phase 5: Secrets Management

I deployed HashiCorp Vault on EKS and configured:
- Kubernetes auth method so pods authenticate to Vault using their service account
- Per-service Vault policies — auth-service can only read `secureflow/data/auth-service`, not other services' secrets
- Vault Agent Injector annotates pods to receive secrets as files mounted at runtime
- All passwords are randomly generated 24+ character strings, not the original `postgres`/`admin123`

The before/after is stark: the original deployment had 6 plaintext secrets in environment variables. The hardened deployment has zero — everything comes from Vault.

### Phase 6: Observability

I deployed the kube-prometheus-stack and built a Grafana dashboard with 8 panels:
- Pipeline security gate pass/fail rate over time
- Container vulnerability count by severity (trending downward)
- Falco runtime alerts by rule
- OPA admission denial breakdown by policy
- Mean time to remediate critical vulnerabilities
- DAST findings from OWASP ZAP
- Vault secrets rotation status
- Cosign image signing verification

Loki aggregates logs from Falco, Vault audit, and application logs into a single searchable interface for incident investigation.

I also run OWASP ZAP against the staging environment — baseline scans on every deploy, full scans weekly — with results feeding into the dashboard.

## Results

**Quantified improvements:**
- Critical container vulnerabilities: **47 → 3** (93% reduction) within the first two weeks by updating base images and pinning dependencies
- Hardcoded secrets: **6 → 0** after Vault migration
- Mean time to detect security issues: **days → minutes** (automated scanning vs. manual review)
- Policy compliance: 100% of deployments now pass OPA admission policies
- All container images are signed and verified before deployment

**Operational improvements:**
- Security is no longer a bottleneck — developers get feedback in their PR within minutes
- The security gate has a documented exception process, balancing security with velocity
- Incident response is documented with step-by-step runbooks for the three most common scenarios
- Leadership has a single dashboard showing the organization's security posture

## Key Decisions and Tradeoffs

**Why OPA Gatekeeper over Kyverno?** Gatekeeper has broader community adoption, and OPA's Rego language is used beyond Kubernetes (Terraform, CI pipelines), making the skill more transferable. Kyverno's YAML-based policies are simpler to write, but Rego's flexibility was needed for custom logic like label validation.

**Why Trivy over Grype/Snyk?** Trivy is a single tool that scans container images, IaC, and Kubernetes manifests. This reduced pipeline complexity compared to running separate tools. Snyk has better developer experience but requires a paid plan for CI integration.

**Why Vault over Kubernetes Secrets?** Native K8s secrets are base64-encoded, not encrypted, and anyone with RBAC access can read them. Vault provides real encryption, audit logging, dynamic secrets, and fine-grained access policies. The operational overhead is worth it for a financial application.

**Security gate: hard fail vs. soft fail?** I chose hard fail for critical findings and soft fail for highs. This prevents the worst issues from shipping while not blocking developers on every medium-severity finding. The exception process (PR comment + security team approval) handles legitimate cases where a known issue must ship with a deadline.

## Tools Used

Terraform, Checkov, GitHub Actions, Gitleaks, SonarQube, Trivy, Cosign, OWASP ZAP, OPA Gatekeeper, Falco, HashiCorp Vault, Prometheus, Grafana, Loki, Kustomize, Docker, EKS, ECR
