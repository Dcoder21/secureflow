# SecureFlow — Architecture Decisions

## ADR-001: Microservices Decomposition Strategy

**Status:** Accepted

**Context:** The original vuln-bank application is a monolith. For a DevSecOps case study, we need to demonstrate per-service security controls, network segmentation, and independent scanning — none of which are meaningful with a single container.

**Decision:** Decompose into three services along domain boundaries: auth, transactions, and frontend/BFF.

**Consequences:**
- Each service has its own container image → independent Trivy scanning and Cosign signing
- Service-to-service communication → meaningful network policies
- Separate database schemas → Vault can issue per-service credentials
- More operational complexity → mitigated by Kustomize overlays

---

## ADR-002: Kustomize Over Helm for Application Manifests

**Status:** Accepted

**Context:** We need environment-specific Kubernetes configurations (dev, staging, prod) without duplicating manifests.

**Decision:** Use Kustomize with base manifests and overlays per environment. Use Helm only for third-party tools (Vault, Prometheus, Falco, Gatekeeper).

**Rationale:** Kustomize is built into kubectl, requires no additional tooling, and its patch-based approach makes it easy to see exactly what differs between environments. Helm's templating adds complexity that isn't justified for our own application manifests.

---

## ADR-003: Security Gate Philosophy — Hard Fail on Critical

**Status:** Accepted

**Context:** The security gate aggregates results from multiple scanners. We need to decide what blocks a merge.

**Decision:**
- **CRITICAL findings from any scanner → hard fail** (merge blocked)
- **HIGH findings → warning** (PR comment, but merge allowed)
- **Exception process:** comment `/security-exception` with justification, requires security team approval

**Rationale:** Hard-failing on everything creates alert fatigue and developer frustration. Hard-failing only on criticals catches the worst issues while keeping velocity high. The exception process handles legitimate edge cases without requiring code changes to bypass the gate.

---

## ADR-004: Vault in Dev Mode for Learning

**Status:** Accepted (for dev environment only)

**Context:** HashiCorp Vault in HA mode requires Consul or integrated storage, auto-unseal configuration, and significantly more operational work.

**Decision:** Use Vault dev mode for the development environment. Document what would differ in production (HA mode, auto-unseal with AWS KMS, audit logging to S3).

**Consequences:**
- Dev mode auto-unseals and uses in-memory storage — data is lost on restart
- Root token is known — acceptable for learning, not for production
- The Vault Agent Injector workflow is identical regardless of dev/prod mode, so the K8s integration skills transfer directly

---

## ADR-005: Single Database with Separate Schemas

**Status:** Accepted

**Context:** Each microservice should ideally have its own database for full isolation. However, running three separate PostgreSQL instances in a learning environment is wasteful.

**Decision:** Run a single PostgreSQL instance with separate databases (`secureflow_auth`, `secureflow_transactions`). Each service connects to only its own database.

**Consequences:**
- Lower resource usage in dev
- Vault still issues per-service credentials with access limited to the respective database
- In production, this would be separate RDS instances — the Terraform module supports this but we don't provision it in dev

---

## ADR-006: Spot Instances for Dev/Staging

**Status:** Accepted

**Context:** EKS node groups can use On-Demand or Spot instances. Dev and staging environments are non-critical.

**Decision:** Use Spot instances for dev and staging node groups. Production would use On-Demand.

**Consequences:**
- ~60-70% cost reduction on EC2 compute
- Pods may be evicted with 2-minute warning when Spot capacity is reclaimed
- Acceptable for dev/staging where brief interruptions don't matter
- Pod Disruption Budgets should be set in production overlays
