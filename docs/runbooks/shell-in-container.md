# Runbook: Shell Detected in Production Container

## Trigger
Falco alert: `Shell Spawned in SecureFlow Container`

## Severity
**HIGH** — Potential active intrusion. A shell in a production container is almost never legitimate.

## Detection
- **Source:** Falco DaemonSet → falco-exporter → Prometheus → Grafana alert
- **Alert contains:** pod name, namespace, container name, user, command, image
- **Dashboard:** Grafana → SecureFlow Security Overview → Falco Runtime Alerts

## Triage (First 5 Minutes)

### 1. Confirm the alert is real
```bash
# Check if the pod is still running
kubectl get pod <POD_NAME> -n secureflow

# Check pod events for anything unusual
kubectl describe pod <POD_NAME> -n secureflow

# Check Falco logs for the full event details
kubectl logs -l app=falco -n falco --tail=50 | grep <POD_NAME>
```

### 2. Determine if this is authorized
- Is there an active maintenance window?
- Did anyone on the team run `kubectl exec` for debugging?
- Check who authenticated recently:
```bash
kubectl get events -n secureflow --field-selector reason=Started --sort-by='.lastTimestamp'
```

### 3. Quick assessment
- **If authorized debugging:** Document it, remind team to avoid `exec` in prod, close alert
- **If unauthorized:** Proceed to containment immediately

## Containment (Minutes 5–15)

### 1. Isolate the pod — cut network access
```bash
# Apply emergency network policy that blocks all traffic to/from the compromised pod
kubectl label pod <POD_NAME> -n secureflow quarantine=true

# Apply quarantine network policy
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: quarantine-pod
  namespace: secureflow
spec:
  podSelector:
    matchLabels:
      quarantine: "true"
  policyTypes:
    - Ingress
    - Egress
  ingress: []
  egress: []
EOF
```

### 2. Capture forensic data BEFORE killing the pod
```bash
# Snapshot the running processes
kubectl exec <POD_NAME> -n secureflow -- ps aux > /tmp/forensics-ps.txt

# Snapshot network connections
kubectl exec <POD_NAME> -n secureflow -- cat /proc/net/tcp > /tmp/forensics-net.txt

# Snapshot environment variables (may contain clues about pivot)
kubectl exec <POD_NAME> -n secureflow -- env > /tmp/forensics-env.txt

# Export pod logs
kubectl logs <POD_NAME> -n secureflow > /tmp/forensics-pod-logs.txt

# Check filesystem for dropped files
kubectl exec <POD_NAME> -n secureflow -- find /tmp /var/tmp -type f -newer /proc/1/cmdline
```

### 3. Kill and replace the pod
```bash
kubectl delete pod <POD_NAME> -n secureflow
# The Deployment controller will automatically create a clean replacement
```

## Remediation (Hours 1–4)

### 1. Investigate root cause
- How did the attacker get shell access?
  - Vulnerable application endpoint? (Check ZAP findings)
  - Exposed debug console? (Check if Flask debug was enabled)
  - Compromised credentials? (Check Vault audit logs)
  - Container escape? (Check node-level logs)

### 2. Check for lateral movement
```bash
# Check if other pods were accessed
kubectl logs -l app=falco -n falco | grep -E "shell|exec" | grep -v <KNOWN_POD>

# Check Vault audit log for unauthorized access
kubectl exec vault-0 -n vault -- vault audit list
```

### 3. Rotate compromised credentials
```bash
# Rotate all secrets for the affected service
cd infra/kubernetes/vault/
./setup-vault.sh  # Re-generates all secrets

# Force pod restart to pick up new secrets
kubectl rollout restart deployment/<AFFECTED_SERVICE> -n secureflow
```

### 4. Harden the attack vector
- If debug console was exposed: ensure `FLASK_DEBUG=0` in production manifests
- If container was running as root: apply hardened deployment from `vault/auth-service-hardened.yaml`
- If network policy was too permissive: review and tighten `network-policies/policies.yaml`

## Post-Mortem

### Template
- **Date/Time of incident:**
- **Duration from detection to containment:**
- **Root cause:**
- **Attack vector:**
- **Data exposure (if any):**
- **Actions taken:**
- **Preventive measures added:**
- **Lessons learned:**

### Follow-up Actions
- [ ] Update Falco rules if new patterns were discovered
- [ ] Add regression test to CI pipeline
- [ ] Update this runbook with any new steps
- [ ] Schedule team review of the incident
