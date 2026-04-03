# Runbook: Secret Exposed in Git Commit

## Trigger
Gitleaks detects a secret (API key, password, token) committed to the repository.

## Severity
**CRITICAL** — Once pushed, a secret should be considered compromised even if the commit is reverted. Git history preserves it.

## Detection
- **Source:** GitHub Actions → Gitleaks scan → security gate fail → PR blocked
- **Types caught:** AWS keys, GCP service account JSON, API tokens, database passwords, JWT secrets, Flask secret keys

## Immediate Response (First 10 Minutes)

### 1. Identify what was exposed
```bash
# Check the Gitleaks report
cat security-results/gitleaks.json | jq '.[].Description, .[].Secret, .[].File'
```

Determine:
- **What type of secret?** (AWS key, DB password, API token, etc.)
- **What file was it in?** (Source code, .env file, config, Terraform)
- **Has this been pushed to a remote branch?** If yes, it's compromised.
- **Was it a real secret or a test/dummy value?** (e.g., "AKIAIOSFODNN7EXAMPLE" is the AWS example key)

### 2. If it's a REAL secret that was pushed — rotate immediately

**AWS Access Keys:**
```bash
# Deactivate the exposed key immediately
aws iam update-access-key --access-key-id <EXPOSED_KEY_ID> --status Inactive --user-name <USER>

# Create a new key
aws iam create-access-key --user-name <USER>

# Update the new key wherever it's used (GitHub Secrets, Vault, etc.)

# Delete the old key after confirming everything works
aws iam delete-access-key --access-key-id <EXPOSED_KEY_ID> --user-name <USER>
```

**Database Passwords:**
```bash
# Rotate in Vault
vault kv put secureflow/<service> db_password="$(openssl rand -base64 24)" ...

# Update the database itself
psql -U postgres -c "ALTER USER <db_user> WITH PASSWORD '<new_password>';"

# Force pod restart to pick up new Vault secret
kubectl rollout restart deployment/<service> -n secureflow
```

**JWT Secret Key:**
```bash
# Rotate in Vault
vault kv put secureflow/auth-service secret_key="$(openssl rand -base64 32)" ...

# Force restart — all existing JWTs will be invalidated
kubectl rollout restart deployment/auth-service -n secureflow
```

**GitHub / SonarQube / Other API Tokens:**
- Revoke the exposed token in the service's settings
- Generate a new token
- Update GitHub Actions secrets

### 3. Check for unauthorized usage
- **AWS:** Check CloudTrail for API calls made with the exposed key
- **Database:** Check pg_stat_activity or query logs for unusual connections
- **API tokens:** Check the service's audit log for unexpected usage

## Remove the Secret from Git History

### Option A: If the commit hasn't been merged yet
```bash
# Amend the commit to remove the secret
git checkout <branch>
# Remove the secret from the file
git add <file>
git commit --amend --no-edit
git push --force-with-lease
```

### Option B: If it's already in main — rewrite history (use with caution)
```bash
# Use git-filter-repo (preferred over filter-branch)
pip install git-filter-repo

# Remove the file entirely from history
git filter-repo --path <file-with-secret> --invert-paths

# Or replace the secret in all commits
git filter-repo --blob-callback '
  return blob.data.replace(b"ACTUAL_SECRET_VALUE", b"REDACTED")
'

# Force push (coordinate with the team first)
git push --force --all
```

**Important:** After rewriting history, all team members must re-clone the repository.

## Prevention

### 1. Add a pre-commit hook
```bash
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
```

### 2. Ensure Gitleaks config catches this pattern
If the secret type wasn't caught by the default rules, add a custom rule to `security/gitleaks/gitleaks.toml`.

### 3. Move the secret to Vault
All secrets should live in Vault, not in code, environment variables, or config files. Use the Vault Agent Injector to deliver secrets to pods at runtime.

## Post-Incident

- [ ] Secret rotated and old one deactivated
- [ ] Git history cleaned (if applicable)
- [ ] No unauthorized usage found in audit logs
- [ ] Pre-commit hook installed for the developer who committed it
- [ ] Root cause documented: why was the secret in code in the first place?
- [ ] Team notified about the incident and prevention measures
