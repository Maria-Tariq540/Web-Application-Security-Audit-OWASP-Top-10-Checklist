# DEVSECOPS SOP WIKI & ENGINEERING HANDOFF GUIDE
## Secure Coding Standards & Operational Runbooks for HealthTech Connect
**Document ID:** `HTC-DEVSEC-WIKI-v1.0`  
**Audience:** Software Engineers, DevOps / SRE, QA Engineers, Security Analysts  
**Target Standard:** OWASP Top 10:2021 & HIPAA Security Rule (45 CFR § 164.312)

---

## Wiki Navigation Directory
- **[Module 1: Ingress & Web Server Hardening Standard](#module-1-ingress--web-server-hardening-standard)**
- **[Module 2: Secure API Development & Database Parameterization](#module-2-secure-api-development--database-parameterization)**
- **[Module 3: Modern Session & Token Management Standard](#module-3-modern-session--token-management-standard)**
- **[Module 4: Cloud Egress & SSRF Defense Standard](#module-4-cloud-egress--ssrf-defense-standard)**
- **[Module 5: Continuous CI/CD DAST Integration Runbook](#module-5-continuous-cicd-dast-integration-runbook)**

---

## Module 1: Ingress & Web Server Hardening Standard

### 1.1 Mandatory HTTP Security Headers Standard
All reverse proxies, Ingress controllers (Nginx, Traefik, AWS ALB), and static web servers must inject the following baseline headers into every response.

```nginx
# /etc/nginx/conf.d/security_headers.conf
server_tokens off;

# 1. HSTS (Enforce HTTPS for 2 years + preloading)
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

# 2. Strict Content Security Policy
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://cdn.healthtechconnect.io; font-src 'self' data:; connect-src 'self' https://api.healthtechconnect.io wss://stream.healthtechconnect.io; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;

# 3. Framing & MIME Protections
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(self), microphone=(self), geolocation=(), payment=()" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
```

### 1.2 Verification Checklist
- [ ] Run `curl -I https://portal.healthtechconnect.io` and ensure all 8 headers are present.
- [ ] Confirm `Server` header does not return version number `1.25.3`.
- [ ] Validate on Mozilla Observatory (`https://observatory.mozilla.org`) to confirm Grade **A+**.

---

## Module 2: Secure API Development & Database Parameterization

### 2.1 The Cardinal Rule of Database Queries
> **NEVER concatenate, format, or interpolate user-supplied data into SQL, CQL, or NoSQL query strings.**

### 2.2 Python (SQLAlchemy & FastAPI) Parameterization Pattern
```python
# ==============================================================================
# CORRECT: SQLAlchemy 2.0 select statement with parameterized variables
# ==============================================================================
from sqlalchemy import select
from apps.ehr_sync.models import PatientRecord

# Parameterized query automatically escapes inputs:
stmt = select(PatientRecord).where(PatientRecord.mrn == validated_mrn)
result = db.execute(stmt).scalars().first()
```

### 2.3 Node.js (PostgreSQL / pg-promise) Parameterization Pattern
```javascript
// ==============================================================================
// CORRECT: Parameterized queries using positional variables ($1, $2)
// ==============================================================================
const query = 'SELECT * FROM clinical_notes WHERE patient_id = $1 AND doctor_id = $2';
const values = [req.params.patientId, req.user.id];

const result = await db.query(query, values);
```

### 2.4 Mandatory IDOR Ownership Middleware Pattern
Every endpoint accepting a patient resource identifier (`mrn`, `patient_id`, `record_id`) must route through ownership validation middleware:

```javascript
function verifyPatientOwnership(req, res, next) {
  if (req.user.role === 'admin' || req.user.role === 'physician') return next();
  if (req.user.mrn !== req.params.mrn) {
    return res.status(403).json({
      status: "error",
      code: "AUTH_FORBIDDEN",
      message: "Access Denied: You do not have permission to view this clinical resource."
    });
  }
  next();
}
```

---

## Module 3: Modern Session & Token Management Standard

### 3.1 Session Storage Rules
- ❌ **NEVER store tokens or ePHI in `localStorage` or `sessionStorage`**. They are accessible by any script running on the page (XSS risk).
- ✅ **ALWAYS issue session tokens inside `__Host-` prefixed `HttpOnly`, `Secure`, `SameSite=Strict` cookies**.

### 3.2 Cookie Configuration Standard
```javascript
res.cookie('__Host-htc_auth', jwtToken, {
  httpOnly: true,              // Blocks document.cookie access
  secure: true,                // Requires TLS / HTTPS
  sameSite: 'strict',          // Restricts cross-site transmission
  path: '/',                   // Required for __Host- prefix
  maxAge: 15 * 60 * 1000       // 15-minute HIPAA idle session limit
});
```

### 3.3 Server-Side Token Invalidation on Logout
Stateless JWTs must be paired with a Redis revocation store to satisfy HIPAA 45 CFR § 164.312(a)(2)(iii):
1. When a user clicks **Logout**, client calls `POST /v1/auth/logout`.
2. Backend decodes token `jti` (JWT ID) and writes `jti` to Redis with TTL equal to the token's remaining lifespan.
3. Auth middleware queries Redis on each incoming request; if `jti` exists in the blacklist, request is rejected with `401 Unauthorized`.

---

## Module 4: Cloud Egress & SSRF Defense Standard

### 4.1 Outbound HTTP Request Hardening
When an application feature requires fetching user-provided URLs (e.g., webhook notifications, FHIR endpoints, avatar imports), apply strict DNS and IP validation:

```python
import ipaddress, socket, urllib.parse
from fastapi import HTTPException

BLOCKED_SUBNETS = [
    ipaddress.ip_network("127.0.0.0/8"),      # Localhost
    ipaddress.ip_network("10.0.0.0/8"),       # Private Class A
    ipaddress.ip_network("172.16.0.0/12"),    # Private Class B
    ipaddress.ip_network("192.168.0.0/16"),   # Private Class C
    ipaddress.ip_network("169.254.0.0/16"),   # AWS IMDSv2 Metadata
    ipaddress.ip_network("::1/128"),          # IPv6 Loopback
]

def assert_safe_outbound_url(target_url: str):
    parsed = urllib.parse.urlparse(target_url)
    if parsed.scheme != "https":
        raise HTTPException(status_code=400, detail="Only HTTPS is permitted.")
        
    resolved_ips = socket.getaddrinfo(parsed.hostname, 443)
    for entry in resolved_ips:
        ip = ipaddress.ip_address(entry[4][0])
        for subnet in BLOCKED_SUBNETS:
            if ip in subnet:
                raise HTTPException(status_code=400, detail="Target IP is restricted.")
```

---

## Module 5: Continuous CI/CD DAST Integration Runbook

### 5.1 GitHub Actions Workflow: Automated Security Gate
Place in `.github/workflows/security_dast_gate.yml`:

```yaml
name: DevSecOps Staging DAST Gate

on:
  pull_request:
    branches: [ staging, main ]
  workflow_dispatch:

jobs:
  zap_security_audit:
    runs-on: ubuntu-latest
    name: OWASP ZAP Baseline Security Scan
    steps:
      - name: Checkout Source Code
        uses: actions/checkout@v4

      - name: Execute OWASP ZAP Baseline Scan
        uses: zaproxy/action-baseline@v0.12.0
        with:
          target: 'https://staging.healthtechconnect.io'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a'
          fail_action: true # Fails build if High/Critical alerts are discovered

      - name: Verify Mozilla Observatory Headers
        run: |
          npm install -g observatory-cli
          observatory staging.healthtechconnect.io --format=json --min-grade=A
```
