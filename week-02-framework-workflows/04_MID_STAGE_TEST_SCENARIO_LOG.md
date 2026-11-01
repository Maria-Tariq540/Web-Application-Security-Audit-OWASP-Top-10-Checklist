# MID-STAGE TEST SCENARIO LOG & BENCHMARK VALIDATION
## HealthTech Connect Staging Security Assessment
**Date of Execution:** 2026-11-02  
**Test Suite:** OWASP Top 10:2021 Comprehensive Audit Matrix  
**Test Harness:** Chromium DevTools, OWASP ZAP v2.14.0, cURL v8.4.0  
**Environment:** Staging Pre-Production (`https://*.healthtechconnect.io`)

---

## 1. Test Scenario Execution Summary

| Test ID | OWASP Category | Target Feature / Endpoint | Test Objective | Tool / Method | Outcome | Finding ID |
| :---: | :--- | :--- | :--- | :--- | :---: | :---: |
| **TC-01** | A01: Broken Access Control | `/api/v1/patients/{mrn}/lab-results` | Horizontal privilege escalation (IDOR) | DevTools Network Replay | ❌ **FAIL** (Vuln) | HTC-SEC-009 |
| **TC-02** | A01: Broken Access Control | `/api/v1/admin/audit-logs` | Vertical privilege escalation via patient JWT | cURL / Auth Header | ✅ **PASS** (403 Forbidden) | N/A |
| **TC-03** | A02: Cryptographic Failures | `portal.healthtechconnect.io` | Absence of HSTS header allow downgrade | ZAP Passive Rule 10035 | ❌ **FAIL** (Vuln) | HTC-SEC-005 |
| **TC-04** | A02: Cryptographic Failures | Browser LocalStorage | Cleartext ePHI & unencrypted tokens | DevTools Application Tab | ❌ **FAIL** (Vuln) | HTC-SEC-001 |
| **TC-05** | A03: Injection | `/fhir/r4/Patient?name={str}` | SQL/NoSQL injection via FHIR filter parameter | ZAP Active Rule 40018 | ❌ **FAIL** (Vuln) | HTC-SEC-010 |
| **TC-06** | A03: Injection | `portal.healthtechconnect.io/telehealth/portal?view={str}` | Reflected DOM XSS in query sink | DevTools Console/Sources | ❌ **FAIL** (Vuln) | HTC-SEC-011 |
| **TC-07** | A04: Insecure Design | `/appointment/book` | Client-side copay fee tampering | DevTools Elements / Payload | ❌ **FAIL** (Vuln) | HTC-SEC-012 |
| **TC-08** | A05: Security Misconfig | Ingress HTTP Headers | Missing CSP, Clickjacking, MIME sniff headers | Mozilla Observatory / ZAP | ❌ **FAIL** (Vuln) | HTC-SEC-002, 003 |
| **TC-09** | A07: Auth Failures | `/api/v1/auth/logout` | Token invalidation & post-logout reuse | DevTools Network Replay | ❌ **FAIL** (Vuln) | HTC-SEC-013 |
| **TC-10** | A10: SSRF | `/api/v1/integrations/fhir-webhook` | Server-Side Request Forgery via webhook URL | cURL / ZAP Rule 40034 | ❌ **FAIL** (Vuln) | HTC-SEC-014 |

---

## 2. Detailed Mid-Stage Test Execution Logs

### Scenario TC-05: Injection in FHIR Filter Parameter (Finding HTC-SEC-010)
- **Target URL**: `https://ehr-sync.healthtechconnect.io/fhir/r4/Patient?identifier=1001`
- **Audit Objective**: Evaluate parameter handling in Python FastAPI / SQLAlchemy backend.
- **Probe Applied**: Standard non-destructive boundary probe: `1001' OR '1'='1`
- **Observed Behavior**: The API returned HTTP 500 with unhandled psycopg2 / SQLAlchemy trace leaking raw SQL syntax:
  ```json
  {
    "detail": "Internal Server Error: syntax error at or near \"OR\" in SELECT * FROM fhir_patients WHERE mrn = '1001' OR '1'='1'..."
  }
  ```
- **Analysis**: Demonstrates dynamic SQL string concatenation rather than parameterized ORM queries (`session.execute(text("..."))`).
- **Severity**: **CRITICAL (CVSS 9.8)**. Assigned ticket for immediate Week 3 SOP remediation.

---

### Scenario TC-06: Reflected DOM XSS via Unescaped View Parameter (Finding HTC-SEC-011)
- **Target URL**: `https://portal.healthtechconnect.io/telehealth/portal?view=records`
- **Audit Objective**: Verify client-side sanitization of URL parameters reflected in DOM title header.
- **Probe Applied**: Safe boundary probe string: `test_probe'"><b id="injected">marker</b>`
- **Observed Behavior**: The React component uses `dangerouslySetInnerHTML` to render breadcrumbs based on `window.location.search`. The element `<b id="injected">marker</b>` rendered directly into the DOM tree.
- **Severity**: **HIGH (CVSS 8.2)**. Assigned ticket for Week 3 React sanitization SOP.

---

### Scenario TC-07: Client-Side Fee Tampering / Insecure Design (Finding HTC-SEC-012)
- **Target URL**: `https://portal.healthtechconnect.io/api/v1/appointments/checkout`
- **Audit Objective**: Test whether copay charge calculations are verified server-side.
- **Execution**: In DevTools, intercepted the JSON payload for a specialist consultation (`normal copay: $75.00`) and modified the parameter:
  ```json
  {
    "appointment_id": "APT-4401",
    "copay_cents": 0
  }
  ```
- **Observed Behavior**: The backend accepted `0` cents, created the scheduled consultation, and returned `status: "CONFIRMED"`.
- **Severity**: **MEDIUM (CVSS 5.3)**. Business logic failure; server must look up copay from patient insurance tier table, ignoring client-sent values.

---

### Scenario TC-09: Token Replay Post-Logout (Finding HTC-SEC-013)
- **Target URL**: `https://api.healthtechconnect.io/v1/auth/logout`
- **Audit Objective**: Verify server-side token invalidation upon user logout.
- **Execution**: User logged out via UI. The Bearer token was immediately reused to query `GET /v1/patients/me/profile`.
- **Observed Behavior**: The API responded with HTTP 200 OK. The JWT is stateless with 24-hour expiration and is not stored in a Redis revocation denylist.
- **Severity**: **HIGH (CVSS 7.5)**. Fails HIPAA § 164.312(a)(2)(iii) Automatic Logoff requirement.

---

### Scenario TC-10: Blind SSRF in Clinical Webhook Registration (Finding HTC-SEC-014)
- **Target URL**: `https://api.healthtechconnect.io/v1/integrations/fhir-webhook`
- **Audit Objective**: Verify URL validation when clinical partners register real-time FHIR event listeners.
- **Probe Applied**: Pointed webhook `callback_url` to cloud metadata endpoint IP: `http://169.254.169.254/latest/meta-data/`
- **Observed Behavior**: The backend immediately attempted an outbound HTTP connection without IP filtering or private CIDR block blacklisting.
- **Severity**: **HIGH (CVSS 8.6)**. Potential cloud credential compromise via SSRF.
