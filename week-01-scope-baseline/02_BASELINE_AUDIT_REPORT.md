# BASELINE SECURITY AUDIT REPORT
## Web Application Security Assessment & OWASP Top 10 Analysis
**Target System:** HealthTech Connect (Telehealth & EHR Management Portal)  
**Date of Assessment:** 2026-11-01  
**Assessment Tooling:** OWASP ZAP (Zed Attack Proxy v2.14.0), Chrome DevTools (v124), Mozilla Observatory CLI, cURL  
**Assessor:** Lead Web Security Auditor & DevSecOps Engineer  
**Classification:** Confidential — Protected Health Information (HIPAA Compliance Context)

---

## 1. Executive Summary

A comprehensive baseline security assessment of the **HealthTech Connect** staging platform (`https://portal.healthtechconnect.io` and `https://api.healthtechconnect.io`) was executed. The objective was to discover early-stage architectural flaws, misconfigurations, and OWASP Top 10 vulnerabilities prior to production patient rollout.

The automated baseline scan and manual browser inspection revealed **8 distinct vulnerabilities**, including **1 Critical**, **2 High**, **3 Medium**, and **2 Low/Informational** findings. 

Most critically, the portal suffers from an architectural flaw where patient Electronic Protected Health Information (ePHI) is cached unencrypted within browser `localStorage`, coupled with the complete absence of modern HTTP Security Headers (notably `Content-Security-Policy` and `Strict-Transport-Security`). This combination exposes patients to trivial Cross-Site Scripting (XSS), Clickjacking, and unauthorized session hijacking in violation of HIPAA 45 CFR § 164.312.

---

## 2. Target Profile & Architecture Overview

```
                      [ Client Browser (React SPA) ]
                                    |
                 (HTTPS / Missing Security Headers)
                                    v
                       [ Nginx Reverse Proxy / Ingress ]
                                    |
                 +------------------+------------------+
                 |                                     |
                 v                                     v
      [ Node.js API Gateway ]               [ Python FastAPI FHIR Engine ]
      Port 4000 (Express.js)                Port 8000 (SQLAlchemy)
                 |                                     |
                 +------------------+------------------+
                                    |
                                    v
                     [ PostgreSQL 15 (ePHI Datastore) ]
```

- **Frontend Application**: React 18 SPA hosted via Nginx (`portal.healthtechconnect.io`).
- **Authentication**: JWT Bearer tokens issued via OAuth2/OIDC provider.
- **Backend Services**: Node.js v20 (Express) routing engine and Python 3.11 (FastAPI) FHIR API.
- **Target Ingress Controller**: Nginx 1.25.3 on Alpine Linux.

---

## 3. OWASP ZAP Baseline Scan Findings Summary

OWASP ZAP was configured in **Passive Scan & Spider Mode** with a crawl depth of 5 and max crawl duration of 45 minutes against `https://portal.healthtechconnect.io`.

### 3.1 Severity Distribution
```
+--------------------------------------------------------------------------+
| Alert Severity Breakdown                                                 |
+------------------------------------+------------------+------------------+
| Risk Level                         | Number of Alerts | % Total Findings |
+------------------------------------+------------------+------------------+
| Critical (CVSS 9.0 - 10.0)         | 1                | 12.5%            |
| High (CVSS 7.0 - 8.9)              | 2                | 25.0%            |
| Medium (CVSS 4.0 - 6.9)            | 3                | 37.5%            |
| Low / Info (CVSS 0.1 - 3.9)        | 2                | 25.0%            |
| Total                              | 8                | 100%             |
+------------------------------------+------------------+------------------+
```

---

## 4. Deep-Dive Vulnerability Analysis

### Finding HTC-SEC-001: Unencrypted ePHI & JWT Stored in Browser `localStorage`
- **OWASP Top 10 Category**: A04:2021 – Insecure Design / A02:2021 – Cryptographic Failures
- **HIPAA Regulation**: 45 CFR § 164.312(a)(2)(iv) (Encryption and Decryption)
- **Severity**: **CRITICAL** | **CVSS v3.1**: `9.1` (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
- **Asset**: `https://portal.healthtechconnect.io/dashboard`
- **Discovery Method**: Chrome DevTools (Application > Storage > Local Storage)

#### Observation & PoC
Upon logging into the patient portal, the React client application stores the authentication token and full patient demographics in browser `window.localStorage`:

```javascript
// Inspected in DevTools Console:
localStorage.getItem("htc_patient_session");
```
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "patient_mrn": "MRN-902184-US",
  "full_name": "Eleanor Vance",
  "dob": "1984-06-12",
  "ssn_last_four": "4819",
  "conditions": ["Type 2 Diabetes", "Hypertension", "Depression"],
  "prescriptions": [
    {"name": "Metformin", "dosage": "500mg daily"},
    {"name": "Lisinopril", "dosage": "10mg daily"}
  ]
}
```

#### Risk & Impact
`localStorage` has no cross-site scripting isolation. Any injected third-party script, malicious NPM dependency, or cross-site scripting flaw can read this data directly using `window.localStorage.getItem()`. Furthermore, medical diagnoses and Social Security digits reside in cleartext on shared workstation disk caches (e.g., hospital kiosk terminals).

---

### Finding HTC-SEC-002: Missing Content-Security-Policy (CSP) & Insecure Inline Scripts
- **OWASP Top 10 Category**: A05:2021 – Security Misconfiguration
- **HIPAA Regulation**: 45 CFR § 164.312(c)(1) (Data Integrity)
- **Severity**: **HIGH** | **CVSS v3.1**: `7.5` (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
- **Asset**: `https://portal.healthtechconnect.io/*`
- **Discovery Method**: OWASP ZAP Alert Plugin ID `10038` (Content Security Policy (CSP) Header Not Set)

#### Observation & Proof of Concept
The HTTP response headers returned by the Nginx ingress server completely omit the `Content-Security-Policy` header.

```http
GET /dashboard HTTP/1.1
Host: portal.healthtechconnect.io
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)

HTTP/1.1 200 OK
Server: nginx/1.25.3
Date: Sun, 01 Nov 2026 18:30:12 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
ETag: "6543bca2-8a4"
Content-Length: 2212
```

Inspecting the HTML payload reveals unhashed inline script blocks used for analytics loading:
```html
<script>
  window.__HTC_CONFIG__ = {
    apiEndpoint: "https://api.healthtechconnect.io/v1",
    telehealthRelay: "wss://stream.healthtechconnect.io/rtc"
  };
</script>
```
Without a CSP header defining `default-src 'self'` and requiring cryptographically secure nonces, an attacker who identifies any input reflection can execute arbitrary JavaScript in the context of the user's active clinical session.

---

### Finding HTC-SEC-003: Clickjacking Exposure via Missing `X-Frame-Options` & `frame-ancestors`
- **OWASP Top 10 Category**: A05:2021 – Security Misconfiguration
- **HIPAA Regulation**: 45 CFR § 164.312(a)(1) (Access Control)
- **Severity**: **HIGH** | **CVSS v3.1**: `7.1` (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N)
- **Asset**: `https://portal.healthtechconnect.io/telehealth/room/*`
- **Discovery Method**: OWASP ZAP Alert Plugin ID `10020` (Anti-clickjacking Header)

#### Observation & Proof of Concept
Neither `X-Frame-Options: DENY` nor `Content-Security-Policy: frame-ancestors 'none'` is present.

The vulnerability was validated by embedding the telehealth consultation portal inside an adversarial frame:
```html
<!-- Malicious Clickjacking PoC: attack-poc.html -->
<!DOCTYPE html>
<html>
<head><title>Telehealth Free Voucher Claim</title></head>
<body>
  <h2>Click below to confirm your insurance reimbursement</h2>
  <iframe 
    src="https://portal.healthtechconnect.io/telehealth/room/consent?patient_id=902184" 
    style="opacity: 0.0001; position: absolute; top: 0px; left: 0px; width: 800px; height: 600px; z-index: 2;">
  </iframe>
  <button style="position: absolute; top: 310px; left: 450px; z-index: 1;">Claim $100 Health Credit</button>
</body>
</html>
```
#### Impact
A patient can be tricked into unknowingly clicking "Approve Medical Record Transfer" or "Grant Camera/Microphone Permissions" while believing they are clicking an innocent promotion.

---

### Finding HTC-SEC-004: Insecure Cookie Configuration (Missing `HttpOnly`, `Secure`, and `SameSite`)
- **OWASP Top 10 Category**: A01:2021 – Broken Access Control
- **HIPAA Regulation**: 45 CFR § 164.312(d) (Person or Entity Authentication)
- **Severity**: **MEDIUM** | **CVSS v3.1**: `6.5` (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N)
- **Asset**: `https://api.healthtechconnect.io/v1/auth/login`
- **Discovery Method**: OWASP ZAP Alert Plugin ID `10010` / `10011`

#### Raw HTTP Response
```http
HTTP/1.1 200 OK
Date: Sun, 01 Nov 2026 18:32:00 GMT
Content-Type: application/json; charset=utf-8
Set-Cookie: htc_auth=s%3AeyJuYW1laWQiOiJ1c3ItOTAx...; Path=/;
Set-Cookie: session_tracker=cf48902b11a; Path=/; Domain=.healthtechconnect.io
```
#### Deficiencies
1. **`HttpOnly` omitted**: The `htc_auth` cookie can be read by any JavaScript via `document.cookie`.
2. **`Secure` flag omitted**: The browser transmits this session cookie over unencrypted HTTP if a user types `http://` or clicks an insecure link.
3. **`SameSite` attribute omitted**: The browser defaults to lax or none, leaving authenticated endpoints vulnerable to Cross-Site Request Forgery (CSRF).

---

### Finding HTC-SEC-005: Missing HTTP Strict Transport Security (HSTS) Header
- **OWASP Top 10 Category**: A02:2021 – Cryptographic Failures
- **HIPAA Regulation**: 45 CFR § 164.312(e)(1) (Transmission Security)
- **Severity**: **MEDIUM** | **CVSS v3.1**: `5.9` (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N)
- **Asset**: `https://portal.healthtechconnect.io` & `https://api.healthtechconnect.io`
- **Discovery Method**: OWASP ZAP Alert Plugin ID `10035`

#### Impact
Without `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`, a user connecting via public Wi-Fi (e.g., hospital guest network) is vulnerable to SSL stripping attacks (e.g., `sslstrip` or ARP spoofing), enabling an adversary to downgrade the connection to cleartext HTTP and intercept ePHI.

---

### Finding HTC-SEC-006: Insecure Referrer Policy Exposing Patient IDs in Query Strings
- **OWASP Top 10 Category**: A04:2021 – Insecure Design
- **HIPAA Regulation**: 45 CFR § 164.530(c) (Safeguards)
- **Severity**: **MEDIUM** | **CVSS v3.1**: `4.3` (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N)
- **Asset**: `https://portal.healthtechconnect.io/patient/records?patient_mrn=MRN-902184-US&ref=oncology`
- **Discovery Method**: OWASP ZAP Alert Plugin ID `10037`

#### Observation
The default browser policy or missing `Referrer-Policy: strict-origin-when-cross-origin` causes outgoing external requests (e.g., fetching CDN assets, telehealth CDN scripts) to pass the full URL in the `Referer` request header. Third-party CDNs receive URLs containing unmasked Medical Record Numbers (`patient_mrn`) and clinical department identifiers (`oncology`).

---

### Finding HTC-SEC-007: Exposed JavaScript Production Source Maps
- **OWASP Top 10 Category**: A05:2021 – Security Misconfiguration
- **Severity**: **LOW** | **CVSS v3.1**: `3.7` (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)
- **Asset**: `https://portal.healthtechconnect.io/assets/index-D7b3qL1a.js.map`
- **Discovery Method**: Chrome DevTools (Sources Tab / Network 200 OK inspection)

#### Observation
The production Vite build published source map files alongside compiled bundles:
```http
GET /assets/index-D7b3qL1a.js.map HTTP/1.1
Host: portal.healthtechconnect.io

HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 3849102
{"version":3,"file":"index-D7b3qL1a.js","sources":["src/services/telehealth.ts","src/auth/jwtDecoder.ts", ...]}
```
#### Impact
Adversaries obtain unminified TypeScript source code, backend route specifications, internal variable names, and hidden administrative feature flags.

---

### Finding HTC-SEC-008: Unauthenticated Swagger / OpenAPI Documentation Endpoint
- **OWASP Top 10 Category**: A01:2021 – Broken Access Control
- **Severity**: **LOW** | **CVSS v3.1**: `3.1` (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)
- **Asset**: `https://api.healthtechconnect.io/v1/docs` & `https://api.healthtechconnect.io/v1/openapi.json`
- **Discovery Method**: Automated Web Crawl & DevTools Network

#### Observation
Accessing `/v1/docs` renders the interactive Swagger UI without requiring bearer token authentication. Attackers can view unpublished FHIR ingestion schemas, staging parameters, and internal error structures.

---

## 5. HTTP Security Header Baseline Assessment Matrix

A detailed analysis of security headers returned by `portal.healthtechconnect.io` was evaluated against the Mozilla Observatory standard:

| Security Header | Target Standard | Current State | Status | Risk Level |
| :--- | :--- | :--- | :---: | :---: |
| **Content-Security-Policy** | `default-src 'self'; script-src 'self' 'nonce-...'; frame-ancestors 'none';` | *Missing entirely* | ❌ FAIL | **HIGH** |
| **Strict-Transport-Security** | `max-age=63072000; includeSubDomains; preload` | *Missing entirely* | ❌ FAIL | **MEDIUM** |
| **X-Frame-Options** | `DENY` or `SAMEORIGIN` | *Missing entirely* | ❌ FAIL | **HIGH** |
| **X-Content-Type-Options** | `nosniff` | *Missing entirely* | ❌ FAIL | **LOW** |
| **Referrer-Policy** | `strict-origin-when-cross-origin` | `no-referrer-when-downgrade` (Default) | ❌ FAIL | **MEDIUM** |
| **Permissions-Policy** | `camera=(self), microphone=(self), geolocation=()` | *Missing entirely* | ❌ FAIL | **MEDIUM** |
| **Cross-Origin-Opener-Policy**| `same-origin` | *Missing entirely* | ❌ FAIL | **LOW** |
| **Server Banner** | Token removed or generic | `nginx/1.25.3` (Disclosing exact version) | ❌ FAIL | **INFO** |

**Current Mozilla Observatory Grade: F (0 / 100)**  
**Target Post-Remediation Grade: A+ (115 / 100)**

---

## 6. Initial Recommendations & Remediation Priorities

1. **Immediate Quarantine of LocalStorage (Within 24 Hours)**:
   - Deprecate storing JWTs and ePHI objects in `localStorage`.
   - Implement `HttpOnly`, `Secure`, `SameSite=Strict` cookies for session tokens.
2. **Ingress Security Header Hardening (Within 48 Hours)**:
   - Inject standardized security headers at the Nginx ingress tier.
   - Suppress `Server` response header tokens.
3. **Build Pipeline Sanitization (Within 72 Hours)**:
   - Disable `.map` production sourcemap generation in `vite.config.ts`.
   - Restrict `/v1/docs` to VPN/Authenticated developer roles.
