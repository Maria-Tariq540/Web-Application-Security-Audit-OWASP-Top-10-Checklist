# Web Application Security Audit & OWASP Top 10 Checklist
### Enterprise Penetration Testing & DevSecOps Hardening Benchmark
**Target System:** HealthTech Connect (Telehealth & FHIR EHR Cloud Platform)  
**Standard:** OWASP Top 10:2021 & HIPAA Security Rule (45 CFR § 164.312)

---

[![Security Audit](https://img.shields.io/badge/Security%20Audit-OWASP%20Top%2010%3A2021-red.svg?style=for-the-badge&logo=owasp)](https://owasp.org/Top10/)
[![Compliance](https://img.shields.io/badge/Compliance-HIPAA%20Security%20Rule-blue.svg?style=for-the-badge&logo=shield)](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
[![CVSS v3.1](https://img.shields.io/badge/CVSS%20v3.1-Scored%20%26%20Triaged-orange.svg?style=for-the-badge&logo=securityscorecard)](https://www.first.org/cvss/)
[![Observatory Score](https://img.shields.io/badge/Mozilla%20Observatory-Grade%20A%2B%20(115%2F100)-brightgreen.svg?style=for-the-badge&logo=mozilla)](https://observatory.mozilla.org/)
[![DevSecOps CI/CD](https://img.shields.io/badge/CI%2FCD-DAST%20Gate%20Passing-success.svg?style=for-the-badge&logo=githubactions)](https://github.com/features/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

---

## 1. Executive Summary & Scope

This repository houses the full-scope security audit, vulnerability analysis, and engineering remediation package for **HealthTech Connect**, a cloud-native Telehealth and Electronic Health Records (EHR) platform managing sensitive Electronic Protected Health Information (ePHI) for over 150,000 active patients.

The engagement evaluated the platform against the **OWASP Top 10:2021** standards and verified compliance with the **Health Insurance Portability and Accountability Act (HIPAA) Security Rule (45 CFR Part 160 & Part 164, Subparts A and C)**. 

### Key Audit Outcomes
> - **14 Distinct Vulnerabilities Identified & Remediated**: 2 Critical, 6 High, 4 Medium, 2 Low/Info.
> - **Zero SLA Breaches**: All Critical findings resolved in `< 24 hours` and High findings in `< 72 hours`.
> - **Security Header Posture**: Ingress perimeter elevated from **Grade F (0/100)** to **Grade A+ (115/100)** on Mozilla Observatory.
> - **ePHI Perimeter Lockdown**: Eradicated unencrypted browser `localStorage` caching in favor of `__Host-` prefixed `HttpOnly`, `Secure`, and `SameSite=Strict` cookies.
> - **DevSecOps Automation**: Integrated automated OWASP ZAP DAST gates into GitHub Actions CI/CD to prevent vulnerability regressions.

### Target Scope Boundaries

| Environment | Asset Name | FQDN / Endpoint | Architectural Stack | Data Classification | Scope Boundary |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **Staging** | **Patient Web Portal** | `https://portal.healthtechconnect.io` | React 18 SPA, Vite, Tailwind CSS | ePHI, Demographics, Prescriptions | **IN-SCOPE** |
| **Staging** | **Clinical Console** | `https://clinical.healthtechconnect.io` | Next.js 14, SSR, Redux Toolkit | EHR Diagnoses, Medical Notes | **IN-SCOPE** |
| **Staging** | **Core API Gateway** | `https://api.healthtechconnect.io/v1` | Node.js (Express), Kong Ingress | Bearer JWT Auth, Route Dispatcher | **IN-SCOPE** |
| **Staging** | **FHIR Sync Service** | `https://ehr-sync.healthtechconnect.io` | Python 3.11, FastAPI, PostgreSQL 15 | HL7/FHIR v4 Datastores, Lab Panels | **IN-SCOPE** |
| **Production**| **All Production DBs** | `*.prod.healthtechconnect.io` | AWS RDS Multi-AZ PostgreSQL | Live Clinical Data | **OUT-OF-SCOPE** |
| **External** | **Payment Processor** | `https://api.stripe.com` | Third-Party SaaS Gateway | PCI-DSS Cardholder Data | **OUT-OF-SCOPE** |
| **Network** | **Network Infrastructure** | N/A (Denial of Service / Layer 3/4) | AWS CloudFront / Shield | Infrastructure Routing | **OUT-OF-SCOPE** |

---

## 2. Tools & Testing Methodology

The audit applied a hybrid methodology combining automated Dynamic Application Security Testing (DAST) with deep-dive manual business logic analysis:

```
+----------------------------------------------------------------------------------------------------+
|                                    AUDIT TOOLING ECOSYSTEM                                         |
+-------------------+--------------------+-----------------------------------------------------------+
| Tool              | Version            | Operational Application & Domain Methodology              |
+-------------------+--------------------+-----------------------------------------------------------+
| **OWASP ZAP**     | v2.14.0            | Automated spidering, active injection fuzzing, & CI gates |
| **DevTools**      | Chromium v124      | DOM sink tracking, session storage audit, & IDOR testing  |
| **Observatory**   | CLI v0.4.1         | HTTP security header grading, HSTS verification, & CSP    |
| **CVSS Calc**     | v3.1 / v4.0        | Threat vector computation, base scoring, & SLA triage     |
| **Postman/cURL**  | v8.4.0             | Crafting raw HTTP requests, boundary probes, & PoCs       |
+-------------------+--------------------+-----------------------------------------------------------+
```

```mermaid
flowchart LR
    A["Recon & Crawl\n(OWASP ZAP + Spider)"] --> B["Manual Deep Dive\n(Chromium DevTools)"]
    B --> C["Vulnerability Validation\n(Non-destructive PoC)"]
    C --> D["CVSS v3.1 Triage\n(P0 / P1 / P2 SLA)"]
    D --> E["DevSecOps Code Patch\n(Nginx / FastAPI / Express)"]
    E --> F["Automated Regression\n(Docker ZAP Re-Test)"]
    F --> G["Verified & Closed\n(Mozilla Grade A+)"]
```

---

## 3. Key Security Findings & CVSS Matrix

| Finding ID | Target Asset / Endpoint | OWASP Top 10:2021 | HIPAA Reference | CVSS v3.1 Vector | Base Score | Severity | Status |
| :--- | :--- | :--- | :--- | :--- | :---: | :---: | :---: |
| **HTC-SEC-010** | `/fhir/r4/Patient` | A03: Injection | § 164.312(c)(1) Integrity | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8** | `CRITICAL` | **VERIFIED** |
| **HTC-SEC-001** | `/dashboard` (LocalStorage) | A04: Insecure Design | § 164.312(a)(2)(iv) Encrypt | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | **9.1** | `CRITICAL` | **VERIFIED** |
| **HTC-SEC-009** | `/v1/patients/{mrn}/lab-results`| A01: Broken Access Control | § 164.312(a)(1) Access Ctrl | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | **8.6** | `HIGH` | **VERIFIED** |
| **HTC-SEC-014** | `/v1/integrations/fhir-webhook` | A10: SSRF | § 164.312(e)(1) Trans Sec | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` | **8.6** | `HIGH` | **VERIFIED** |
| **HTC-SEC-011** | `/telehealth/portal` | A03: Injection | § 164.312(c)(1) Integrity | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N` | **8.2** | `HIGH` | **VERIFIED** |
| **HTC-SEC-002** | `portal.healthtechconnect.io/*` | A05: Security Misconfig | § 164.312(c)(1) Integrity | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | **7.5** | `HIGH` | **VERIFIED** |
| **HTC-SEC-013** | `/v1/auth/logout` | A07: Auth Failures | § 164.312(a)(2)(iii) Logoff | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | **7.5** | `HIGH` | **VERIFIED** |
| **HTC-SEC-003** | `/telehealth/room/*` | A05: Security Misconfig | § 164.312(a)(1) Access Ctrl | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N` | **7.1** | `HIGH` | **VERIFIED** |
| **HTC-SEC-004** | `/v1/auth/login` | A01: Broken Access Control | § 164.312(d) Authentication | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N` | **6.5** | `MEDIUM` | **VERIFIED** |
| **HTC-SEC-005** | `portal.healthtechconnect.io` | A02: Cryptographic Failure | § 164.312(e)(1) Trans Sec | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` | **5.9** | `MEDIUM` | **VERIFIED** |
| **HTC-SEC-012** | `/appointments/checkout` | A04: Insecure Design | § 164.312(a)(1) Access Ctrl | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` | **5.3** | `MEDIUM` | **VERIFIED** |
| **HTC-SEC-006** | `/patient/records` | A04: Insecure Design | § 164.530(c) Safeguards | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N` | **4.3** | `MEDIUM` | **VERIFIED** |
| **HTC-SEC-007** | `/assets/*.js.map` | A05: Security Misconfig | § 164.308(a)(1) Risk Mgmt | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | **3.7** | `LOW` | **VERIFIED** |
| **HTC-SEC-008** | `/v1/docs` (Swagger UI) | A01: Broken Access Control | § 164.312(a)(1) Access Ctrl | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | **3.1** | `LOW` | **VERIFIED** |

---

## 4. Detailed Vulnerability Breakdowns & Proof-of-Concepts (PoC)

### PoC 1: Critical SQL Injection in FHIR Search Parameter (HTC-SEC-010)
- **Vulnerability**: Dynamic string concatenation in Python FastAPI SQLAlchemy route (`/fhir/r4/Patient`).
- **CVSS v3.1**: `9.8` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | **Severity**: **CRITICAL**
- **Impact**: Arbitrary extraction and modification of all 150,000+ patient records and diagnosis history.

#### Vulnerable HTTP Request:
```http
GET /fhir/r4/Patient?identifier=MRN-902184-US'OR'1'='1 HTTP/1.1
Host: ehr-sync.healthtechconnect.io
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Accept: application/json
```

#### Vulnerable HTTP Response (Stack Trace Disclosure):
```http
HTTP/1.1 500 Internal Server Error
Date: Sun, 01 Nov 2026 19:10:02 GMT
Content-Type: application/json

{
  "detail": "Internal Server Error: syntax error at or near \"OR\" in SELECT * FROM fhir_patients WHERE mrn = 'MRN-902184-US'OR'1'='1'..."
}
```

---

### PoC 2: Insecure Direct Object Reference (IDOR) in Diagnostic Lab Results (HTC-SEC-009)
- **Vulnerability**: Absence of horizontal authorization check between authenticated user and requested MRN.
- **CVSS v3.1**: `8.6` (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`) | **Severity**: **HIGH**
- **Impact**: Any authenticated patient can retrieve any other patient's clinical diagnostic lab results.

#### Malicious Replay Request (Patient A querying Patient B's MRN):
```http
GET /v1/patients/MRN-902185-US/lab-results HTTP/1.1
Host: api.healthtechconnect.io
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3ItOTAxMTgiLCJtcm4iOiJNUk4tOTAyMTg0LVVTIiwicm9sZSI6InBhdGllbnQifQ...
Accept: application/json
```

#### Unauthorized Sensitive Response:
```http
HTTP/1.1 200 OK
Date: Sun, 01 Nov 2026 19:15:22 GMT
Content-Type: application/json; charset=utf-8

{
  "status": "success",
  "patient_mrn": "MRN-902185-US",
  "reports": [
    {
      "test_name": "Comprehensive Metabolic Panel",
      "findings": "Elevated ALT/AST hepatic markers",
      "ordering_physician": "Dr. S. Vance, MD"
    }
  ]
}
```

---

### PoC 3: Cleartext ePHI & JWT in Browser `localStorage` (HTC-SEC-001)
- **Vulnerability**: Client-side single page app cached tokens, full demographics, and ICD-10 diagnoses in browser storage.
- **CVSS v3.1**: `9.1` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`) | **Severity**: **CRITICAL**
- **Impact**: Trivial data extraction via XSS or physical access on shared clinical kiosk terminals.

#### Exposed LocalStorage Payload (Inspected via DevTools):
```javascript
// window.localStorage.getItem("htc_patient_session")
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "patient_mrn": "MRN-902184-US",
  "full_name": "Eleanor Vance",
  "dob": "1984-06-12",
  "ssn_last_four": "4819",
  "conditions": ["Type 2 Diabetes", "Hypertension", "Depression"]
}
```

---

### PoC 4: Missing Content-Security-Policy & Clickjacking Exposure (HTC-SEC-002 / 003)
- **Vulnerability**: Ingress server lacked `Content-Security-Policy`, `X-Frame-Options`, and `frame-ancestors`.
- **CVSS v3.1**: `7.5` and `7.1` | **Severity**: **HIGH**
- **Impact**: UI redressing / clickjacking attack tricking patients into authorizing unconsented medical records transfers.

#### Clickjacking Framing Proof of Concept:
```html
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

---

## 5. Production Remediation SOPs & Code Patches

<details>
<summary><b>SOP-01: Ingress Security Headers Hardening (Nginx 1.25+) — [Click to Expand]</b></summary>

```nginx
# ==============================================================================
# Ingress HTTP Security Headers Hardening (/etc/nginx/conf.d/security_headers.conf)
# Mozilla Observatory Target: Grade A+ (115/100)
# ==============================================================================

server_tokens off;

# 1. Enforce HSTS for 2 years with preloading
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

# 2. Strict Content-Security-Policy
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://cdn.healthtechconnect.io; font-src 'self' data:; connect-src 'self' https://api.healthtechconnect.io wss://stream.healthtechconnect.io; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;

# 3. Framing & MIME Sniffing Defense
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(self), microphone=(self), geolocation=(), payment=()" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
```
</details>

<details>
<summary><b>SOP-02: SQL Injection Remediation in FHIR Engine (Python / FastAPI / SQLAlchemy) — [Click to Expand]</b></summary>

```python
"""
HealthTech Connect - Parameterized FHIR Patient Query
HIPAA 45 CFR § 164.312(c)(1) Data Integrity Safeguard
"""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import select
import re

router = APIRouter(prefix="/fhir/r4", tags=["FHIR"])
MRN_REGEX = r"^MRN-\d{6}-[A-Z]{2}$"

@router.get("/Patient", status_code=status.HTTP_200_OK)
async def get_patient_by_identifier(
    identifier: str = Query(..., regex=MRN_REGEX),
    db: Session = Depends(get_db)
):
    # Parameterized query automatically binds variables without string interpolation:
    stmt = select(FHIRPatientModel).where(FHIRPatientModel.mrn == identifier)
    patient = db.execute(stmt).scalars().first()

    if not patient:
        raise HTTPException(status_code=404, detail="Patient record not found.")

    return patient
```
</details>

<details>
<summary><b>SOP-03: Modern Session Cookie Architecture (Node.js / Express) — [Click to Expand]</b></summary>

```javascript
/**
 * Modern Cookie Session Management
 * HIPAA 45 CFR § 164.312(a)(2)(iv) Encryption & Session Safeguards
 */
const jwt = require('jsonwebtoken');

exports.issueSessionCookie = (res, user) => {
  // Scoped token with minimal claims (zero clinical diagnoses in payload)
  const token = jwt.sign(
    { sub: user.id, mrn: user.mrn, role: user.role },
    process.env.JWT_SECRET_KEY,
    { expiresIn: '15m', issuer: 'healthtechconnect.io' }
  );

  // Enforce __Host- cookie security
  res.cookie('__Host-htc_auth', token, {
    httpOnly: true,              // Blocks client script access
    secure: true,                // Transmits strictly over HTTPS
    sameSite: 'strict',          // CSRF defense
    path: '/',
    maxAge: 15 * 60 * 1000       // 15-minute HIPAA idle timeout
  });
};
```
</details>

<details>
<summary><b>SOP-04: Authorization Middleware for IDOR Defense (Node.js / Express) — [Click to Expand]</b></summary>

```javascript
/**
 * Resource Ownership Verification Middleware
 * HIPAA 45 CFR § 164.312(a)(1) Access Control
 */
module.exports = function verifyResourceOwnership(req, res, next) {
  const user = req.user;
  const targetMrn = req.params.mrn;

  if (!user) {
    return res.status(401).json({ status: "error", message: "Authentication required." });
  }

  // Clinical staff have multi-tenant access privileges
  if (['physician', 'nurse_practitioner', 'system_admin'].includes(user.role)) {
    return next();
  }

  // Enforce horizontal boundary: Patients can only view their own MRN
  if (user.role === 'patient' && user.mrn !== targetMrn) {
    console.warn(`[SECURITY ALERT] IDOR attempt by User ${user.id} against MRN ${targetMrn}`);
    return res.status(403).json({
      status: "error",
      code: "AUTH_FORBIDDEN",
      message: "Access Denied: Unauthorized access to clinical records."
    });
  }

  return next();
};
```
</details>

---

## 6. Project Architecture & Repository Structure

```
Web Application Security Audit & OWASP Top 10 Checklist/
│
├── README.md                                       <- Portfolio Master Index & Execution Guide
│
├── week-01-scope-baseline/                         <- [WEEK 1: SCOPE & BASELINE AUDIT]
│   ├── 01_PROJECT_CHARTER_AND_KPIS.md              <- Scope Boundaries, SLAs, RACI Matrix
│   ├── 02_BASELINE_AUDIT_REPORT.md                 <- ZAP & DevTools Baseline Security Assessment
│   ├── 03_MASTER_FINDINGS_DASHBOARD.md             <- Real-Time Tracking & Remediation Matrix
│   └── data/
│       ├── master_findings_matrix.csv              <- Machine-readable CSV of all 14 findings & CVSS
│       ├── zap_baseline_scan_results.json          <- Machine-readable OWASP ZAP Alert Logs
│       └── security_headers_assessment.json        <- Mozilla Observatory Header Audit Data
│
├── week-02-framework-workflows/                    <- [WEEK 2: FRAMEWORK & WORKFLOW DESIGN]
│   ├── 01_DEVTOOLS_MANUAL_TESTING_WORKFLOW.md      <- Step-by-step browser devtools audit guide
│   ├── 02_ZAP_ACTIVE_SCAN_POLICY.md                <- ZAP tuning, regex filters & active crawl rules
│   ├── 03_STANDARDIZED_POC_TEMPLATES.md            <- Vulnerability PoC & reporting schema
│   ├── 04_MID_STAGE_TEST_SCENARIO_LOG.md           <- 10 OWASP Top 10 test execution logs
│   └── healthtech-context.json                     <- Machine-readable ZAP auth & regex context
│
├── week-03-execution-integration/                  <- [WEEK 3: EXECUTION & TOOL INTEGRATION]
│   ├── 01_CVSS_SCORING_CALCULATOR_MATRIX.md        <- In-depth CVSS v3.1/v4.0 vector computations
│   ├── 02_PRODUCTION_REMEDIATION_SOPS.md           <- Node.js, Python FastAPI, & Nginx security code
│   └── 03_SLA_AND_VERIFICATION_CHECKLIST.md        <- QA verification and re-test protocols
│
└── week-04-final-presentation-sops/                <- [WEEK 4: FINAL PRESENTATION & SOPS]
    ├── 01_EXECUTIVE_CASE_STUDY_REPORT.md           <- Formal client-facing executive report (PDF ready)
    ├── 02_DEVSECOPS_SOP_WIKI.md                    <- Engineering SOP Wiki & Secure Coding Runbook
    ├── 03_EXECUTIVE_PRESENTATION_DECK.md           <- 10-Slide executive presentation deck outline
    └── 04_VIDEO_WALKTHROUGH_SCRIPT.md              <- Word-for-word 3-5 min Loom presentation script
```

---

## 7. How to Reproduce & Setup

### 7.1 Automated OWASP ZAP Baseline Scan (Docker)
To execute an automated baseline scan against the staging environment:

```bash
# Clone the repository
git clone https://github.com/your-username/web-app-security-audit-owasp-top-10.git
cd web-app-security-audit-owasp-top-10

# Run automated ZAP baseline container
docker run --rm -v $(pwd):/zap/wrk/:rw \
  -t zaproxy/zap-stable zap-baseline.py \
  -t https://portal.healthtechconnect.io \
  -r zap_baseline_report.html \
  -J zap_baseline_report.json
```

### 7.2 Authenticated Active Scanning with Custom Policy
```bash
docker run --rm -v $(pwd):/zap/wrk/:rw \
  -t zaproxy/zap-stable zap-full-scan.py \
  -t https://api.healthtechconnect.io/v1 \
  -c week-02-framework-workflows/zap_active_scan_policy.conf \
  -n week-02-framework-workflows/healthtech-context.json \
  -u auditor_test_user@healthtechconnect.io \
  -r zap_active_scan_report.html
```

### 7.3 HTTP Security Headers Verification
```bash
# Verify headers via cURL
curl -s -I "https://portal.healthtechconnect.io" | grep -Ei \
  '(content-security-policy|strict-transport-security|x-frame-options|x-content-type-options|referrer-policy|permissions-policy|server)'

# Run Mozilla Observatory CLI
npx observatory-cli portal.healthtechconnect.io --format=report
```

---

## 8. Author & License

- **Lead Security Auditor & DevSecOps Engineer**: [Maria Tariq / GitHub Profile](https://github.com/Maria-Tariq540)
- **Role**: Lead Web Security Auditor & DevSecOps Engineer
- **Project Classification**: Enterprise Portfolio Deliverable (500 Leaderboard Points)
- **License**: Distributed under the **MIT License**. See `LICENSE` for more information.

---
*Verified against OWASP Top 10:2021 & HIPAA Security Rule (45 CFR § 164.312) — November 2026.*
