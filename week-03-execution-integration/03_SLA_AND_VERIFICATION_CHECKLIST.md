# OPERATIONAL SLA, TRIAGE RULES & QUALITY ASSURANCE CHECKLIST
## DevSecOps Remediation Verification & Governance Framework
**Document ID:** `HTC-QA-SLA-v1.0`  
**Target:** HealthTech Connect Telehealth & Clinical EHR System  
**Framework:** OWASP Top 10:2021 & HIPAA Security Rule (45 CFR Part 160 & 164)

---

## 1. Vulnerability Triage Hierarchy & SLA Standards

Every vulnerability reported during the audit engagement must be triaged within **2 hours** of discovery and assigned an engineering Service Level Agreement (SLA) based on its CVSS v3.1 Base Score:

```
+---------------------------------------------------------------------------------------------------------+
|                                  OPERATIONAL REMEDIATION SLA MATRIX                                     |
+----------+--------------------+----------------+--------------------+-----------------------------------+
| Severity | CVSS v3.1 Range    | Triage SLA     | Fix SLA (Deploy)   | Verification Re-Scan SLA          |
+----------+--------------------+----------------+--------------------+-----------------------------------+
| **P0**   | 9.0 – 10.0 (Crit)  | < 2 Hours      | < 24 Hours         | < 4 Hours post-deployment         |
| **P1**   | 7.0 – 8.9 (High)   | < 6 Hours      | < 72 Hours         | < 12 Hours post-deployment        |
| **P2**   | 4.0 – 6.9 (Med)    | < 24 Hours     | < 14 Days          | Next sprint regression cycle      |
| **P3**   | 0.1 – 3.9 (Low)    | < 48 Hours     | < 30 Days          | Next scheduled monthly scan       |
+----------+--------------------+----------------+--------------------+-----------------------------------+
```

---

## 2. Remediation Verification Protocols (Step-by-Step Re-Test)

Before any finding can be updated from `IN REMEDIATION` to `RESOLVED & VERIFIED`, the Lead Security Auditor must execute the defined re-test protocol.

### Protocol RV-01: Verifying SQL Injection Remediation (HTC-SEC-010)
1. **Target**: `https://ehr-sync.healthtechconnect.io/fhir/r4/Patient`
2. **Execution**:
   ```bash
   # Issue test payload with invalid SQL formatting
   curl -s -i "https://ehr-sync.healthtechconnect.io/fhir/r4/Patient?identifier=MRN-902184-US'OR'1'='1"
   ```
3. **Verification Criteria**:
   - HTTP response must return `400 Bad Request` or `422 Unprocessable Entity`.
   - The response body must contain clean JSON error validation (`"detail": "Invalid MRN identifier format"`).
   - Zero raw database error strings (`psycopg2`, `syntax error near`, `SELECT *`) are leaked.
4. **Sign-off**: `[VERIFIED FIXED]`

---

### Protocol RV-02: Verifying Ingress Security Headers (HTC-SEC-002, 003, 005)
1. **Target**: `https://portal.healthtechconnect.io/`
2. **Execution**:
   ```bash
   curl -s -I "https://portal.healthtechconnect.io/"
   ```
3. **Verification Criteria**:
   - `Content-Security-Policy`: Present, containing `default-src 'self'` and `frame-ancestors 'none'`.
   - `Strict-Transport-Security`: Present, containing `max-age=63072000; includeSubDomains; preload`.
   - `X-Frame-Options`: Present, value `DENY`.
   - `X-Content-Type-Options`: Present, value `nosniff`.
   - `Server`: Version token suppressed (returns `Server: nginx` or absent).
4. **Mozilla Observatory Score**: Target must score **Grade A+ (>= 100/100)**.
5. **Sign-off**: `[VERIFIED FIXED]`

---

### Protocol RV-03: Verifying IDOR Authorization Defense (HTC-SEC-009)
1. **Target**: `https://api.healthtechconnect.io/v1/patients/MRN-902185-US/lab-results`
2. **Execution**:
   - Authenticate as Patient User A (MRN: `MRN-902184-US`).
   - Attempt to access Patient User B's lab results with User A's token:
     ```bash
     curl -s -i -X GET "https://api.healthtechconnect.io/v1/patients/MRN-902185-US/lab-results" \
       -H "Authorization: Bearer <token_patient_user_a>"
     ```
3. **Verification Criteria**:
   - Server returns `403 Forbidden` with `"code": "AUTH_FORBIDDEN"`.
   - Patient B's laboratory diagnostic information is completely withheld.
4. **Sign-off**: `[VERIFIED FIXED]`

---

### Protocol RV-04: Verifying SSRF Protection (HTC-SEC-014)
1. **Target**: `https://api.healthtechconnect.io/v1/integrations/fhir-webhook`
2. **Execution**:
   - Attempt to register webhooks targeting loopback and metadata addresses:
     - `http://127.0.0.1:8080/metrics`
     - `http://169.254.169.254/latest/meta-data/`
     - `http://10.0.0.15:5432/`
3. **Verification Criteria**:
   - Server rejects all attempts with `400 Bad Request` (`"Webhook destination resolves to a restricted internal network address"`).
   - Zero outbound requests are initiated from the server egress interface.
4. **Sign-off**: `[VERIFIED FIXED]`

---

## 3. Automated Regression Re-Scan Command

Following deployment of patches to the staging environment, the DevSecOps automated regression suite is triggered via Docker:

```bash
docker run --rm -v $(pwd):/zap/wrk/:rw \
  -t zaproxy/zap-stable zap-full-scan.py \
  -t https://portal.healthtechconnect.io \
  -c week-02-framework-workflows/zap_scan_policy.conf \
  -n week-02-framework-workflows/healthtech-context.json \
  -r week-03-execution-integration/retest_zap_regression_report.html \
  -J week-03-execution-integration/retest_zap_regression_report.json
```

---

## 4. Quality Assurance Sign-Off Checklist

```
+--------------------------------------------------------------------------------------------------+
|                              FINAL SECURITY VERIFICATION SIGN-OFF                                |
+-------------------------------------------------------------------------+--------------+---------+
| Verification Item                                                       | Verified By  | Status  |
+-------------------------------------------------------------------------+--------------+---------+
| 1. All P0 Critical vulnerabilities remediated and verified (< 24h SLA)  | Sec Lead     | PASS    |
| 2. All P1 High vulnerabilities remediated and verified (< 72h SLA)      | Sec Lead     | PASS    |
| 3. LocalStorage cleared of all tokens, SSNs, and medical condition ePHI | Dev Lead     | PASS    |
| 4. Mozilla Observatory score elevated from Grade F to Grade A+          | SRE Lead     | PASS    |
| 5. Automated ZAP Regression Scan completed with ZERO High/Critical alerts| Sec Lead     | PASS    |
| 6. HIPAA 45 CFR § 164.312 Access & Transmission compliance signed off   | CISO         | PASS    |
+-------------------------------------------------------------------------+--------------+---------+
```
