# STANDARDIZED VULNERABILITY REPORT & PROOF-OF-CONCEPT (POC) TEMPLATE
## HealthTech Connect Enterprise Security Assurance Schema
**Document Version:** 2.1  
**Target Compliance:** OWASP Top 10:2021 & HIPAA Security Rule (45 CFR § 164.312)  
**Intended Audience:** Security Auditors, DevSecOps Engineers, Software Developers, and Compliance Officers

---

## 1. Template Structure & Usage Guidelines
This template must be used for documenting any vulnerability discovered during automated scanning or manual inspection. All vulnerability submissions must include non-destructive, benign reproduction steps, exact HTTP artifacts, impact analysis, and specific remediation actions.

---

## 2. Standardized Vulnerability Reporting Template (Markdown Schema)

```markdown
# [VULNERABILITY ID]: [Concise Vulnerability Title]

## 1. Finding Metadata
- **Vulnerability ID**: HTC-SEC-XXX
- **Target Asset / URL**: `https://subdomain.healthtechconnect.io/path/endpoint`
- **OWASP Top 10 (2021) Category**: AXX:2021 - [Category Name]
- **Common Weakness Enumeration (CWE)**: CWE-XXX: [CWE Title]
- **HIPAA Security Rule Reference**: 45 CFR § 164.312([Section])([Subsection])
- **CVSS v3.1 Base Score**: [X.X] ([CRITICAL | HIGH | MEDIUM | LOW])
- **CVSS v3.1 Vector String**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **Discovery Method**: [OWASP ZAP Plugin ID / Browser DevTools / Manual Source Audit]
- **Auditor / Reporter**: [Name / Lead Security Auditor]
- **Triage Status**: [OPEN | TRIAGED | IN REMEDIATION | RETEST REQUIRED | VERIFIED]

---

## 2. Technical Description & Vulnerability Summary
[Provide an exact, highly technical explanation of the flaw, the affected software component, and why the vulnerability exists (e.g., lack of sanitization, improper header propagation, missing authorization middleware).]

---

## 3. Business & HIPAA Compliance Impact
[Detail the realistic organizational consequences if this vulnerability is exploited in production:
- Threat to Protected Health Information (ePHI confidentiality, integrity, availability).
- Potential regulatory penalties under HIPAA Enforcement Rule (45 CFR Part 160).
- Operational or clinical disruption.]

---

## 4. Step-by-Step Non-Destructive Verification Procedure
1. [Prerequisite: Setup test environment and obtain test credentials for User A and User B].
2. [Step 1: Navigate to the target URL in browser with DevTools Network tab active].
3. [Step 2: Submit a benign probe string or inspect application state].
4. [Step 3: Capture the resulting HTTP request and observe the response behavior].
5. [Step 4: Verify boundary enforcement failure].

---

## 5. Raw HTTP Request & Response Proof of Concept

### 5.1 Outgoing HTTP Request
```http
POST /api/v1/clinical/telehealth/session HTTP/1.1
Host: api.healthtechconnect.io
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json
Content-Length: [length]

{
  "parameter": "benign_probe_value"
}
```

### 5.2 Server HTTP Response
```http
HTTP/1.1 200 OK
Date: Sun, 01 Nov 2026 19:00:00 GMT
Content-Type: application/json; charset=utf-8
Content-Length: [length]

{
  "status": "success",
  "data": {
    "sensitive_field": "revealed_value"
  }
}
```

---

## 6. Root Cause Analysis & Remediation Recommendation
- **Root Cause**: [Explain the exact flaw in the code or server config, e.g., missing parameterization or unauthenticated route].
- **Recommended Remediation**: [Provide specific instructions and code snippet / config directive].
- **Reference SOP**: [Link to internal remediation SOP, e.g., SOP-002: CSP Header Injection].

---

## 7. Verification & Retest Evidence
- **Retest Date**: [YYYY-MM-DD]
- **Retest Auditor**: [Name]
- **Retest Tool**: [OWASP ZAP / cURL / DevTools]
- **Retest Outcome**: [PASSED (Closed) / FAILED (Reopened)]
- **Verification Evidence**:
```http
HTTP/1.1 403 Forbidden
Content-Type: application/json

{"error": "Unauthorized access to resource"}
```
```

---

## 3. Example Populated Vulnerability Report: Insecure Direct Object Reference (IDOR)

### HTC-SEC-009: Insecure Direct Object Reference (IDOR) in Patient Diagnostic Lab Endpoint

#### 1. Finding Metadata
- **Vulnerability ID**: HTC-SEC-009
- **Target Asset / URL**: `https://api.healthtechconnect.io/v1/patients/{patient_mrn}/lab-results`
- **OWASP Top 10 (2021) Category**: A01:2021 – Broken Access Control
- **Common Weakness Enumeration (CWE)**: CWE-639: Authorization Bypass Through User-Controlled Key
- **HIPAA Security Rule Reference**: 45 CFR § 164.312(a)(1) (Access Control)
- **CVSS v3.1 Base Score**: **8.6** (HIGH)
- **CVSS v3.1 Vector String**: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- **Discovery Method**: Chrome DevTools Network Tab / Parameter Manipulation
- **Auditor / Reporter**: Lead Web Security Auditor
- **Triage Status**: **OPEN**

#### 2. Technical Description & Vulnerability Summary
The `/v1/patients/{patient_mrn}/lab-results` endpoint in the Node.js API Gateway fails to validate whether the authenticated patient identity encoded in the JWT claims matches the `{patient_mrn}` parameter supplied in the URL path. 

The controller extracts the `{patient_mrn}` parameter directly from `req.params` and queries the database without verifying `req.user.mrn == req.params.patient_mrn`. Consequently, any authenticated patient can view any other patient's clinical lab panels (bloodwork, pathology, metabolic panels) by simply modifying the identifier string in the URI.

#### 3. Business & HIPAA Compliance Impact
This represents a direct violation of HIPAA § 164.312(a)(1), exposing Protected Health Information (ePHI) across patient boundaries. Exploitation requires only a valid standard patient account and basic knowledge of the MRN format (`MRN-XXXXXX-US`), presenting severe regulatory breach disclosure obligations and financial liability under HIPAA Tier 4 civil monetary penalties.

#### 4. Step-by-Step Non-Destructive Verification Procedure
1. Log into `portal.healthtechconnect.io` using test patient account `patient_test_01` (Assigned MRN: `MRN-902184-US`).
2. Open DevTools Network tab and click on **"Lab Results"**.
3. Copy the valid Bearer token from the request header.
4. Using DevTools Network Replay or cURL, issue a request targeting peer test patient `MRN-902185-US` while sending `patient_test_01`'s authorization token:
   ```bash
   curl -s -X GET "https://api.healthtechconnect.io/v1/patients/MRN-902185-US/lab-results" \
     -H "Authorization: Bearer <token_of_patient_902184>"
   ```
5. Confirm that the server responds with HTTP 200 OK containing `MRN-902185-US` lab diagnostic values.

#### 5. Raw HTTP Request & Response Proof of Concept

**HTTP Request:**
```http
GET /v1/patients/MRN-902185-US/lab-results HTTP/1.1
Host: api.healthtechconnect.io
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3ItOTAxMTgiLCJtcm4iOiJNUk4tOTAyMTg0LVVTIiwicm9sZSI6InBhdGllbnQifQ.sig...
Accept: application/json
```

**HTTP Response:**
```http
HTTP/1.1 200 OK
Date: Sun, 01 Nov 2026 19:15:22 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 488

{
  "status": "success",
  "patient_mrn": "MRN-902185-US",
  "reports": [
    {
      "test_name": "Comprehensive Metabolic Panel",
      "specimen_date": "2026-10-28",
      "findings": "Elevated ALT/AST hepatic markers",
      "ordering_physician": "Dr. S. Vance, MD"
    }
  ]
}
```

#### 6. Root Cause Analysis & Remediation Recommendation
- **Root Cause**: Missing ownership authorization middleware. The endpoint relies solely on token validity without checking tenant/resource ownership.
- **Remediation**: Implement an authorization middleware (`verifyResourceOwnership`) in Express.js:
  ```javascript
  // Express.js Middleware Fix:
  function verifyPatientOwnership(req, res, next) {
    if (req.user.role !== 'admin' && req.user.mrn !== req.params.patient_mrn) {
      return res.status(403).json({
        status: "error",
        code: "AUTH_FORBIDDEN",
        message: "You are not authorized to view health records for this patient identifier."
      });
    }
    next();
  }
  ```
