# CVSS SCORING CALCULATOR & VULNERABILITY METRICS MATRIX
## Comprehensive Threat Scoring for HealthTech Connect
**Frameworks Evaluated:** Common Vulnerability Scoring System (CVSS) v3.1 & CVSS v4.0  
**Target Application:** HealthTech Connect Telehealth & EHR Platform  
**Compliance Context:** HIPAA Security Rule (45 CFR § 164.312)

---

## 1. CVSS Metric Calculation Principles

Scoring web application vulnerabilities in a clinical environment requires evaluating both the technical exploit mechanics (Base Metrics) and the regulatory impact on Protected Health Information (ePHI).

```
+---------------------------------------------------------------------------------------------------+
|                                  CVSS v3.1 BASE METRIC DEFINITIONS                                |
+------------------+-----------------------------+--------------------------------------------------+
| Metric Group     | Metric                      | Evaluated Scope & Values                         |
+------------------+-----------------------------+--------------------------------------------------+
| **Exploitability**| Attack Vector (AV)          | Network (N), Adjacent (A), Local (L), Physical (P)|
|                  | Attack Complexity (AC)      | Low (L), High (H)                                |
|                  | Privileges Required (PR)    | None (N), Low (L), High (H)                      |
|                  | User Interaction (UI)       | None (N), Required (R)                           |
+------------------+-----------------------------+--------------------------------------------------+
| **Scope**        | Scope (S)                   | Unchanged (U), Changed (C)                       |
+------------------+-----------------------------+--------------------------------------------------+
| **Impact**       | Confidentiality (C)         | High (H), Low (L), None (N)                      |
|                  | Integrity (I)               | High (H), Low (L), None (N)                      |
|                  | Availability (A)            | High (H), Low (L), None (N)                      |
+------------------+-----------------------------+--------------------------------------------------+
```

---

## 2. In-Depth CVSS Breakdown for Core OWASP Vulnerabilities

---

### Vulnerability 1: Critical SQL Injection in FHIR Filter Parameter (HTC-SEC-010)
- **Target Component:** `https://ehr-sync.healthtechconnect.io/fhir/r4/Patient`
- **OWASP Category:** A03:2021 – Injection | **CWE:** CWE-89
- **HIPAA Violation:** 45 CFR § 164.312(c)(1) (Data Integrity) & § 164.312(a)(1) (Access Control)

#### Vector Specifications:
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
  - **Base Score:** **9.8 (CRITICAL)**
- **CVSS v4.0 Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`
  - **Base Score:** **9.3 (CRITICAL)**

#### Metric Justification:
| Metric | Value | Justification |
| :--- | :---: | :--- |
| **Attack Vector (AV)** | `Network` | The FHIR search endpoint is directly reachable over public HTTPS. |
| **Attack Complexity (AC)** | `Low` | Exploitation requires standard SQL injection syntax; no special timing or race conditions exist. |
| **Privileges Required (PR)** | `None` | The endpoint responds to unauthenticated or pre-authenticated search requests. |
| **User Interaction (UI)** | `None` | Exploitation occurs server-side without victim interaction. |
| **Scope (S)** | `Unchanged` | The database compromised is the direct underlying resource of the service. |
| **Confidentiality (C)** | `High` | Total disclosure of entire database contents, exposing 150,000+ patient ePHI records. |
| **Integrity (I)** | `High` | Adversaries can alter diagnosis records, modify prescription dosages, or drop tables. |
| **Availability (A)** | `High` | Adversaries can corrupt database indexes or lock tables, causing total service outage. |

---

### Vulnerability 2: Cleartext ePHI & JWT in Browser `localStorage` (HTC-SEC-001)
- **Target Component:** `https://portal.healthtechconnect.io/dashboard`
- **OWASP Category:** A04:2021 – Insecure Design / A02:2021 – Cryptographic Failures | **CWE:** CWE-312
- **HIPAA Violation:** 45 CFR § 164.312(a)(2)(iv) (Encryption)

#### Vector Specifications:
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
  - **Base Score:** **9.1 (CRITICAL)**
- **CVSS v4.0 Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`
  - **Base Score:** **8.7 (HIGH)**

#### Metric Justification:
| Metric | Value | Justification |
| :--- | :---: | :--- |
| **Attack Vector (AV)** | `Network` | Local storage contents can be extracted remotely via any script execution or shared terminal access. |
| **Attack Complexity (AC)** | `Low` | Client storage API (`localStorage.getItem`) is trivial to access without cryptographic protection. |
| **Privileges Required (PR)** | `None` | No privileged credentials needed; exposed on any active session terminal. |
| **User Interaction (UI)** | `None` | Stored immediately upon authentication without requiring explicit action. |
| **Scope (S)** | `Unchanged` | The affected resource is the local patient session and identity. |
| **Confidentiality (C)** | `High` | Exposes patient full name, DOB, SSN last 4 digits, MRN, and active medical diagnoses. |
| **Integrity (I)** | `High` | Extracted JWT bearer token allows full session impersonation and record tampering. |
| **Availability (A)** | `None` | No disruption to service uptime. |

---

### Vulnerability 3: Insecure Direct Object Reference (IDOR) in Lab Results (HTC-SEC-009)
- **Target Component:** `https://api.healthtechconnect.io/v1/patients/{mrn}/lab-results`
- **OWASP Category:** A01:2021 – Broken Access Control | **CWE:** CWE-639
- **HIPAA Violation:** 45 CFR § 164.312(a)(1) (Access Control)

#### Vector Specifications:
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
  - **Base Score:** **8.6 (HIGH)**
- **CVSS v4.0 Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
  - **Base Score:** **8.6 (HIGH)**

#### Metric Justification:
| Metric | Value | Justification |
| :--- | :---: | :--- |
| **Attack Vector (AV)** | `Network` | Exploit executed over standard API requests. |
| **Attack Complexity (AC)** | `Low` | Requires simple substitution of MRN sequence IDs in the URL path. |
| **Privileges Required (PR)** | `Low` | Attacker needs a standard authenticated patient login. |
| **User Interaction (UI)** | `None` | Direct automated enumeration possible without victim interaction. |
| **Confidentiality (C)** | `High` | Complete disclosure of any target patient's lab panels, pathology reports, and bloodwork. |
| **Integrity (I)** | `None` | Endpoint is read-only (GET). |
| **Availability (A)** | `None` | System availability is unaffected. |

---

### Vulnerability 4: Blind SSRF in FHIR Integration Webhook Registration (HTC-SEC-014)
- **Target Component:** `https://api.healthtechconnect.io/v1/integrations/fhir-webhook`
- **OWASP Category:** A10:2021 – Server-Side Request Forgery | **CWE:** CWE-918
- **HIPAA Violation:** 45 CFR § 164.312(e)(1) (Transmission Security)

#### Vector Specifications:
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N`
  - **Base Score:** **8.6 (HIGH)**
- **CVSS v4.0 Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N`
  - **Base Score:** **8.7 (HIGH)**

#### Metric Justification:
| Metric | Value | Justification |
| :--- | :---: | :--- |
| **Attack Vector (AV)** | `Network` | Exploitable via webhook registration endpoint. |
| **Attack Complexity (AC)** | `Low` | Standard arbitrary URL insertion into callback parameter. |
| **Privileges Required (PR)** | `Low` | Clinical partner account required to register integration webhooks. |
| **User Interaction (UI)** | `None` | Backend automatically triggers dispatch without human intervention. |
| **Scope (S)** | `Changed (C)` | The vulnerable API gateway makes outbound requests to internal VPC systems and cloud metadata services (`169.254.169.254`). |
| **Confidentiality (C)** | `High` | Allows reading internal AWS IAM role temporary credentials and VPC services. |

---

### Vulnerability 5: Reflected DOM XSS via Unescaped View Parameter (HTC-SEC-011)
- **Target Component:** `https://portal.healthtechconnect.io/telehealth/portal`
- **OWASP Category:** A03:2021 – Injection | **CWE:** CWE-79
- **HIPAA Violation:** 45 CFR § 164.312(c)(1) (Data Integrity)

#### Vector Specifications:
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N`
  - **Base Score:** **8.2 (HIGH)**
- **CVSS v4.0 Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:H/SI:L/SA:N`
  - **Base Score:** **8.4 (HIGH)**

#### Metric Justification:
Scope is `Changed` because code executes in the victim's browser origin, capable of reading patient session cookies and DOM contents. Requires User Interaction (`UI:R`) to lure a victim into clicking a crafted consultation link.

---

### Vulnerability 6: Missing Content-Security-Policy & Clickjacking Headers (HTC-SEC-002 / 003)
- **Target Component:** `https://portal.healthtechconnect.io/*`
- **OWASP Category:** A05:2021 – Security Misconfiguration | **CWE:** CWE-693 / CWE-1021
- **CVSS v3.1 Vectors:**
  - Missing CSP (HTC-SEC-002): `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (**7.5 HIGH**)
  - Clickjacking (HTC-SEC-003): `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N` (**7.1 HIGH**)

---

## 3. Comparison Summary: CVSS v3.1 vs. CVSS v4.0

| Vulnerability ID | Vulnerability Title | CVSS v3.1 Score | CVSS v3.1 Severity | CVSS v4.0 Score | CVSS v4.0 Severity | Key Scoring Factor |
| :---: | :--- | :---: | :---: | :---: | :---: | :--- |
| **HTC-SEC-010** | SQL Injection in FHIR Service | **9.8** | CRITICAL | **9.3** | CRITICAL | No auth required, full ePHI DB compromise |
| **HTC-SEC-001** | Cleartext ePHI in LocalStorage | **9.1** | CRITICAL | **8.7** | HIGH | Local cache accessible via XSS/shared kiosk |
| **HTC-SEC-009** | IDOR in Lab Results API | **8.6** | HIGH | **8.6** | HIGH | Broken object authorization between patients |
| **HTC-SEC-014** | Blind SSRF in Webhook System | **8.6** | HIGH | **8.7** | HIGH | Scope Change: Pivoting into AWS metadata |
| **HTC-SEC-011** | Reflected DOM XSS in Telehealth | **8.2** | HIGH | **8.4** | HIGH | UI interaction required, cross-context ePHI theft |
| **HTC-SEC-002** | Missing Content-Security-Policy | **7.5** | HIGH | **7.1** | HIGH | Eliminates defense-in-depth script containment |
| **HTC-SEC-003** | Missing Clickjacking Defense | **7.1** | HIGH | **6.9** | MEDIUM | UI interaction required to frame patient consent |
