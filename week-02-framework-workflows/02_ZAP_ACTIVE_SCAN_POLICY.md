# OWASP ZAP AUTOMATED SCANNING PROFILE & RULE POLICY
## Automated DAST Configuration for HealthTech Connect
**Tool:** OWASP ZAP (Zed Attack Proxy) v2.14.0  
**Target Environment:** Staging (`https://portal.healthtechconnect.io` & `https://api.healthtechconnect.io`)  
**Scan Policy ID:** `HTC-DAST-STAGING-POLICY-v1.2`  
**Purpose:** Establish automated vulnerability scanning without causing denial of service or invalid state corruption in clinical databases.

---

## 1. Scanner Profile Architecture & Policy Parameters

To satisfy the project KPI of `< 5%` false-positive rate while protecting the staging database cluster from thread exhaustion, the scanning profile is tuned with:
- **Threshold (Sensitivity)**: **HIGH** (Suppresses ambiguous or unreliable alerts to minimize noise).
- **Attack Strength (Injection Intensity)**: **MEDIUM** (Limits concurrent HTTP probe variations per parameter to prevent database locks and latency degradation).

```
+-----------------------------------------------------------------------------------------------+
|                            ZAP ACTIVE SCAN POLICY CONFIGURATION                               |
+------------------------------------+--------------------------+-------------------------------+
| Parameter                          | Configured Value         | Rationale                     |
+------------------------------------+--------------------------+-------------------------------+
| Concurrent Scanner Threads         | 4 threads                | Prevents staging CPU spike    |
| Max Rule Duration                  | 5 minutes per rule       | Eliminates infinite loop hangs|
| Delay Between Requests             | 50 ms                    | Rate limit protection         |
| Handle Anti-CSRF Tokens            | Enabled (`csrf_token`)   | Ensures form state continuity |
| Default Alert Threshold            | High                     | Strict false positive control |
| Default Attack Strength            | Medium                   | Safe depth for staging APIs   |
+------------------------------------+--------------------------+-------------------------------+
```

---

## 2. Authentication & Session Management Configuration

The HealthTech Connect platform uses JSON-based Bearer token authentication via OAuth2/Keycloak. ZAP is configured with a custom script and session management wrapper to maintain authentication across spiders and active scanners.

### 2.1 Context Definition (`healthtech-context.json`)
```json
{
  "context": {
    "name": "HealthTech-Connect-Staging",
    "urls": [
      "https://portal.healthtechconnect.io.*",
      "https://api.healthtechconnect.io/v1.*"
    ],
    "excludeUrls": [
      "https://portal.healthtechconnect.io/assets/.*\\.png",
      "https://portal.healthtechconnect.io/assets/.*\\.jpg",
      "https://portal.healthtechconnect.io/assets/.*\\.svg",
      "https://portal.healthtechconnect.io/assets/.*\\.woff2",
      "https://api.healthtechconnect.io/v1/auth/logout.*",
      "https://api.healthtechconnect.io/v1/auth/reset-password.*",
      "https://api.healthtechconnect.io/v1/billing/process-payment.*"
    ],
    "authentication": {
      "method": "json",
      "loginUrl": "https://api.healthtechconnect.io/v1/auth/login",
      "loginRequestBody": "{\"username\":\"auditor_test_user@healthtechconnect.io\",\"password\":\"${AUDIT_TEST_PWD}\"}",
      "tokenPath": "data.access_token"
    },
    "sessionManagement": {
      "method": "httpAuthHeader",
      "headerName": "Authorization",
      "headerPrefix": "Bearer "
    }
  }
}
```

### 2.2 Excluded URLs & Regex Blacklist
To prevent test suite termination and unwanted state corruption, the following patterns are strictly excluded from automated active attacks:
1. `.*logout.*`: Prevents ZAP from invalidating its own active test session.
2. `.*reset-password.*`: Prevents sending mass mock password-reset emails to non-existent addresses.
3. `.*billing/process-payment.*`: Prevents triggering mock credit card gateway rate limits.

---

## 3. Active Scanning Rules Matrix & Tuning

The table below details the active scanner rule IDs enabled, their assigned threat category, alert threshold, and payload tuning:

| Plugin ID | Scan Rule Category | OWASP 2021 | Threshold | Strength | Target Parameters |
| :---: | :--- | :--- | :---: | :---: | :--- |
| **40018** | SQL Injection (Generic & Hypersonic) | A03: Injection | HIGH | MEDIUM | Query strings, JSON body, URI paths |
| **40012** | Cross Site Scripting (Reflected) | A03: Injection | HIGH | MEDIUM | Query params, HTTP headers, form inputs |
| **40014** | Cross Site Scripting (Persistent) | A03: Injection | HIGH | LOW | Clinical notes, user profile names |
| **40003** | Path Traversal / LFI | A01: Access Control | HIGH | MEDIUM | File download and report export paths |
| **90020** | Remote OS Command Injection | A03: Injection | HIGH | LOW | Diagnostic upload endpoints |
| **40034** | Server-Side Request Forgery (SSRF) | A10: SSRF | HIGH | MEDIUM | Webhook endpoints, FHIR sync callbacks |
| **10045** | Source Code Disclosure | A05: Security Misconfig | HIGH | MEDIUM | Static assets, root directories |
| **40026** | Cross-Site Request Forgery (CSRF) | A01: Access Control | MEDIUM | MEDIUM | State-changing POST/PUT requests |

---

## 4. Automation Execution CLI Command

The scan policy is automated within CI/CD pipelines and local staging verification runs using the following standardized Docker CLI invocation:

```bash
# Execute Baseline & Spider Crawl
docker run --rm -v $(pwd):/zap/wrk/:rw \
  -t zaproxy/zap-stable zap-baseline.py \
  -t https://portal.healthtechconnect.io \
  -g gen.conf \
  -r zap_baseline_report.html \
  -J zap_baseline_report.json

# Execute Targeted Active Scan with Authenticated Context
docker run --rm -v $(pwd):/zap/wrk/:rw \
  -t zaproxy/zap-stable zap-full-scan.py \
  -t https://api.healthtechconnect.io/v1 \
  -c zap_active_scan_policy.conf \
  -n healthtech-context.json \
  -u auditor_test_user@healthtechconnect.io \
  -r zap_active_scan_report.html \
  -J zap_active_scan_report.json
```
