# BROWSER DEVTOOLS MANUAL TESTING METHODOLOGY & WORKFLOW
## Operational Security Testing Guide for HealthTech Connect (Telehealth Platform)
**Target Standard:** OWASP Top 10:2021 & HIPAA Security Rule (45 CFR § 164.312)  
**Primary Tooling:** Chromium / Firefox Developer Tools (Network, Application, Sources, Console, Security Panels)  
**Auditor Classification:** Lead Web Security Auditor & DevSecOps Engineer

---

## 1. Overview & Operational Principles

Automated Dynamic Application Security Testing (DAST) tools such as OWASP ZAP detect signature-based flaws and header omissions, but fail to uncover complex client-side business logic errors, authorization bypasses, and state-manipulation vulnerabilities. 

This document defines the standardized manual auditing procedures using native Browser Developer Tools to inspect, trace, and audit the **HealthTech Connect** clinical and patient web portals.

```
+--------------------------------------------------------------------------------------------------+
|                                  DEVTOOLS AUDIT WORKSPACE MATRIX                                 |
+-------------------+-----------------------------------------+------------------------------------+
| DevTools Panel    | Primary Security Audit Focus            | OWASP Top 10:2021 Coverage         |
+-------------------+-----------------------------------------+------------------------------------+
| **Network**       | API payloads, Authorization headers,    | A01 (Broken Access Control)        |
|                   | response codes, caching directives      | A02 (Cryptographic Failures)       |
| **Application**   | Cookies, localStorage, sessionStorage,  | A04 (Insecure Design)              |
|                   | IndexedDB, Service Workers              | A07 (Auth & Identification)        |
| **Sources**       | Unminified code, leaked API secrets,    | A05 (Security Misconfiguration)    |
|                   | sourcemaps, DOM XSS sink analysis       | A03 (Injection)                    |
| **Console**       | Client errors, verbose stack traces,    | A09 (Logging & Monitoring)         |
|                   | prototype pollution, CSP violations     | A05 (Security Misconfiguration)    |
| **Security**      | TLS cipher suites, mixed-content,       | A02 (Cryptographic Failures)       |
|                   | certificate validity & SAN alignment    | A08 (Software & Data Integrity)    |
+-------------------+-----------------------------------------+------------------------------------+
```

---

## 2. Step-by-Step OWASP Top 10 DevTools Verification Workflows

### 2.1 A01:2021 — Broken Access Control & IDOR Verification
**Target Endpoints:** `https://portal.healthtechconnect.io/api/v1/patients/{id}/records`

#### Objective:
Verify whether an authenticated patient (User A) can view or modify records belonging to another patient (User B) by altering identity parameters or authorization tokens.

#### Step-by-Step Audit Procedure:
1. Open DevTools (`F12` or `Ctrl+Shift+I`) and navigate to the **Network** tab.
2. Enable **Preserve log** and filter by `Fetch/XHR`.
3. Authenticate as low-privileged test user `patient_test_01` (ID: `902184`).
4. Click on **"My Clinical Records"** and locate the outgoing XHR request:
   `GET /api/v1/patients/902184/records`
5. Right-click the request in the Network log > select **Copy as cURL (bash)** or **Edit and Replay** (in Firefox).
6. Test Insecure Direct Object References (IDOR):
   - In the request URI, modify the resource identifier to a peer patient ID: `/api/v1/patients/902185/records`.
   - Maintain the `Authorization: Bearer <token_patient_01>` header.
7. Observe the HTTP response:
   - **PASS**: Server responds with `403 Forbidden` or `404 Not Found` with a sanitized JSON payload:
     `{"status": "error", "code": "AUTH_FORBIDDEN", "message": "Access denied"}`.
   - **FAIL (Vulnerability)**: Server returns `200 OK` with User B's clinical diagnostic data or ePHI.
8. Test Missing Function-Level Access Control (Vertical Privilege Escalation):
   - Modify the request path to administrative routes: `/api/v1/admin/users` or `/api/v1/clinical/audit-trail`.
   - Verify that the API gateway enforces role-based access control (RBAC) and immediately rejects the patient token.

---

### 2.2 A02:2021 — Cryptographic Failures & Session Transmission Security
**Target Endpoints:** `https://portal.healthtechconnect.io/*` and `https://api.healthtechconnect.io/*`

#### Step-by-Step Audit Procedure:
1. Open the **Security** tab in Chrome DevTools:
   - Confirm the certificate hierarchy is valid and issued by a recognized CA.
   - Verify connection protocol is **TLS 1.3** or **TLS 1.2** with strong cipher suites (e.g., `TLS_AES_256_GCM_SHA384`).
   - Check the **Overview** panel to verify that **Mixed Content** is blocked (zero passive/active resources loaded over unencrypted HTTP).
2. Open the **Application** tab > select **Cookies** (`https://portal.healthtechconnect.io`):
   - Inspect every authentication and session identifier cookie (`htc_auth`, `session_id`):
     - **`HttpOnly`**: Must be checked (boolean `true`). Prevents client scripts from stealing tokens via `document.cookie`.
     - **`Secure`**: Must be checked (boolean `true`). Enforces transmission strictly over HTTPS.
     - **`SameSite`**: Must be set to `Lax` or `Strict` to mitigate cross-site request forgery.
3. Open the **Network** tab > Inspect HTTP Response Headers of sensitive endpoints:
   - Verify `Cache-Control: no-store, no-cache, must-revalidate, private` is enforced on all endpoints returning ePHI, ensuring browser disk caches do not persist medical records.

---

### 2.3 A03:2021 — Injection (DOM-Based XSS & Client-Side Sink Analysis)
**Target Endpoints:** `https://portal.healthtechconnect.io/telehealth/portal?view=records`

#### Step-by-Step Audit Procedure:
1. Open the **Console** tab and execute runtime probe to inspect DOM manipulation behavior.
2. In the **Sources** tab, open **DOM Breakpoints** or use the **Global Search** (`Ctrl+Shift+F`) to search the frontend codebase for dangerous JavaScript sinks:
   - Dangerous sinks: `innerHTML`, `outerHTML`, `document.write`, `eval()`, `dangerouslySetInnerHTML` (React).
   - Insecure sources: `location.search`, `location.hash`, `window.name`, `document.referrer`.
3. Input harmless, non-destructive boundary test strings in URL parameters:
   - Probe string: `htc_test_param'"><div id="audit_marker">`
4. Inspect the **Elements** panel:
   - Verify whether the boundary characters (`<`, `>`, `"`, `'`) are properly HTML entity-encoded (`&lt;`, `&gt;`, `&quot;`, `&#39;`) or if arbitrary DOM nodes are injected.
   - **PASS**: The browser renders the string as literal text inside safe elements (`innerText` or text nodes).
   - **FAIL**: Custom DOM elements render unencoded into the document tree.

---

### 2.4 A04:2021 — Insecure Design (Client-Side Business Logic & Validation Bypass)
**Target Endpoints:** `https://portal.healthtechconnect.io/appointment/book`

#### Objective:
Verify whether validation rules (e.g., appointment dates, copay amounts, medical license numbers) are enforced strictly on the server or bypassed via client manipulation.

#### Step-by-Step Audit Procedure:
1. Navigate to the appointment booking form.
2. Open the **Elements** tab:
   - Locate disabled buttons, hidden inputs, or fields with `readonly`, `disabled`, or `max="50"`.
   - Modify or delete HTML attributes (e.g., remove `disabled="true"` on the submission button or alter a hidden `copay_amount` input value from `50.00` to `0.00`).
3. In the **Network** tab, trigger the submission and inspect the outgoing payload:
   - Check if the API accepts modified numerical rates or invalid dates without server-side validation.
   - **PASS**: Server returns `422 Unprocessable Entity` or `400 Bad Request` with schema validation error.
   - **FAIL**: Server records the appointment with a modified copay of `$0.00`.

---

### 2.5 A05:2021 — Security Misconfiguration (Sourcemaps & Header Verification)
**Target Endpoints:** `https://portal.healthtechconnect.io/assets/*`

#### Step-by-Step Audit Procedure:
1. Open DevTools > navigate to the **Sources** tab.
2. Expand the left-hand navigation tree under `Page` / `top`:
   - Inspect whether a `webpack://` or `src/` tree appears containing TypeScript/React source files (`.ts`, `.tsx`, `.vue`).
   - If present, unminified source code is being exposed via publicly hosted `.map` files.
3. Open the **Network** tab > filter by `.map`:
   - Request: `GET /assets/index-D7b3qL1a.js.map`
   - If response status is `200 OK`, log as **Security Misconfiguration (Finding HTC-SEC-007)**.
4. Select the primary HTML document request > inspect **Headers** panel:
   - Verify presence of mandatory security headers (`Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options: nosniff`).

---

### 2.6 A07:2021 — Identification & Authentication Failures (Session Life-Cycle)
**Target Endpoints:** `https://api.healthtechconnect.io/v1/auth/refresh`

#### Step-by-Step Audit Procedure:
1. Log into the portal and capture the active session Bearer token from the Network tab.
2. Click **"Log Out"**:
   - Verify that the client sends a `POST /v1/auth/logout` invalidation request.
3. Use DevTools to replay the previous authenticated request (`GET /v1/patients/me/profile`) using the logged-out token:
   - **PASS**: Server responds with `401 Unauthorized` (Token revoked on server-side blacklist/Redis store).
   - **FAIL**: Server responds with `200 OK` (Stateless token remains valid until expiration, failing HIPAA automatic logoff requirement 45 CFR § 164.312(a)(2)(iii)).
4. Verify Idle Session Timeout:
   - Leave the application inactive for 15 minutes (HIPAA guideline threshold).
   - Confirm that the UI locks, redirects to login, and destroys in-memory credentials.

---

### 2.7 A08:2021 — Software & Data Integrity Failures (Subresource Integrity - SRI)
**Target Endpoints:** External scripts and CDNs loaded on the portal.

#### Step-by-Step Audit Procedure:
1. In DevTools, open the **Elements** panel or search the initial HTML response in the **Network** tab.
2. Locate all `<script>` and `<link>` elements pointing to external Content Delivery Networks (e.g., Google Fonts, CDNJS, video chat SDKs).
3. Verify presence of the `integrity` and `crossorigin` attributes:
   ```html
   <!-- COMPLIANT IMPLEMENTATION -->
   <script 
     src="https://cdnjs.cloudflare.com/ajax/libs/webrtc-adapter/8.2.3/adapter.min.js" 
     integrity="sha384-abc1234..." 
     crossorigin="anonymous">
   </script>
   ```
4. If an external asset is loaded without an `integrity` cryptographic hash, record an integrity finding: if the CDN is compromised, malicious code could be injected into the patient portal.

---

### 2.8 A09:2021 — Security Logging & Monitoring Failures
**Target Endpoints:** `https://api.healthtechconnect.io/v1/auth/login`

#### Step-by-Step Audit Procedure:
1. Attempt 5 consecutive failed login requests with invalid passwords in the UI.
2. Inspect the **Network** tab responses:
   - Verify whether rate-limiting (`429 Too Many Requests`) is triggered.
   - Inspect response headers for `Retry-After` or `X-RateLimit-Remaining`.
3. In the **Console** tab, verify that detailed server connection strings, database error codes, or unhandled promise rejections are **not** printed to the client console.
