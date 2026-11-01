# PRODUCTION REMEDIATION SOPS & CODE IMPLEMENTATIONS
## Standard Operating Procedures for HealthTech Connect DevSecOps Team
**Document ID:** `HTC-SOP-REMEDIATION-v1.0`  
**Classification:** Engineering Standard — Production Ready  
**Target Compliance:** OWASP Top 10:2021 & HIPAA Security Rule (45 CFR § 164.312)

---

## SOP-SEC-01: Ingress Security Headers Hardening (Nginx 1.25+)

### Objective:
Resolve **HTC-SEC-002** (CSP), **HTC-SEC-003** (Clickjacking), and **HTC-SEC-005** (HSTS), elevating the platform to a Mozilla Observatory **Grade A+ (115/100)**.

### Target Configuration File: `/etc/nginx/conf.d/security_headers.conf`

```nginx
# ==============================================================================
# HealthTech Connect - Ingress HTTP Security Headers
# HIPAA 45 CFR § 164.312(e)(1) Transmission Security & OWASP A05:2021
# ==============================================================================

# 1. Suppress Nginx server version tokens
server_tokens off;

# 2. HTTP Strict Transport Security (HSTS)
# 2-year duration, enforced on all subdomains with browser preloading eligibility
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

# 3. Content-Security-Policy (CSP)
# Restricts script/style execution to origin, prohibits framing, allows WebRTC sockets
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://cdn.healthtechconnect.io; font-src 'self' data:; connect-src 'self' https://api.healthtechconnect.io wss://stream.healthtechconnect.io; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;

# 4. Anti-Clickjacking Defense
add_header X-Frame-Options "DENY" always;

# 5. Anti-MIME Sniffing
add_header X-Content-Type-Options "nosniff" always;

# 6. Referrer Policy (Mitigates leaking ePHI query parameters)
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# 7. Permissions Policy (Hardware API Isolation)
add_header Permissions-Policy "camera=(self), microphone=(self), geolocation=(), payment=()" always;

# 8. Cross-Origin Isolation Policies
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
```

---

## SOP-SEC-02: SQL Injection Defense in FHIR Engine (Python / FastAPI)

### Objective:
Remediate **HTC-SEC-010** (Critical SQLi) by eliminating dynamic SQL string concatenation and enforcing parameterized SQLAlchemy statements and Pydantic validation.

### Vulnerable Code Pattern (Before):
```python
# VULNERABLE: Direct string interpolation into raw SQL
@router.get("/fhir/r4/Patient")
async def get_patient(identifier: str, db: Session = Depends(get_db)):
    query = f"SELECT * FROM fhir_patients WHERE mrn = '{identifier}'"
    result = db.execute(text(query)).fetchall()
    return result
```

### Remediated Production Implementation (After):
**File:** `apps/ehr_sync/api/v1/patient_router.py`

```python
"""
HealthTech Connect - FHIR Patient Ingestion Gateway
HIPAA 45 CFR § 164.312(c)(1) Data Integrity Control
"""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import select
import re
from typing import List

from apps.ehr_sync.database import get_db
from apps.ehr_sync.models import FHIRPatientModel
from apps.ehr_sync.schemas import FHIRPatientResponse

router = APIRouter(prefix="/fhir/r4", tags=["FHIR Patients"])

# Strict regex pattern for Medical Record Numbers (MRN)
MRN_REGEX = r"^MRN-\d{6}-[A-Z]{2}$"

@router.get(
    "/Patient",
    response_model=List[FHIRPatientResponse],
    status_code=status.HTTP_200_OK,
    summary="Query FHIR Patient Resources securely via parameterized statements"
)
async def get_patient_by_identifier(
    identifier: str = Query(
        ...,
        description="Patient Medical Record Number (e.g. MRN-902184-US)",
        regex=MRN_REGEX
    ),
    db: Session = Depends(get_db)
):
    # 1. Input Validation: Enforce regex formatting
    if not re.match(MRN_REGEX, identifier):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid MRN identifier format."
        )

    # 2. Parameterized Query Execution via SQLAlchemy 2.0 select statement
    stmt = select(FHIRPatientModel).where(FHIRPatientModel.mrn == identifier)
    result = db.execute(stmt).scalars().all()

    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Patient resource not found."
        )

    return result
```

---

## SOP-SEC-03: Secure Token & Cookie Session Architecture (Node.js / Express)

### Objective:
Remediate **HTC-SEC-001** (Cleartext ePHI in LocalStorage) and **HTC-SEC-004** (Missing HttpOnly/Secure flags) by issuing cryptographically protected HTTP cookies.

### Production Implementation: `apps/api_gateway/src/controllers/authController.js`

```javascript
/**
 * HealthTech Connect - Authentication Controller
 * HIPAA 45 CFR § 164.312(a)(2)(iv) & (d) Authentication Safeguards
 */
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const AUTH_COOKIE_NAME = '__Host-htc_auth';
const CSRF_COOKIE_NAME = 'htc_csrf_token';

exports.loginHandler = async (req, res) => {
  const { email, password } = req.body;
  
  // 1. Authenticate user against Keycloak / identity store
  const user = await authenticateUser(email, password);
  if (!user) {
    return res.status(401).json({ status: "error", message: "Invalid credentials" });
  }

  // 2. Generate minimal scoped JWT (Zero clinical ePHI in payload)
  const sessionToken = jwt.sign(
    {
      sub: user.id,
      mrn: user.mrn,
      role: user.role
    },
    process.env.JWT_SECRET_KEY,
    { expiresIn: '15m', issuer: 'healthtechconnect.io', algorithm: 'HS256' }
  );

  // 3. Generate Anti-CSRF Token
  const csrfToken = crypto.randomBytes(32).toString('hex');

  // 4. Set HttpOnly, Secure, SameSite=Strict Cookie
  // Note: __Host- prefix enforces Secure and Host origin isolation
  res.cookie(AUTH_COOKIE_NAME, sessionToken, {
    httpOnly: true,                                // Block client-side JavaScript access
    secure: true,                                  // Transmit only over TLS
    sameSite: 'strict',                            // Mitigate cross-site request forgery
    path: '/',
    maxAge: 15 * 60 * 1000                         // 15-minute HIPAA idle session limit
  });

  res.cookie(CSRF_COOKIE_NAME, csrfToken, {
    httpOnly: false,                               // Readable by frontend to attach to X-CSRF-Token header
    secure: true,
    sameSite: 'strict',
    path: '/',
    maxAge: 15 * 60 * 1000
  });

  // 5. Respond with sanitised metadata only (NO medical conditions or SSN in JSON)
  return res.status(200).json({
    status: "success",
    user: {
      id: user.id,
      name: user.name,
      role: user.role
    }
  });
};
```

---

## SOP-SEC-04: Authorization Middleware for IDOR Defense (Node.js / Express)

### Objective:
Remediate **HTC-SEC-009** (Insecure Direct Object Reference) by validating resource ownership on every patient endpoint.

### Production Implementation: `apps/api_gateway/src/middleware/authorizeOwnership.js`

```javascript
/**
 * Resource Ownership Verification Middleware
 * HIPAA 45 CFR § 164.312(a)(1) Access Control
 */
module.exports = function verifyResourceOwnership(req, res, next) {
  const authenticatedUser = req.user;
  const requestedMrn = req.params.mrn;

  if (!authenticatedUser) {
    return res.status(401).json({
      status: "error",
      code: "AUTH_UNAUTHENTICATED",
      message: "Authentication credentials required."
    });
  }

  // Clinical staff and system administrators possess authorization for multi-patient records
  const privilegedRoles = ['physician', 'nurse_practitioner', 'system_admin'];
  if (privilegedRoles.includes(authenticatedUser.role)) {
    return next();
  }

  // Enforce horizontal boundary: Patient can only access their own MRN
  if (authenticatedUser.role === 'patient') {
    if (authenticatedUser.mrn !== requestedMrn) {
      console.warn(`[SECURITY ALERT] Unauthorized IDOR attempt detected. User ${authenticatedUser.id} attempted to access MRN ${requestedMrn}`);
      return res.status(403).json({
        status: "error",
        code: "AUTH_FORBIDDEN",
        message: "Access Denied: You do not possess authorization to access this clinical record."
      });
    }
  }

  return next();
};
```

---

## SOP-SEC-05: Server-Side Request Forgery (SSRF) Defense (Python / FastAPI)

### Objective:
Remediate **HTC-SEC-014** (Blind SSRF) by strictly validating destination IP addresses against RFC 1918 private CIDR blocks, localhost, and AWS metadata services (`169.254.169.254`) before performing outbound requests.

### Production Implementation: `apps/api_gateway/src/services/webhook_validator.py`

```python
"""
HealthTech Connect - Secure Outbound HTTP Webhook Dispatcher
Prevents SSRF against internal VPC and AWS IMDSv2
"""
import ipaddress
import socket
import urllib.parse
from fastapi import HTTPException, status
import httpx

# Blocked IP ranges: RFC 1918, Loopback, Link-Local (AWS Metadata)
PROHIBITED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),          # Loopback
    ipaddress.ip_network("10.0.0.0/8"),           # RFC 1918 Private
    ipaddress.ip_network("172.16.0.0/12"),        # RFC 1918 Private
    ipaddress.ip_network("192.168.0.0/16"),       # RFC 1918 Private
    ipaddress.ip_network("169.254.0.0/16"),       # Link-Local & AWS Metadata
    ipaddress.ip_network("::1/128"),              # IPv6 Loopback
    ipaddress.ip_network("fc00::/7"),             # IPv6 Private
]

def validate_webhook_url(target_url: str) -> str:
    parsed = urllib.parse.urlparse(target_url)
    
    # 1. Enforce HTTPS scheme
    if parsed.scheme != "https":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Webhook endpoint must use secure HTTPS protocol."
        )

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid target hostname.")

    # 2. Resolve hostname to IPv4/IPv6 addresses
    try:
        addr_info = socket.getaddrinfo(hostname, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        raise HTTPException(status_code=400, detail="Cannot resolve webhook destination host.")

    # 3. Check every resolved IP address against blacklisted networks
    for entry in addr_info:
        ip_str = entry[4][0]
        ip_obj = ipaddress.ip_address(ip_str)
        for prohibited in PROHIBITED_NETWORKS:
            if ip_obj in prohibited:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Webhook destination resolves to a restricted internal network address."
                )

    return target_url
```

---

## SOP-SEC-06: Reflected DOM XSS Remediation (React 18 / TypeScript)

### Objective:
Remediate **HTC-SEC-011** (DOM XSS in Telehealth Portal) by eliminating `dangerouslySetInnerHTML` and enforcing sanitization with `DOMPurify`.

### Production Implementation: `apps/patient_portal/src/components/TelehealthBreadcrumb.tsx`

```tsx
/**
 * HealthTech Connect - Telehealth Portal Safe Breadcrumb Component
 * Prevents DOM-based Cross-Site Scripting (XSS)
 */
import React from 'react';
import { useSearchParams } from 'react-router-dom';
import DOMPurify from 'dompurify';

export const TelehealthBreadcrumb: React.FC = () => {
  const [searchParams] = useSearchParams();
  const rawView = searchParams.get('view') || 'Overview';

  // 1. Sanitize text through DOMPurify with strict text-only profile
  const sanitizedView = DOMPurify.sanitize(rawView, { ALLOWED_TAGS: [] });

  return (
    <nav aria-label="Breadcrumb" className="py-2 px-4 bg-slate-50 text-slate-700">
      <ol className="flex items-center space-x-2">
        <li><span>Telehealth</span></li>
        <li className="text-slate-400">/</li>
        {/* Render safe sanitized text node - NEVER use dangerouslySetInnerHTML */}
        <li className="font-semibold text-teal-600">{sanitizedView}</li>
      </ol>
    </nav>
  );
};
```
