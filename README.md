# Vulnerable MERN E-Commerce Application

⚠️ **CRITICAL WARNING: This application contains INTENTIONAL CRITICAL security vulnerabilities for SAST testing purposes ONLY.**

## ⚠️ DO NOT USE IN PRODUCTION ⚠️

**This code is DELIBERATELY INSECURE and should NEVER be:**
- Deployed to production environments
- Exposed to the internet
- Used with real user data
- Used with real credentials or payment information
- Installed on systems with sensitive data

## About

This is a full-stack MERN (MongoDB, Express, React, Node.js) e-commerce application designed specifically for testing Static Application Security Testing (SAST) tools, Dynamic Application Security Testing (DAST) tools, and security training.

**Purpose:**
- Validate SAST/DAST tool effectiveness
- Security training and education
- Penetration testing practice
- Secure coding demonstrations
- AppScan and other security tool testing

## 📊 Vulnerability Statistics

**Total Vulnerabilities:** 45+ distinct types
- **CRITICAL:** 5 (RCE, Command Injection, Hardcoded Secrets)
- **HIGH:** 10 (SQLi, NoSQL Injection, XXE, SSRF, etc.)
- **MEDIUM:** 20+ (XSS, IDOR, Session issues, etc.)
- **LOW:** 10+ (Info disclosure, weak validation, etc.)

**OWASP Top 10 Coverage:** 10/10 categories

See [SECURITY_VULNERABILITIES.md](SECURITY_VULNERABILITIES.md) for complete vulnerability catalog.

## ⚠️ Critical Security Vulnerabilities Included

### 🔴 CRITICAL Severity

#### 1. Remote Code Execution (RCE)
- **Location:** `server/server.js`, `server/routes/admin.js`, `client/src/App.js`
- **Issue:** eval() and vm.runInNewContext() with user input
- **CVSS:** 10.0

#### 2. Command Injection
- **Location:** `server/server.js`, `server/routes/products.js`, `server/routes/admin.js`
- **Issue:** exec() with unsanitized user input
- **CVSS:** 9.8

#### 3. Hardcoded Credentials & API Keys
- **Locations:** Throughout codebase
- **Examples:**
  - Database: `mongodb://admin:password123@localhost:27017`
  - JWT: `hardcoded_jwt_secret`
  - AWS: `AKIAIOSFODNN7EXAMPLE` (FAKE)
  - Stripe: `sk_live_51KfakeKEY...` (FAKE)
  - Backdoor: `username:backdoor, password:admin123!`
- **CVSS:** 9.8
- **Note:** All credentials are FAKE for testing only

#### 4. Insecure Deserialization
- **Location:** `server/server.js`
- **Issue:** node-serialize.unserialize() without validation
- **CVSS:** 9.8

#### 5. Prototype Pollution
- **Location:** `server/server.js`
- **Issue:** Unsafe recursive object merge
- **CVSS:** 8.6

### 🟠 HIGH Severity

#### 6. NoSQL Injection
- **Locations:** `server/routes/users.js`, `server/routes/products.js`, `server/routes/admin.js`
- **Examples:**
  ```javascript
  { username: { "$ne": null }, password: { "$ne": null } }
  ```
- **CVSS:** 8.1

#### 7. SQL Injection (Pattern)
- **Location:** `server/utils/validator.js`, `server/config/database.js`
- **Issue:** String concatenation in queries
- **CVSS:** 8.1

#### 8. LDAP Injection
- **Location:** `server/server.js`, `server/utils/validator.js`
- **Issue:** Unescaped LDAP filter construction
- **CVSS:** 7.5

#### 9. XXE (XML External Entity)
- **Location:** `server/server.js`
- **Issue:** libxmljs with `noent:true`, `dtdload:true`
- **CVSS:** 8.8

#### 10. Path Traversal
- **Locations:** Multiple files
- **Examples:**
  - `/download?file=../../../../etc/passwd`
  - `/image/../../config/database.js`
- **CVSS:** 7.5

#### 11. Unrestricted File Upload
- **Location:** `server/server.js`, `server/routes/admin.js`
- **Risk:** Malware upload, webshell deployment, RCE
- **CVSS:** 8.8

#### 12. SSRF (Server-Side Request Forgery)
- **Location:** `server/routes/products.js`
- **Risk:** Access to cloud metadata, internal services
- **CVSS:** 8.3

#### 13. Broken Authentication
- **Locations:** `server/middleware/auth.js`, `server/routes/users.js`
- **Issues:**
  - No token validation
  - JWT with 'none' algorithm
  - Plaintext password storage
  - No authentication on admin endpoints
- **CVSS:** 9.1

#### 14. Weak Cryptography
- **Location:** `server/utils/auth.js`
- **Issues:**
  - MD5 password hashing
  - No salt in hashing
  - DES encryption (deprecated)
  - 3-byte reset tokens
- **CVSS:** 7.4

#### 15. IDOR (Insecure Direct Object Reference)
- **Locations:** `server/routes/users.js`, `server/routes/orders.js`
- **Issue:** Access any user profile/order without authorization
- **CVSS:** 7.5

### 🟡 MEDIUM Severity

#### 16. XSS (Cross-Site Scripting)
- **Types:** Stored, Reflected, DOM-based
- **Locations:** `client/src/App.js`, `server/routes/products.js`
- **Issues:**
  - dangerouslySetInnerHTML
  - innerHTML with user input
  - No HTML sanitization
- **CVSS:** 6.1

#### 17. Open Redirect
- **Locations:** `client/src/App.js`, `server/routes/admin.js`
- **CVSS:** 6.1

#### 18. Session Fixation
- **Location:** `server/routes/users.js`
- **Issues:**
  - Accepting user-provided session ID
  - Insecure cookie settings (httpOnly:false, secure:false)
- **CVSS:** 6.5

#### 19. Mass Assignment
- **Locations:** Multiple route files
- **Issue:** No field filtering on req.body
- **CVSS:** 6.5

#### 20. Price Manipulation
- **Location:** `server/routes/orders.js`
- **Issue:** Client controls price, discount, totalAmount
- **CVSS:** 7.3

#### 21. Race Conditions
- **Locations:** `server/routes/orders.js`, `server/routes/users.js`
- **Issues:** Non-atomic inventory updates, fund transfers
- **CVSS:** 5.9

#### 22-30. Additional Vulnerabilities
- Integer Overflow
- Timing Attacks
- Information Disclosure
- Business Logic Flaws
- ReDoS (Regular Expression DoS)
- Insecure Randomness
- CSRF (No Protection)
- CORS Misconfiguration
- postMessage Vulnerabilities

### Additional Security Issues
- **PCI DSS Violations:** Storing CVV, full card numbers
- **GDPR/Privacy Violations:** Exposing SSN, email, PII
- **Missing Security Headers:** No CSP, X-Frame-Options, etc.
- **No Rate Limiting:** All endpoints vulnerable to brute force
- **Privilege Escalation:** Anyone can become admin
- **Memory Leaks:** Intentional memory exhaustion
- **DoS Vulnerabilities:** CPU exhaustion endpoints

## Backend Vulnerabilities
- **Hardcoded Credentials**: Passwords, API keys, and secrets in source code
- **SQL/NoSQL Injection**: Unvalidated user input in database queries
- **Command Injection**: Unsanitized input in system commands
- **Path Traversal**: File access without proper validation
- **XXE (XML External Entity)**: Insecure XML parsing
- **Insecure File Upload**: No file type or size validation
- **IDOR (Insecure Direct Object Reference)**: Missing authorization checks
- **Mass Assignment**: Unfiltered object updates
- **Weak Cryptography**: Use of deprecated algorithms (MD5, DES)
- **Information Disclosure**: Exposing stack traces and sensitive data
- **Insecure Deserialization**: Unsafe data handling
- **SSRF (Server-Side Request Forgery)**: Unvalidated URL requests
- **Race Conditions**: Concurrent operation issues
- **Prototype Pollution**: Unsafe object merging
- **ReDoS**: Vulnerable regular expressions
- **Logging Sensitive Data**: Passwords and PII in logs

### Frontend Vulnerabilities
- **XSS (Cross-Site Scripting)**: Unescaped user input
- **eval() Usage**: Dynamic code execution
- **DOM-based XSS**: Dangerous DOM manipulation
- **Sensitive Data Exposure**: Credentials in localStorage
- **Open Redirect**: Unvalidated redirects
- **Insecure Random**: Weak random number generation
- **Missing CSRF Protection**: No anti-CSRF tokens
- **Hardcoded API Keys**: Secrets in client code

### Dependency Vulnerabilities
All packages are intentionally outdated with known CVEs:
- Express 4.16.0 (vulnerable)
- Mongoose 5.5.0 (vulnerable)
- Lodash 4.17.11 (prototype pollution)
- jQuery 3.3.1 (XSS vulnerabilities)
- Handlebars 4.0.11 (RCE vulnerabilities)
- And many more...

## Installation

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Start production server
npm start
```

## Default Credentials

⚠️ **These are hardcoded in the application:**

- **Database**: `mongodb://admin:password123@localhost:27017/ecommerce`
- **Admin User**: username: `admin`, password: `admin`
- **JWT Secret**: `hardcoded_jwt_secret`
- **API Keys**: See `.env` file

## API Endpoints

### Users
- `POST /api/users/register` - User registration (no validation)
- `POST /api/users/login` - Login (vulnerable to NoSQL injection)
- `GET /api/users/:id` - Get user (IDOR vulnerability)
- `PUT /api/users/:id` - Update user (mass assignment)

### Products
- `GET /api/products` - List all products
- `GET /api/products/search?q=` - Search (NoSQL injection)
- `POST /api/products` - Create product (no auth)
- `DELETE /api/products/:id` - Delete product (no auth)

### Orders
- `POST /api/orders` - Create order (price manipulation)
- `GET /api/orders/:id` - Get order (IDOR vulnerability)
- `POST /api/orders/process-payment` - Process payment (storing CVV)

### Vulnerable Endpoints
- `POST /api/ping` - Command injection
- `POST /api/calculate` - eval() vulnerability
- `GET /download?file=` - Path traversal
- `POST /api/upload` - Unrestricted file upload

## Known Issues for SAST Testing

1. ✗ 50+ outdated npm packages with known CVEs
2. ✗ Hardcoded secrets in 8+ files
3. ✗ No input validation or sanitization
4. ✗ No authentication/authorization on critical endpoints
5. ✗ Insecure cryptographic practices
6. ✗ Sensitive data exposure
7. ✗ Missing security headers
8. ✗ No HTTPS enforcement
9. ✗ Verbose error messages
10. ✗ No rate limiting
11. ✗ No CSRF protection
12. ✗ SQL/NoSQL injection vulnerabilities
13. ✗ XSS vulnerabilities
14. ✗ Command injection points
15. ✗ Path traversal vulnerabilities

## DO NOT USE IN PRODUCTION

This application should **NEVER** be deployed in a production environment or exposed to the internet. It is designed solely for:

- SAST tool testing and validation
- Security training
- Vulnerability scanning demonstrations
- DevSecOps pipeline testing

## License

ISC - For testing purposes only
