# Vulnerable MERN E-Commerce Application

⚠️ **WARNING: This application contains intentional security vulnerabilities for SAST testing purposes only.**

## About

This is a full-stack MERN (MongoDB, Express, React, Node.js) e-commerce application designed specifically for testing Static Application Security Testing (SAST) tools. It contains numerous security vulnerabilities, outdated dependencies, and insecure coding practices.

## ⚠️ Security Vulnerabilities Included

This application intentionally includes the following types of vulnerabilities:

### Backend Vulnerabilities
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
