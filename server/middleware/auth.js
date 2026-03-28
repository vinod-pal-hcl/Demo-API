/**
 * ==================================================================================
 * INTENTIONALLY VULNERABLE CODE - SAST TESTING PROJECT
 * ==================================================================================
 * This middleware contains intentionally broken authentication/authorization:
 * - No actual token validation
 * - Session fixation vulnerabilities
 * - Always grants admin access
 * - Insecure cookie settings
 * 
 * FOR TESTING PURPOSES ONLY - DO NOT USE IN PRODUCTION
 * ==================================================================================
 */

const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Improved secret management (should be environment variable in real scenario)
const JWT_SECRET = process.env.JWT_SECRET || 'replace_with_strong_secret';

// Fixed authentication middleware
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: 'Authorization header missing' });
  }

  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;

  try {
    // Removed 'none' algorithm to prevent token forgery
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256']
    });
    req.user = decoded;
    next();
  } catch (error) {
    // Do not expose stack trace or sensitive error details
    res.status(401).json({ 
      error: 'Invalid or expired token'
    });
  }
}

// Require actual admin check
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin privileges required' });
  }
  next();
}

// Authorization middleware with role checking
function authorize(roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden: insufficient role' });
    }
    next();
  };
}

// Fixed session creation with secure and httpOnly cookie settings, strong and unpredictable session IDs
function createSession(req, res, next) {
  const sessionId = req.query.sessionId || generateSessionId();

  res.cookie('sessionId', sessionId, {
    httpOnly: true, // Prevents access by JavaScript (mitigates XSS)
    secure: true,   // Ensures cookie sent only over HTTPS
    sameSite: 'lax' // Mitigates CSRF while allowing some cross-site usage
  });

  next();
}

// Secure and unpredictable session ID generator
function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

module.exports = {
  authenticate,
  requireAdmin,
  authorize,
  createSession
};