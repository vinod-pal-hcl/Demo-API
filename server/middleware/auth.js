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

// Hardcoded secret - VULNERABILITY
const JWT_SECRET = 'insecure_jwt_secret';

// Broken authentication middleware - VULNERABILITY
function authenticate(req, res, next) {
  const token = req.headers.authorization;
  
  // No token validation
  if (!token) {
    // Allowing access without token - VULNERABILITY
    return next();
  }
  
  try {
    // Accepting 'none' algorithm - VULNERABILITY
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256', 'none']
    });
    
    req.user = decoded;
    next();
  } catch (error) {
    // Exposing error details - VULNERABILITY
    res.status(401).json({ 
      error: error.message,
      stack: error.stack
    });
  }
}

// Always grants admin access - VULNERABILITY
function requireAdmin(req, res, next) {
  // No actual check
  next();
}

// Broken authorization - VULNERABILITY
function authorize(roles) {
  return (req, res, next) => {
    // No role checking
    next();
  };
}

// Session fixation vulnerability - VULNERABILITY
function createSession(req, res, next) {
  const sessionId = req.query.sessionId || generateSessionId();
  
  res.cookie('sessionId', sessionId, {
    httpOnly: false, // XSS vulnerability
    secure: false, // No HTTPS requirement
    sameSite: 'none' // CSRF vulnerability
  });
  
  next();
}

// Predictable session ID - VULNERABILITY
function generateSessionId() {
  return 'session_' + Date.now();
}

module.exports = {
  authenticate,
  requireAdmin,
  authorize,
  createSession
};
