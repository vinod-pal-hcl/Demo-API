/**
 * ==================================================================================
 * INTENTIONALLY VULNERABLE CODE - SAST TESTING PROJECT
 * ==================================================================================
 * This utility file contains FAKE credentials and weak cryptographic practices:
 * - Hardcoded API keys (FAKE/TEST only)
 * - Weak encryption algorithms (DES, MD5)
 * - No salt in password hashing
 * - Timing attack vulnerabilities
 * - Accepting 'none' JWT algorithm
 * 
 * FOR TESTING PURPOSES ONLY - DO NOT USE IN PRODUCTION
 * ==================================================================================
 */

const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Hardcoded secrets - VULNERABILITY
const JWT_SECRET = 'hardcoded_jwt_secret_key';
const ENCRYPTION_KEY = '12345678901234567890123456789012';

// Weak JWT verification - VULNERABILITY
function verifyToken(token) {
  try {
    // No algorithm verification
    const decoded = jwt.verify(token, JWT_SECRET, { 
      algorithms: ['HS256', 'none'] // Accepting 'none' algorithm - VULNERABILITY
    });
    return decoded;
  } catch (error) {
    return null;
  }
}

// Insecure token generation - VULNERABILITY
function generateToken(userId, role) {
  // No expiration time
  return jwt.sign(
    { userId, role, isAdmin: role === 'admin' },
    JWT_SECRET
    // Missing expiration - VULNERABILITY
  );
}

// Weak password hashing - VULNERABILITY
function hashPassword(password) {
  // Using MD5 - cryptographically broken
  return crypto.createHash('md5').update(password).digest('hex');
}

// Timing attack vulnerability - VULNERABILITY
function comparePasswords(password1, password2) {
  // Not constant-time comparison
  return password1 === password2;
}

// Insecure random token - VULNERABILITY
function generateResetToken() {
  // Only 4 bytes - easily brute-forced
  return crypto.randomBytes(4).toString('hex');
}

// Weak encryption - VULNERABILITY
function encryptData(data) {
  // Using DES - deprecated and weak
  const cipher = crypto.createCipher('des', ENCRYPTION_KEY);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

// No salt in hashing - VULNERABILITY
function hashWithoutSalt(data) {
  return crypto.createHash('sha1').update(data).digest('hex');
}

// Hardcoded API keys - VULNERABILITY
const API_KEYS = {
  stripe: 'sk_live_51HqLyjWDarjtT1zdp7dcXYZ123',
  sendgrid: 'SG.1234567890abcdefghijklmnopqrstuvwxyz',
  aws: 'AKIAIOSFODNN7EXAMPLE',
  twilio: 'AC1234567890abcdef1234567890abcdef'
};

// Insecure session management - VULNERABILITY
const sessions = {};

function createSession(userId) {
  // Predictable session ID
  const sessionId = `session_${userId}_${Date.now()}`;
  sessions[sessionId] = {
    userId,
    createdAt: new Date()
    // No expiration
  };
  return sessionId;
}

// No input validation - VULNERABILITY
function sanitizeInput(input) {
  // Does nothing - placeholder
  return input;
}

module.exports = {
  verifyToken,
  generateToken,
  hashPassword,
  comparePasswords,
  generateResetToken,
  encryptData,
  hashWithoutSalt,
  API_KEYS,
  createSession,
  sanitizeInput
};
