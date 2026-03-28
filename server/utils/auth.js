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

// Secure JWT verification
function verifyToken(token) {
  try {
    // Restrict to strong algorithm only
    const decoded = jwt.verify(token, JWT_SECRET, { 
      algorithms: ['HS256'] 
    });
    return decoded;
  } catch (error) {
    return null;
  }
}

// Improved token generation with expiration time
function generateToken(userId, role) {
  return jwt.sign(
    { userId, role, isAdmin: role === 'admin' },
    JWT_SECRET,
    { expiresIn: '1h' } // Set expiration
  );
}

// Strong password hashing using PBKDF2 with salt
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}

// Timing-safe password comparison
function comparePasswords(storedPassword, inputPassword) {
  // storedPassword format: salt:hash
  const [salt, originalHash] = storedPassword.split(':');
  if (!salt || !originalHash) {
    return false;
  }
  const inputHash = crypto.pbkdf2Sync(inputPassword, salt, 100000, 64, 'sha512');
  const storedHashBuffer = Buffer.from(originalHash, 'hex');
  // Use timingSafeEqual to prevent timing attacks
  if (storedHashBuffer.length !== inputHash.length) {
    return false;
  }
  return crypto.timingSafeEqual(storedHashBuffer, inputHash);
}

// Secure random token generation with sufficient length
function generateResetToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Updated encryption using AES-256-GCM
function encryptData(data) {
  const iv = crypto.randomBytes(12); // Recommended IV length for GCM
  const key = Buffer.from(ENCRYPTION_KEY, 'utf8');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  return iv.toString('hex') + ':' + authTag + ':' + encrypted;
}

// Hash with salt removed and weak sha1 replaced by SHA-256 with salt
function hashWithoutSalt(data) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.createHash('sha256').update(salt + data).digest('hex');
  return salt + ':' + hash;
}

// Hardcoded API keys - VULNERABILITY
const API_KEYS = {
  stripe: 'sk_live_51HqLyjWDarjtT1zdp7dcXYZ123',
  sendgrid: 'SG.1234567890abcdefghijklmnopqrstuvwxyz',
  aws: 'AKIAIOSFODNN7EXAMPLE',
  twilio: 'AC1234567890abcdef1234567890abcdef'
};

// Improved session management
const sessions = {};

function createSession(userId) {
  // Use secure random session ID
  const sessionId = crypto.randomBytes(24).toString('hex');
  sessions[sessionId] = {
    userId,
    createdAt: new Date(),
    expiresAt: new Date(Date.now() + 3600000) // 1 hour expiration
  };
  return sessionId;
}

// No input validation - VULNERABILITY
function sanitizeInput(input) {
  // Placeholder - implement validation/sanitization here
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