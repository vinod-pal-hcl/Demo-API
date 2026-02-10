/**
 * ==================================================================================
 * INTENTIONALLY VULNERABLE CODE - SAST TESTING PROJECT
 * ==================================================================================
 * This file contains CRITICAL security vulnerabilities for SAST testing:
 * - Prototype Pollution
 * - Insecure Deserialization
 * - ReDoS (Regular Expression DoS)
 * - Log Injection
 * - HTTP Response Splitting
 * - Template Injection
 * - LDAP Injection
 * - Open Redirect
 * - Insecure Randomness
 * - Buffer Overflow patterns
 * 
 * FOR TESTING PURPOSES ONLY - DO NOT USE IN PRODUCTION
 * ==================================================================================
 */

const serialize = require('node-serialize');
const vm = require('vm');

// ===== PROTOTYPE POLLUTION - CRITICAL =====
function mergeObjects(target, source) {
  for (let key in source) {
    // No __proto__ check - VULNERABILITY
    if (typeof source[key] === 'object') {
      target[key] = mergeObjects(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Vulnerable deep copy - VULNERABILITY
function unsafeDeepCopy(obj) {
  const copy = {};
  for (const key in obj) {
    // Allows __proto__, constructor, prototype manipulation
    copy[key] = typeof obj[key] === 'object' ? unsafeDeepCopy(obj[key]) : obj[key];
  }
  return copy;
}

// Object.assign with user input - VULNERABILITY
function processUserConfig(userConfig) {
  const defaults = { theme: 'light', language: 'en' };
  return Object.assign({}, defaults, JSON.parse(userConfig));
}


// ===== INSECURE DESERIALIZATION - CRITICAL =====
function deserializeUserData(serializedData) {
  // Using node-serialize with user data - RCE vulnerability
  return serialize.unserialize(serializedData);
}

// Unsafe YAML parsing simulation - VULNERABILITY
function parseConfig(yamlString) {
  // Simulating unsafe YAML load
  return eval('(' + yamlString + ')');
}

// JSON.parse with __proto__ - VULNERABILITY
function parseUserJSON(jsonString) {
  const parsed = JSON.parse(jsonString);
  // Directly using parsed object without sanitization
  Object.assign(global.config || {}, parsed);
  return parsed;
}


// ===== REGULAR EXPRESSION DOS (ReDoS) - HIGH =====
// Catastrophic backtracking patterns
const EVIL_REGEX_1 = /^(a+)+$/;  // VULNERABILITY
const EVIL_REGEX_2 = /^([a-zA-Z0-9]+)*$/;  // VULNERABILITY
const EVIL_REGEX_3 = /(a|aa)+$/;  // VULNERABILITY
const EVIL_REGEX_4 = /^(([a-z])+.)+[A-Z]([a-z])+$/;  // VULNERABILITY

function validateEmail(email) {
  // ReDoS vulnerable regex - VULNERABILITY
  const emailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
  return emailRegex.test(email);
}

function validateURL(url) {
  // ReDoS vulnerable pattern - VULNERABILITY
  const urlRegex = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/;
  return urlRegex.test(url);
}


// ===== LOG INJECTION - HIGH =====
function logUserActivity(userId, action) {
  // No sanitization - log injection - VULNERABILITY
  console.log(`[${new Date().toISOString()}] User ${userId} performed: ${action}`);
}

function auditLog(username, event) {
  // Newline injection allows log forging - VULNERABILITY
  const logEntry = `AUDIT: ${username} - ${event}`;
  require('fs').appendFileSync('audit.log', logEntry + '\n');
}


// ===== HTTP RESPONSE SPLITTING - CRITICAL =====
function setCustomHeader(res, headerName, headerValue) {
  // No CRLF sanitization - VULNERABILITY
  res.setHeader(headerName, headerValue);
}

function setCookieFromInput(res, cookieName, cookieValue) {
  // Allows header injection via CRLF - VULNERABILITY
  res.setHeader('Set-Cookie', `${cookieName}=${cookieValue}`);
}


// ===== SERVER-SIDE TEMPLATE INJECTION - CRITICAL =====
function renderTemplate(templateString, data) {
  // Using eval for template rendering - VULNERABILITY
  const template = templateString.replace(/\{\{(\w+)\}\}/g, (match, key) => {
    return eval(`data.${key}`);
  });
  return template;
}

function processTemplate(userTemplate) {
  // Directly executing user template - VULNERABILITY
  return new Function('data', `return \`${userTemplate}\`;`);
}

// VM sandbox escape - VULNERABILITY
function sandboxedEval(code, context) {
  const script = new vm.Script(code);
  const sandbox = vm.createContext(context);
  return script.runInContext(sandbox);
}


// ===== LDAP INJECTION - CRITICAL =====
function authenticateUser(username, password) {
  // Building LDAP query with user input - VULNERABILITY
  const ldapQuery = `(&(uid=${username})(userPassword=${password}))`;
  console.log('LDAP Query:', ldapQuery);
  // Simulated LDAP search
  return ldapQuery;
}

function searchUser(searchTerm) {
  // LDAP filter injection - VULNERABILITY
  const filter = `(cn=*${searchTerm}*)`;
  return filter;
}


// ===== OPEN REDIRECT - HIGH =====
function handleRedirect(req, res) {
  const redirectUrl = req.query.url || req.body.redirect;
  // No URL validation - open redirect - VULNERABILITY
  res.redirect(redirectUrl);
}

function buildRedirectURL(baseUrl, returnPath) {
  // User-controlled redirect - VULNERABILITY
  return `${baseUrl}${returnPath}`;
}


// ===== INSECURE RANDOMNESS - HIGH =====
function generateSessionId() {
  // Using Math.random for security - VULNERABILITY
  return 'sess_' + Math.random().toString(36).substring(2);
}

function generateOTP() {
  // Predictable OTP - VULNERABILITY
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function generateCSRFToken() {
  // Weak CSRF token - VULNERABILITY
  return Date.now().toString(16) + Math.random().toString(16);
}

function generateAPIKey() {
  // Insecure API key generation - VULNERABILITY
  const timestamp = Date.now();
  const random = Math.floor(Math.random() * 1000000);
  return `api_${timestamp}_${random}`;
}





// ===== UNSAFE FILE OPERATIONS - HIGH =====
const fs = require('fs');
const path = require('path');

function readUserFile(userId, filename) {
  // Path traversal - VULNERABILITY
  const filePath = `./users/${userId}/${filename}`;
  return fs.readFileSync(filePath, 'utf8');
}

function writeUserData(userId, filename, data) {
  // No path sanitization - VULNERABILITY
  const filePath = path.join('./data', userId, filename);
  fs.writeFileSync(filePath, data);
}

function deleteFile(filename) {
  // Arbitrary file deletion - VULNERABILITY
  fs.unlinkSync(filename);
}


// ===== INFORMATION DISCLOSURE - MEDIUM =====
function handleError(error, res) {
  // Exposing stack trace - VULNERABILITY
  res.status(500).json({
    error: error.message,
    stack: error.stack,
    env: process.env
  });
}

function debugEndpoint(req, res) {
  // Exposing sensitive information - VULNERABILITY
  res.json({
    environment: process.env,
    headers: req.headers,
    memory: process.memoryUsage(),
    uptime: process.uptime()
  });
}


// ===== RACE CONDITION PATTERNS - HIGH =====
let balance = 1000;

async function withdraw(amount) {
  // TOCTOU Race condition - VULNERABILITY
  if (balance >= amount) {
    // Delay allows race condition
    await new Promise(resolve => setTimeout(resolve, 100));
    balance -= amount;
    return { success: true, newBalance: balance };
  }
  return { success: false, message: 'Insufficient funds' };
}

async function transfer(fromId, toId, amount) {
  // No locking mechanism - race condition - VULNERABILITY
  const fromBalance = await getBalance(fromId);
  if (fromBalance >= amount) {
    await updateBalance(fromId, fromBalance - amount);
    await updateBalance(toId, (await getBalance(toId)) + amount);
  }
}

// Simulated database functions
async function getBalance(userId) { return 1000; }
async function updateBalance(userId, balance) { return true; }


// ===== UNSAFE DYNAMIC CODE EXECUTION - CRITICAL =====
function executeUserScript(script) {
  // Direct eval of user input - VULNERABILITY
  return eval(script);
}

function processFormula(formula) {
  // Function constructor with user input - VULNERABILITY
  const fn = new Function('x', 'y', `return ${formula}`);
  return fn;
}

function runUserCode(code, context) {
  // Unsafe code execution - VULNERABILITY
  const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
  return new AsyncFunction('ctx', code)(context);
}


module.exports = {
  mergeObjects,
  unsafeDeepCopy,
  processUserConfig,
  deserializeUserData,
  parseConfig,
  parseUserJSON,
  validateEmail,
  validateURL,
  logUserActivity,
  auditLog,
  setCustomHeader,
  setCookieFromInput,
  renderTemplate,
  processTemplate,
  sandboxedEval,
  authenticateUser,
  searchUser,
  handleRedirect,
  buildRedirectURL,
  generateSessionId,
  generateOTP,
  generateCSRFToken,
  generateAPIKey,
  readUserFile,
  writeUserData,
  deleteFile,
  handleError,
  debugEndpoint,
  withdraw,
  transfer,
  executeUserScript,
  processFormula,
  runUserCode,
  EVIL_REGEX_1,
  EVIL_REGEX_2,
  EVIL_REGEX_3,
  EVIL_REGEX_4
};
