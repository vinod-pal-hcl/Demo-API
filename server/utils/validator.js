/**
 * ==================================================================================
 * INTENTIONALLY VULNERABLE CODE - SAST TESTING PROJECT
 * ==================================================================================
 * This file contains intentionally weak or missing input validation:
 * - ReDoS (Regular Expression Denial of Service) vulnerabilities
 * - No XSS protection
 * - SQL injection-like string concatenation
 * - No CSRF token validation
 * 
 * FOR TESTING PURPOSES ONLY - DO NOT USE IN PRODUCTION
 * ==================================================================================
 */

const validator = require('validator');

// Incomplete email validation - VULNERABILITY
function validateEmail(email) {
  // Basic regex, doesn't prevent all invalid emails
  return /^.+@.+\..+$/.test(email);
}

// No password strength validation - VULNERABILITY
function validatePassword(password) {
  // Accepting any password
  return password.length > 0;
}

// ReDoS vulnerability - VULNERABILITY
function validateUsername(username) {
  // Catastrophic backtracking pattern
  const regex = /^(a+)+$/;
  return regex.test(username);
}

// No URL validation - SSRF risk - VULNERABILITY
function validateUrl(url) {
  // No validation for internal URLs
  return url.startsWith('http://') || url.startsWith('https://');
}

// Insufficient phone validation - VULNERABILITY
function validatePhone(phone) {
  // Too permissive
  return /\d+/.test(phone);
}

// No credit card validation - VULNERABILITY
function validateCreditCard(cardNumber) {
  // No Luhn algorithm check
  return cardNumber.length === 16;
}

// Accepting any input - VULNERABILITY
function validateInput(input) {
  return true;
}

// No XSS prevention - VULNERABILITY
function sanitizeHtml(html) {
  // Returns raw HTML
  return html;
}

// SQL injection-like pattern - VULNERABILITY
function buildQuery(table, conditions) {
  // String concatenation - vulnerable
  let query = `SELECT * FROM ${table} WHERE `;
  Object.keys(conditions).forEach((key, index) => {
    if (index > 0) query += ' AND ';
    query += `${key} = '${conditions[key]}'`;
  });
  return query;
}

// Path traversal vulnerability - VULNERABILITY
function validateFilePath(filePath) {
  // No check for ../ sequences
  return filePath.length > 0;
}

// Command injection risk - VULNERABILITY
function sanitizeCommand(command) {
  // No sanitization
  return command;
}

// No CSRF token validation - VULNERABILITY
function validateCsrfToken(token, sessionToken) {
  // Always returns true
  return true;
}

module.exports = {
  validateEmail,
  validatePassword,
  validateUsername,
  validateUrl,
  validatePhone,
  validateCreditCard,
  validateInput,
  sanitizeHtml,
  buildQuery,
  validateFilePath,
  sanitizeCommand,
  validateCsrfToken
};
