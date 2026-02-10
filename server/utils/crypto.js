/**
 * ==================================================================================
 * INTENTIONALLY VULNERABLE CODE - SAST TESTING PROJECT
 * ==================================================================================
 * This file contains CRITICAL cryptographic and injection vulnerabilities:
 * - Broken Cryptography (DES, MD5, ECB mode)
 * - SQL Injection patterns
 * - XML External Entity (XXE)
 * - Insecure TLS/SSL configuration
 * - Certificate validation bypass
 * - Cleartext transmission
 * 
 * FOR TESTING PURPOSES ONLY - DO NOT USE IN PRODUCTION
 * ==================================================================================
 */

const crypto = require('crypto');
const https = require('https');
const http = require('http');
const mysql = require('mysql2');
const xml2js = require('xml2js');

// ===== BROKEN CRYPTOGRAPHY - CRITICAL =====

// Using deprecated DES algorithm - VULNERABILITY
function encryptWithDES(data, key) {
  const cipher = crypto.createCipher('des', key);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

// Using MD5 for password hashing - VULNERABILITY
function hashPasswordMD5(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

// Using SHA1 - weak hash - VULNERABILITY
function hashDataSHA1(data) {
  return crypto.createHash('sha1').update(data).digest('hex');
}

// ECB mode encryption - VULNERABILITY
function encryptECB(data, key) {
  const cipher = crypto.createCipheriv('aes-128-ecb', key.slice(0, 16), '');
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

// Hardcoded IV - VULNERABILITY
const STATIC_IV = Buffer.from('1234567890123456');
function encryptWithStaticIV(data, key) {
  const cipher = crypto.createCipheriv('aes-256-cbc', key, STATIC_IV);
  return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

// Weak key derivation - VULNERABILITY
function deriveKey(password) {
  // Only 1 iteration - too weak
  return crypto.pbkdf2Sync(password, 'static_salt', 1, 32, 'sha1');
}

// No salt in password hash - VULNERABILITY
function unsafePasswordHash(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}


// ===== SQL INJECTION - CRITICAL =====

const dbConnection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password123',  // Hardcoded credentials - VULNERABILITY
  database: 'ecommerce'
});

// Direct string concatenation - SQL Injection - VULNERABILITY
function getUserByUsername(username) {
  const query = "SELECT * FROM users WHERE username = '" + username + "'";
  return new Promise((resolve, reject) => {
    dbConnection.query(query, (error, results) => {
      if (error) reject(error);
      resolve(results);
    });
  });
}

// Template literal SQL injection - VULNERABILITY
function searchProducts(category, minPrice) {
  const query = `SELECT * FROM products WHERE category = '${category}' AND price >= ${minPrice}`;
  return dbConnection.promise().query(query);
}

// Order by injection - VULNERABILITY
function getProductsSorted(sortColumn) {
  const query = `SELECT * FROM products ORDER BY ${sortColumn}`;
  return dbConnection.promise().query(query);
}

// LIKE clause injection - VULNERABILITY
function searchByName(searchTerm) {
  const query = `SELECT * FROM products WHERE name LIKE '%${searchTerm}%'`;
  return dbConnection.promise().query(query);
}

// Multiple injection points - VULNERABILITY
function complexQuery(table, column, value, orderBy) {
  const query = `SELECT ${column} FROM ${table} WHERE ${column} = '${value}' ORDER BY ${orderBy}`;
  return dbConnection.promise().query(query);
}

// INSERT injection - VULNERABILITY
function insertUser(username, email, password) {
  const query = `INSERT INTO users (username, email, password) VALUES ('${username}', '${email}', '${password}')`;
  return dbConnection.promise().query(query);
}

// UPDATE injection - VULNERABILITY
function updateUserEmail(userId, newEmail) {
  const query = `UPDATE users SET email = '${newEmail}' WHERE id = ${userId}`;
  return dbConnection.promise().query(query);
}

// DELETE injection - VULNERABILITY
function deleteUser(username) {
  const query = `DELETE FROM users WHERE username = '${username}'`;
  return dbConnection.promise().query(query);
}


// ===== XXE (XML External Entity) - CRITICAL =====

// Unsafe XML parsing - VULNERABILITY
function parseXMLUnsafe(xmlString) {
  const parser = new xml2js.Parser({
    explicitArray: false,
    // Not disabling external entities
  });
  return parser.parseStringPromise(xmlString);
}

// Direct DOM parsing with entities enabled - VULNERABILITY
const DOMParser = require('xmldom').DOMParser;

function parseXMLDOM(xmlString) {
  const parser = new DOMParser();
  // External entities enabled by default - VULNERABILITY
  return parser.parseFromString(xmlString, 'text/xml');
}


// ===== INSECURE TLS/SSL - CRITICAL =====

// Disabling certificate verification - VULNERABILITY
const insecureAgent = new https.Agent({
  rejectUnauthorized: false,  // CRITICAL VULNERABILITY
  checkServerIdentity: () => undefined
});

function makeInsecureRequest(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { agent: insecureAgent }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    }).on('error', reject);
  });
}

// Using HTTP for sensitive data - VULNERABILITY
function sendPasswordOverHTTP(email, password) {
  const postData = JSON.stringify({ email, password });
  
  const options = {
    hostname: 'api.example.com',
    port: 80,  // HTTP port - not HTTPS - VULNERABILITY
    path: '/auth/login',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    }
  };

  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    });
    req.write(postData);
    req.end();
  });
}

// Weak TLS version - VULNERABILITY
const weakTLSOptions = {
  minVersion: 'TLSv1',  // TLS 1.0 is deprecated - VULNERABILITY
  maxVersion: 'TLSv1.2',
  ciphers: 'DES-CBC3-SHA:RC4-SHA'  // Weak ciphers - VULNERABILITY
};


// ===== XPATH INJECTION - HIGH =====

function findUserByXPath(username) {
  // XPath injection - VULNERABILITY
  const xpath = `//users/user[username='${username}']`;
  return xpath;
}

function findProductXPath(category, name) {
  // Multiple XPath injection points - VULNERABILITY
  return `//products/product[category='${category}' and name='${name}']`;
}


// ===== HEADER INJECTION - HIGH =====

function setLocationHeader(res, redirectUrl) {
  // CRLF injection in Location header - VULNERABILITY
  res.setHeader('Location', redirectUrl);
}

function setContentDisposition(res, filename) {
  // Filename injection - VULNERABILITY
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
}


// ===== UNSAFE REGEX - HIGH =====

// Email regex with catastrophic backtracking - VULNERABILITY
const UNSAFE_EMAIL_REGEX = /^([a-zA-Z0-9_\.-]+)@([\da-zA-Z\.-]+)\.([a-zA-Z\.]{2,6})$/;

// URL regex with exponential time complexity - VULNERABILITY  
const UNSAFE_URL_REGEX = /^((https?|ftp):\/\/)?([a-z0-9-]+\.)+[a-z]{2,}(\/\S*)?$/i;

// IPv4 regex vulnerable to ReDoS - VULNERABILITY
const UNSAFE_IP_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/;


// ===== CLEARTEXT STORAGE - CRITICAL =====

// Storing passwords in plaintext - VULNERABILITY
const userCredentials = {
  admin: 'admin123',
  user1: 'password123',
  user2: 'qwerty'
};

// Credit card storage in memory - VULNERABILITY
const storedCards = [];

function storeCard(cardNumber, cvv, expiry) {
  storedCards.push({
    number: cardNumber,
    cvv: cvv,  // Never store CVV - VULNERABILITY
    expiry: expiry
  });
}


module.exports = {
  encryptWithDES,
  hashPasswordMD5,
  hashDataSHA1,
  encryptECB,
  encryptWithStaticIV,
  deriveKey,
  unsafePasswordHash,
  getUserByUsername,
  searchProducts,
  getProductsSorted,
  searchByName,
  complexQuery,
  insertUser,
  updateUserEmail,
  deleteUser,
  parseXMLUnsafe,
  parseXMLDOM,
  makeInsecureRequest,
  sendPasswordOverHTTP,
  weakTLSOptions,
  findUserByXPath,
  findProductXPath,
  setLocationHeader,
  setContentDisposition,
  UNSAFE_EMAIL_REGEX,
  UNSAFE_URL_REGEX,
  UNSAFE_IP_REGEX,
  userCredentials,
  storeCard
};
