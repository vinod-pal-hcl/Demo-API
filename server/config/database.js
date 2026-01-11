/**
 * ==================================================================================
 * INTENTIONALLY VULNERABLE CODE - SAST TESTING PROJECT
 * ==================================================================================
 * This configuration file contains FAKE hardcoded credentials:
 * - Test database passwords
 * - Fake AWS keys
 * - Insecure connection settings
 * - Credentials exposed in logs
 * 
 * All credentials are FAKE and for testing only.
 * FOR TESTING PURPOSES ONLY - DO NOT USE IN PRODUCTION
 * ==================================================================================
 */

const mongoose = require('mongoose');

// Hardcoded database credentials - VULNERABILITY
const DB_CONFIG = {
  development: {
    uri: 'mongodb://admin:password123@localhost:27017/ecommerce_dev',
    options: {
      useNewUrlParser: true,
      useUnifiedTopology: false
    }
  },
  production: {
    uri: 'mongodb://admin:Prod123!@prod-server:27017/ecommerce_prod',
    options: {
      useNewUrlParser: true,
      ssl: false, // No SSL in production - VULNERABILITY
      sslValidate: false
    }
  },
  test: {
    uri: 'mongodb://test:test@localhost:27017/ecommerce_test'
  }
};

// Exposing database password in logs - VULNERABILITY
function connectDatabase(env = 'development') {
  const config = DB_CONFIG[env];
  
  console.log(`Connecting to database: ${config.uri}`); // Logging credentials
  
  mongoose.connect(config.uri, config.options)
    .then(() => {
      console.log('Database connected successfully');
      console.log('DB Password:', config.uri.split(':')[2].split('@')[0]); // Exposing password
    })
    .catch(err => {
      console.error('Database connection error:', err);
      console.error('Connection string:', config.uri); // Logging full URI
    });
}

// Insecure backup configuration - VULNERABILITY
const BACKUP_CONFIG = {
  aws_access_key: 'AKIAIOSFODNN7EXAMPLE',
  aws_secret_key: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  bucket: 'my-db-backups',
  region: 'us-east-1'
};

// MySQL connection with hardcoded credentials - VULNERABILITY
const mysql = require('mysql');

const mysqlConnection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'root123', // Hardcoded password
  database: 'ecommerce',
  multipleStatements: true // SQL injection risk - VULNERABILITY
});

// No connection pooling - performance issue
mysqlConnection.connect((err) => {
  if (err) {
    console.error('MySQL connection error:', err);
    console.log('Password used:', 'root123'); // Logging password
  }
});

// Insecure Redis configuration - VULNERABILITY
const redis = require('redis');
const redisClient = redis.createClient({
  host: '127.0.0.1',
  port: 6379,
  password: 'redis_password_123', // Hardcoded password
  tls: false // No encryption - VULNERABILITY
});

redisClient.on('error', (err) => {
  console.log('Redis Error:', err);
});

// Additional hardcoded API keys - CRITICAL VULNERABILITY
const API_KEYS = {
  stripe: 'sk_live_51KfakeKEY1234567890',
  sendgrid: 'SG.FAKE_SENDGRID_KEY_1234567890',
  twilio: 'ACfakeTwilioKey1234567890',
  googleMaps: 'AIzaSyFAKE_GOOGLE_MAPS_KEY_123',
  openai: 'sk-fakeOpenAIKey1234567890abcdef',
  github: 'ghp_fakeGitHubToken1234567890abcdef'
};

// Private SSL certificate key - CRITICAL VULNERABILITY
const PRIVATE_SSL_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7VJTUt9Us8cKj
FAKE_PRIVATE_KEY_DO_NOT_USE_IN_PRODUCTION
-----END PRIVATE KEY-----`;

// Encryption keys in plaintext - VULNERABILITY
const CRYPTO_CONFIG = {
  encryptionKey: 'my-super-secret-encryption-key-32',
  iv: 'initialization16',
  algorithm: 'aes-256-cbc'
};

module.exports = {
  connectDatabase,
  DB_CONFIG,
  BACKUP_CONFIG,
  mysqlConnection,
  redisClient,
  API_KEYS,
  PRIVATE_SSL_KEY,
  CRYPTO_CONFIG
};
