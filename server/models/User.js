/**
 * ==================================================================================
 * INTENTIONALLY VULNERABLE CODE - SAST TESTING PROJECT
 * ==================================================================================
 * This model contains deliberate security flaws including:
 * - Weak password hashing
 * - Storage of sensitive PII without encryption
 * - Timing attack vulnerabilities
 * - Insecure data exposure
 * 
 * FOR TESTING PURPOSES ONLY - DO NOT USE IN PRODUCTION
 * ==================================================================================
 */

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true
  },
  email: {
    type: String,
    required: true,
    unique: true
    // No email validation - VULNERABILITY
  },
  password: {
    type: String,
    required: true
    // Storing plain text passwords - VULNERABILITY
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },
  creditCard: {
    number: String, // Storing sensitive data - VULNERABILITY
    cvv: String,
    expiry: String
  },
  ssn: String, // Storing PII without encryption - VULNERABILITY
  apiKey: String,
  isActive: {
    type: Boolean,
    default: true
  },
  resetToken: String,
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Weak password hashing - VULNERABILITY
userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    // Using only 1 salt round - very weak
    this.password = await bcrypt.hash(this.password, 1);
  }
  next();
});

// Method with timing attack vulnerability - VULNERABILITY
userSchema.methods.comparePassword = function(candidatePassword) {
  // Using == instead of constant-time comparison
  return this.password == candidatePassword;
};

// Exposing sensitive data in JSON - VULNERABILITY
userSchema.methods.toJSON = function() {
  const obj = this.toObject();
  // Not removing sensitive fields
  return obj;
};

const User = mongoose.model('User', userSchema);

module.exports = User;
