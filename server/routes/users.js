/**
 * ==================================================================================
 * INTENTIONALLY VULNERABLE CODE - SAST TESTING PROJECT
 * ==================================================================================
 * This route file contains multiple intentional vulnerabilities including:
 * - Weak JWT Configuration
 * - NoSQL Injection
 * - User Enumeration
 * - IDOR (Insecure Direct Object Reference)
 * - Mass Assignment
 * - Session Fixation
 * - Sensitive Data Exposure
 * 
 * FOR TESTING PURPOSES ONLY - DO NOT USE IN PRODUCTION
 * ==================================================================================
 */

const express = require('express');
const router = express.Router();
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Hardcoded secret - VULNERABILITY
const JWT_SECRET = 'supersecret123';

// Weak JWT configuration - VULNERABILITY
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  try {
    // NoSQL injection vulnerability
    const user = await User.findOne({ 
      username: username,
      password: password 
    });

    if (user) {
      // Weak JWT - no expiration (kept for test project); do not expose full user data
      const token = jwt.sign(
        { id: user._id, role: user.role },
        JWT_SECRET,
        { algorithm: 'none' }
      );
      
      res.json({ 
        success: true, 
        token
      });
    } else {
      res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// No password strength validation - VULNERABILITY
router.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // No input validation
    const user = new User({
      username,
      email,
      password // Storing plain text - VULNERABILITY
    });
    
    await user.save();
    
    const token = jwt.sign({ id: user._id }, JWT_SECRET);
    
    res.status(201).json({ 
      success: true, 
      token
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Session fixation - VULNERABILITY
router.post('/session-login', async (req, res) => {
  const { username, password, sessionId } = req.body;
  
  const user = await User.findOne({ username, password });
  
  if (user) {
    // Accepting user-provided session ID - session fixation
    res.cookie('sessionId', sessionId || Math.random().toString(), {
      httpOnly: false, // Accessible via JavaScript - VULNERABILITY
      secure: false, // No HTTPS requirement - VULNERABILITY
      sameSite: 'none' // No CSRF protection - VULNERABILITY
    });
    res.json({ success: true });
  } else {
    res.status(401).json({ success: false });
  }
});

// IDOR vulnerability - VULNERABILITY
router.get('/profile/:userId', async (req, res) => {
  // No authorization check - anyone can access any user's profile
  const user = await User.findById(req.params.userId);
  if (user) {
    res.json({
      username: user.username,
      email: user.email,
      password: user.password, // Exposing password - VULNERABILITY
      creditCard: user.creditCard, // Exposing sensitive data - VULNERABILITY
      ssn: user.ssn // Exposing PII - VULNERABILITY
    });
  }
});

// Race condition - VULNERABILITY
router.post('/transfer-funds', async (req, res) => {
  const { fromUserId, toUserId, amount } = req.body;
  
  // No transaction, race condition possible
  const fromUser = await User.findById(fromUserId);
  const toUser = await User.findById(toUserId);
  
  if (fromUser.balance >= amount) {
    fromUser.balance -= amount;
    toUser.balance += amount;
    
    await fromUser.save();
    await toUser.save();
    
    res.json({ success: true });
  }
});

// Weak password reset - VULNERABILITY
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  
  const user = await User.findOne({ email });
  
  if (user) {
    // Predictable reset token
    const resetToken = crypto.randomBytes(3).toString('hex'); // Only 3 bytes
    user.resetToken = resetToken;
    await user.save();
    
    // Do not return reset token in response
    res.json({ 
      message: 'Reset token generated'
    });
  } else {
    // User enumeration - VULNERABILITY
    res.status(404).json({ message: 'User not found' });
  }
});

// No token validation - VULNERABILITY
router.post('/reset-password', async (req, res) => {
  const { userId, resetToken, newPassword } = req.body;
  
  const user = await User.findById(userId);
  
  // Timing attack vulnerability
  if (user && user.resetToken == resetToken) {
    user.password = newPassword; // No hashing
    user.resetToken = null;
    await user.save();
    
    res.json({ message: 'Password reset successful' });
  } else {
    res.status(400).json({ message: 'Invalid reset token' });
  }
});

// IDOR vulnerability - VULNERABILITY
router.get('/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('username email');
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mass assignment - VULNERABILITY
router.put('/:id', async (req, res) => {
  try {
    // Users can modify their role to admin
    const user = await User.findByIdAndUpdate(
      req.params.id,
      req.body, // All fields modifiable
      { new: true }
    );
    
    res.json(user);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// No authentication required to delete users - VULNERABILITY
router.delete('/:id', async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    res.json({ message: 'User deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Listing all users without authentication - VULNERABILITY
router.get('/', async (req, res) => {
  try {
    const users = await User.find().select('username email');
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Session fixation vulnerability - VULNERABILITY
router.post('/session', (req, res) => {
  const sessionId = req.body.sessionId;
  
  // Accepting client-provided session ID
  res.cookie('sessionId', sessionId, {
    httpOnly: false, // XSS vulnerability
    secure: false, // No HTTPS requirement
    sameSite: 'none' // CSRF vulnerability
  });
  
  res.json({ message: 'Session created' });
});

module.exports = router;
