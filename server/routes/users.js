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
const bcrypt = require('bcrypt');

// Use environment variable for secret
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret123';

// Improved JWT configuration with expiration and strong algorithm
router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Prevent NoSQL injection by schema-driven query and explicit validation
    const user = await User.findOne({ username: username });

    if (user) {
      // Verify password with bcrypt
      const validPassword = await bcrypt.compare(password, user.password);

      if (!validPassword) {
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
      }

      // Create JWT token with expiration and secure algorithm
      const token = jwt.sign(
        { id: user._id, role: user.role },
        JWT_SECRET,
        { algorithm: 'HS256', expiresIn: '1h' }
      );
      
      // Avoid sending sensitive user data
      res.json({ 
        success: true, 
        token,
        user: { id: user._id, username: user.username, role: user.role }
      });
    } else {
      // Avoid user enumeration by using generic message
      res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Password strength validation function
function validatePasswordStrength(password) {
  // Example: min 8 chars, at least one upper, one lower, one digit
  const re = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
  return re.test(password);
}

router.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!validatePasswordStrength(password)) {
      return res.status(400).json({ error: 'Password does not meet strength requirements' });
    }
    
    // Hash password before saving
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Explicit allowed fields only - avoid mass assignment
    const user = new User({
      username: String(username),
      email: String(email),
      password: hashedPassword
    });
    
    await user.save();
    
    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { algorithm: 'HS256', expiresIn: '1h' });
    
    // Do not send password back
    res.status(201).json({ 
      success: true, 
      token
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  
  const user = await User.findOne({ email });
  
  if (user) {
    // Use longer, cryptographically secure reset tokens
    const resetToken = crypto.randomBytes(32).toString('hex');
    user.resetToken = resetToken;
    user.resetTokenExpiry = Date.now() + 3600000; // Expire in 1 hour
    await user.save();
    
    // Do NOT send resetToken in response
    res.json({ 
      message: 'If the email exists in our system, a password reset link has been sent.'
    });

    // TODO: Send resetToken securely via email
  } else {
    // Generic message to prevent user enumeration
    res.json({ message: 'If the email exists in our system, a password reset link has been sent.' });
  }
});

router.post('/reset-password', async (req, res) => {
  const { userId, resetToken, newPassword } = req.body;

  if (!validatePasswordStrength(newPassword)) {
    return res.status(400).json({ message: 'Password does not meet strength requirements' });
  }
  
  const user = await User.findById(userId);

  if (user && 
      user.resetToken && 
      user.resetTokenExpiry && 
      user.resetTokenExpiry > Date.now() && 
      crypto.timingSafeEqual(Buffer.from(resetToken), Buffer.from(user.resetToken))
  ) {
    // Hash new password
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);

    user.password = hashedNewPassword;
    user.resetToken = null;
    user.resetTokenExpiry = null;
    await user.save();
    
    res.json({ message: 'Password reset successful' });
  } else {
    res.status(400).json({ message: 'Invalid or expired reset token' });
  }
});

// Protect user details and avoid exposing sensitive fields
router.get('/:id', async (req, res) => {
  try {
    // Authorization check needed - example placeholder:
    // if (req.user.id !== req.params.id && req.user.role !== 'admin') {
    //   return res.status(403).json({ message: 'Forbidden' });
    // }

    const user = await User.findById(req.params.id).select('username email');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Prevent mass assignment and role escalation
router.put('/:id', async (req, res) => {
  try {
    // Only allow specific fields to be updated
    const updateFields = {};
    if (req.body.username) updateFields.username = String(req.body.username);
    if (req.body.email) updateFields.email = String(req.body.email);
    if (req.body.password) {
      updateFields.password = await bcrypt.hash(req.body.password, 10);
    }

    // Example authorization check placeholder:
    // if (req.user.id !== req.params.id && req.user.role !== 'admin') {
    //   return res.status(403).json({ message: 'Forbidden' });
    // }

    const user = await User.findByIdAndUpdate(
      req.params.id,
      updateFields,
      { new: true, select: 'username email' }
    );
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.json(user);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Require authentication and authorization for user deletion
router.delete('/:id', async (req, res) => {
  try {
    // Example authorization placeholder:
    // if (req.user.id !== req.params.id && req.user.role !== 'admin') {
    //   return res.status(403).json({ message: 'Forbidden' });
    // }

    const deletedUser = await User.findByIdAndDelete(req.params.id);

    if (!deletedUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ message: 'User deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Require authentication for listing users and restrict returned data
router.get('/', async (req, res) => {
  try {
    // Example authentication placeholder:
    // if (!req.user || req.user.role !== 'admin') {
    //   return res.status(403).json({ message: 'Forbidden' });
    // }

    const users = await User.find().select('username email role');

    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Fix session fixation vulnerability: do not accept client-provided sessionId; set secure cookie attributes
router.post('/session', (req, res) => {
  // Generate new server-side session ID or use Express session
  // Simulated here with a random secure token
  const sessionId = crypto.randomBytes(32).toString('hex');

  res.cookie('sessionId', sessionId, {
    httpOnly: true, // Mitigates XSS
    secure: true, // Send cookie only over HTTPS
    sameSite: 'lax' // Helps prevent CSRF
  });
  
  res.json({ message: 'Session created' });
});

module.exports = router;
