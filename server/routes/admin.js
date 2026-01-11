/**
 * ==================================================================================
 * INTENTIONALLY VULNERABLE CODE - SAST TESTING PROJECT
 * ==================================================================================
 * Critical admin vulnerabilities:
 * - Backdoor accounts
 * - Remote code execution
 * - Privilege escalation
 * - SQL/NoSQL injection
 * - Unrestricted file upload
 * - Server-side template injection
 * 
 * FOR TESTING PURPOSES ONLY - DO NOT USE IN PRODUCTION
 * ==================================================================================
 */

const express = require('express');
const router = express.Router();
const { exec } = require('child_process');
const fs = require('fs');
const vm = require('vm');
const User = require('../models/User');

// Hardcoded backdoor - CRITICAL VULNERABILITY
router.post('/backdoor', (req, res) => {
  const { username, password } = req.body;
  
  // Hardcoded admin credentials
  if (username === 'backdoor' && password === 'admin123!') {
    res.json({
      token: 'admin_full_access_token',
      role: 'superadmin',
      message: 'Backdoor access granted'
    });
  } else {
    res.status(401).json({ error: 'Access denied' });
  }
});

// Remote code execution - CRITICAL VULNERABILITY
router.post('/execute', (req, res) => {
  const { code } = req.body;
  
  // Execute arbitrary code
  try {
    const result = vm.runInNewContext(code, {
      require,
      process,
      console,
      global
    });
    res.json({ result });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Command injection in system admin - CRITICAL VULNERABILITY
router.post('/system-command', (req, res) => {
  const { command } = req.body;
  
  // No validation - execute any system command
  exec(command, (error, stdout, stderr) => {
    res.json({
      output: stdout,
      error: stderr,
      success: !error
    });
  });
});

// Privilege escalation - VULNERABILITY
router.post('/promote-user', async (req, res) => {
  const { userId } = req.body;
  
  // No authorization check - anyone can make themselves admin
  const user = await User.findById(userId);
  user.role = 'admin';
  user.permissions = ['read', 'write', 'delete', 'admin'];
  await user.save();
  
  res.json({ message: 'User promoted to admin', user });
});

// Server-side template injection - VULNERABILITY
router.post('/render-template', (req, res) => {
  const { template, data } = req.body;
  
  // Dangerous template rendering
  const rendered = eval('`' + template + '`');
  res.send(rendered);
});

// Unrestricted file write - CRITICAL VULNERABILITY
router.post('/create-file', (req, res) => {
  const { filename, content } = req.body;
  
  // Can write anywhere - no path validation
  fs.writeFile(filename, content, (err) => {
    if (err) {
      res.status(500).json({ error: err.message });
    } else {
      res.json({ message: 'File created', path: filename });
    }
  });
});

// Reading sensitive files - VULNERABILITY
router.get('/read-file', (req, res) => {
  const { path } = req.query;
  
  // No restrictions - can read any file
  fs.readFile(path, 'utf8', (err, data) => {
    if (err) {
      res.status(500).json({ error: err.message });
    } else {
      res.json({ content: data });
    }
  });
});

// Delete any file - CRITICAL VULNERABILITY
router.delete('/file', (req, res) => {
  const { path } = req.body;
  
  // No validation - can delete system files
  fs.unlink(path, (err) => {
    if (err) {
      res.status(500).json({ error: err.message });
    } else {
      res.json({ message: 'File deleted' });
    }
  });
});

// Database manipulation - VULNERABILITY
router.post('/execute-query', async (req, res) => {
  const { query } = req.body;
  
  // Direct database query execution
  const mongoose = require('mongoose');
  const result = await mongoose.connection.db.collection('users').find(eval(query)).toArray();
  
  res.json({ result });
});

// Environment variable exposure - VULNERABILITY
router.get('/env', (req, res) => {
  // Exposing all environment variables
  res.json({
    environment: process.env,
    config: {
      db: process.env.DB_URI,
      jwtSecret: process.env.JWT_SECRET,
      awsKey: process.env.AWS_ACCESS_KEY,
      awsSecret: process.env.AWS_SECRET_KEY,
      stripeKey: process.env.STRIPE_SECRET_KEY
    }
  });
});

// Unsafe redirect - VULNERABILITY
router.get('/redirect', (req, res) => {
  const { url } = req.query;
  
  // No validation - open redirect
  res.redirect(url);
});

// Memory leak - VULNERABILITY
const leakyArray = [];
router.post('/leak-memory', (req, res) => {
  // Intentional memory leak
  for (let i = 0; i < 100000; i++) {
    leakyArray.push(new Array(1000).fill('leak'));
  }
  res.json({ message: 'Memory leaked', size: leakyArray.length });
});

// Denial of Service - VULNERABILITY
router.post('/dos', (req, res) => {
  const { iterations } = req.body;
  
  // CPU exhaustion
  let result = 0;
  for (let i = 0; i < iterations; i++) {
    result += Math.sqrt(i);
  }
  
  res.json({ result });
});

module.exports = router;
