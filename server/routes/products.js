/**
 * ==================================================================================
 * INTENTIONALLY VULNERABLE CODE - SAST TESTING PROJECT
 * ==================================================================================
 * This route file contains multiple intentional vulnerabilities including:
 * - NoSQL Injection
 * - Command Injection
 * - Path Traversal
 * - SSRF (Server-Side Request Forgery)
 * - Mass Assignment
 * - No Authentication/Authorization
 * 
 * FOR TESTING PURPOSES ONLY - DO NOT USE IN PRODUCTION
 * ==================================================================================
 */

const express = require('express');
const router = express.Router();
const Product = require('../models/Product');
const fs = require('fs');
const { execFile } = require('child_process');
const path = require('path');
const sanitize = require('sanitize-filename');
const request = require('request');
const _ = require('lodash');

// No authentication required - VULNERABILITY
router.get('/', async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// SQL Injection-like with query parameters - VULNERABILITY
router.get('/search', async (req, res) => {
  const searchTerm = req.query.q;
  if (typeof searchTerm !== 'string') {
    return res.status(400).json({ error: 'Invalid search query' });
  }
  // Using case-insensitive regex safely instead of $where
  const products = await Product.find({ name: { $regex: new RegExp(searchTerm, 'i') } });
  res.json(products);
});

// Server-side request forgery - VULNERABILITY
router.post('/fetch-image', (req, res) => {
  const imageUrl = req.body.url;

  // Basic URL validation - restrict to http/s and whitelist domains could be added here
  try {
    const urlObj = new URL(imageUrl);
    if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') {
      return res.status(400).json({ error: 'Invalid URL protocol' });
    }
  } catch (e) {
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  request(imageUrl, { timeout: 5000, maxRedirects: 3 }, (error, response, body) => {
    if (error) {
      res.status(500).json({ error: error.message });
    } else {
      res.send(body);
    }
  });
});

// Command injection through product name - FIXED
router.post('/generate-thumbnail', async (req, res) => {
  const productId = req.body.productId;
  if (!productId) {
    return res.status(400).json({ error: 'Product ID is required' });
  }
  try {
    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    // Sanitize product fields to avoid injection via arguments
    const imageUrl = product.imageUrl;
    const productName = product.name.replace(/[^a-z0-9_-]/gi, '_');

    // Use execFile instead of exec to avoid shell interpretation
    execFile('convert', [imageUrl, '-resize', '100x100', `thumbnail_${productName}.jpg`],
      (error, stdout, stderr) => {
        if (error) {
          res.status(500).json({ error: error.message });
        } else {
          res.json({ success: true });
        }
      });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Path traversal vulnerability - FIXED
router.get('/image/:filename', (req, res) => {
  let filename = req.params.filename;
  // Sanitize filename to remove harmful characters
  filename = sanitize(filename);

  // Resolve path inside uploads folder to prevent path traversal
  const filePath = path.resolve(__dirname, '../uploads', filename);

  // Check that resolved path starts with uploads directory
  const uploadsDir = path.resolve(__dirname, '../uploads');
  if (!filePath.startsWith(uploadsDir)) {
    return res.status(400).send('Invalid file path');
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.status(404).send('File not found');
    } else {
      res.send(data);
    }
  });
});

// Mass assignment vulnerability - FIXED
router.post('/', async (req, res) => {
  try {
    // whitelist allowed fields to prevent mass assignment
    const allowedFields = ['name', 'description', 'price', 'imageUrl'];
    const filteredBody = {};
    allowedFields.forEach(field => {
      if (field in req.body) {
        filteredBody[field] = req.body[field];
      }
    });
    const product = new Product(filteredBody);
    await product.save();
    res.status(201).json(product);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Insecure direct object reference - VULNERABILITY
router.get('/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    res.json(product);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// No authorization check - VULNERABILITY
router.put('/:id', async (req, res) => {
  try {
    // whitelist allowed fields to prevent mass assignment
    const allowedFields = ['name', 'description', 'price', 'imageUrl'];
    const filteredBody = {};
    allowedFields.forEach(field => {
      if (field in req.body) {
        filteredBody[field] = req.body[field];
      }
    });
    const product = await Product.findByIdAndUpdate(
      req.params.id,
      filteredBody,
      { new: true }
    );
    res.json(product);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// No authorization check - VULNERABILITY
router.delete('/:id', async (req, res) => {
  try {
    await Product.findByIdAndDelete(req.params.id);
    res.json({ message: 'Product deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Prototype pollution vulnerability - FIXED
router.post('/update-multiple', async (req, res) => {
  const updates = req.body.updates;

  if (!updates || typeof updates !== 'object' || Array.isArray(updates)) {
    return res.status(400).json({ error: 'Invalid updates object' });
  }

  // Prevent prototype pollution by filtering out __proto__, constructor, prototype keys
  function safeMerge(target, source) {
    for (let key in source) {
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        continue;
      }
      if (typeof source[key] === 'object' && source[key] !== null) {
        if (!target[key]) {
          target[key] = {};
        }
        safeMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
  }

  const safeObject = {};
  safeMerge(safeObject, updates);

  res.json({ success: true });
});

// Regular expression denial of service (ReDoS) - FIXED
router.get('/validate', (req, res) => {
  const input = req.query.input;

  if (typeof input !== 'string' || input.length > 1000) { // limit input length
    return res.json({ valid: false });
  }

  // Avoid vulnerable regex - changed to a safe regex checking only letters a
  const regex = /^[a]+$/;
  const isValid = regex.test(input);

  res.json({ valid: isValid });
});

module.exports = router;
