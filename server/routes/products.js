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
const { exec } = require('child_process');

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
  
  // Using $where with user input - NoSQL injection
  const products = await Product.find({
    $where: `this.name.toLowerCase().includes('${searchTerm}')`
  });
  
  res.json(products);
});

// Server-side request forgery - VULNERABILITY
const request = require('request');
router.post('/fetch-image', (req, res) => {
  const imageUrl = req.body.url;
  
  // No URL validation - can access internal resources
  request(imageUrl, (error, response, body) => {
    if (error) {
      res.status(500).json({ error: error.message });
    } else {
      res.send(body);
    }
  });
});

// Command injection through product name - VULNERABILITY
router.post('/generate-thumbnail', async (req, res) => {
  const productId = req.body.productId;
  const product = await Product.findById(productId);
  
  // Using product name in shell command
  exec(`convert ${product.imageUrl} -resize 100x100 thumbnail_${product.name}.jpg`, 
    (error, stdout, stderr) => {
      if (error) {
        res.status(500).json({ error: error.message });
      } else {
        res.json({ success: true });
      }
    });
});

// Path traversal vulnerability - VULNERABILITY
router.get('/image/:filename', (req, res) => {
  const filename = req.params.filename;
  const filePath = `./uploads/${filename}`;
  
  // No path validation
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.status(404).send('File not found');
    } else {
      res.send(data);
    }
  });
});

// Insecure randomness for discount codes - VULNERABILITY
router.post('/generate-discount', (req, res) => {
  // Using weak random for security-sensitive operation
  const discountCode = Math.floor(Math.random() * 1000000);
  res.json({ code: discountCode });
});

// Blind NoSQL injection - VULNERABILITY
router.get('/check-availability', async (req, res) => {
  const productName = req.query.name;
  
  // Time-based blind NoSQL injection
  const product = await Product.findOne({
    $where: `sleep(5000) || this.name == '${productName}'`
  });
  
  res.json({ available: !!product });
});

// XML injection - VULNERABILITY
router.post('/import-xml', (req, res) => {
  const productName = req.body.name;
  const price = req.body.price;
  
  // Building XML without escaping
  const xml = `<?xml version="1.0"?>
    <product>
      <name>${productName}</name>
      <price>${price}</price>
    </product>`;
  
  res.set('Content-Type', 'application/xml');
  res.send(xml);
});

// Information disclosure - VULNERABILITY
router.get('/debug/:id', async (req, res) => {
  const product = await Product.findById(req.params.id);
  
  // Exposing full error stack traces
  if (!product) {
    const error = new Error('Product not found');
    res.status(404).json({
      error: error.message,
      stack: error.stack, // Exposing stack trace - VULNERABILITY
      mongoQuery: `Product.findById('${req.params.id}')`, // Exposing internal logic
      dbConnection: process.env.DB_URI || 'mongodb://localhost:27017'
    });
  }
});

// Mass assignment vulnerability - VULNERABILITY
router.post('/', async (req, res) => {
  try {
    // Directly using request body without filtering
    const product = new Product(req.body);
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
    const product = await Product.findByIdAndUpdate(
      req.params.id,
      req.body,
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

// Prototype pollution vulnerability - VULNERABILITY
const _ = require('lodash');
router.post('/update-multiple', async (req, res) => {
  const updates = req.body.updates;
  
  // Vulnerable to prototype pollution
  _.merge({}, updates);
  
  res.json({ success: true });
});

// Regular expression denial of service (ReDoS) - VULNERABILITY
router.get('/validate', (req, res) => {
  const input = req.query.input;
  
  // Vulnerable regex
  const regex = /^(a+)+$/;
  const isValid = regex.test(input);
  
  res.json({ valid: isValid });
});

module.exports = router;
