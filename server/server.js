/**
 * ==================================================================================
 * WARNING: INTENTIONALLY VULNERABLE CODE - FOR SAST TESTING ONLY
 * ==================================================================================
 * This application contains deliberate security vulnerabilities for testing
 * Static Application Security Testing (SAST) tools.
 * 
 * DO NOT USE IN PRODUCTION
 * DO NOT DEPLOY TO THE INTERNET
 * DO NOT USE REAL CREDENTIALS
 * 
 * All vulnerabilities are intentional and documented.
 * ==================================================================================
 */

const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const fileUpload = require('express-fileupload');
const path = require('path');
const fs = require('fs');
const { exec } = require('child_process');

// Hardcoded credentials - VULNERABILITY
const DB_CONNECTION = "mongodb://admin:password123@localhost:27017/ecommerce";
const JWT_SECRET = "hardcoded_jwt_secret";

const app = express();

// Insecure CORS - VULNERABILITY
app.use(cors({
  origin: '*',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(fileUpload());

// Vulnerable to path traversal - VULNERABILITY
app.get('/download', (req, res) => {
  const filename = req.query.file;
  const filepath = path.join(__dirname, 'uploads', filename);
  res.download(filepath);
});

// Command injection vulnerability - VULNERABILITY
app.post('/api/ping', (req, res) => {
  const host = req.body.host;
  exec(`ping -c 4 ${host}`, (error, stdout, stderr) => {
    res.send(stdout);
  });
});

// SQL Injection-like vulnerability with eval - VULNERABILITY
app.post('/api/calculate', (req, res) => {
  const expression = req.body.expression;
  try {
    const result = eval(expression);
    res.json({ result });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// XXE vulnerability - VULNERABILITY
const libxmljs = require('libxmljs');
app.post('/api/parse-xml', (req, res) => {
  const xmlData = req.body.xml;
  const xmlDoc = libxmljs.parseXml(xmlData, { 
    noent: true,
    dtdload: true 
  });
  res.json({ parsed: xmlDoc.toString() });
});

// Insecure file upload - VULNERABILITY
app.post('/api/upload', (req, res) => {
  if (!req.files || Object.keys(req.files).length === 0) {
    return res.status(400).send('No files uploaded.');
  }

  const uploadedFile = req.files.file;
  const uploadPath = path.join(__dirname, 'uploads', uploadedFile.name);

  uploadedFile.mv(uploadPath, (err) => {
    if (err) return res.status(500).send(err);
    res.send('File uploaded!');
  });
});

// NoSQL Injection - VULNERABILITY
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  
  // Directly using user input in query - NoSQL injection
  const user = await User.findOne({ 
    username: username, 
    password: password 
  });

  if (user) {
    const token = jwt.sign({ id: user._id }, JWT_SECRET);
    res.json({ success: true, token });
  } else {
    res.status(401).json({ success: false });
  }
});

// Insecure direct object reference - VULNERABILITY
app.get('/api/user/:id', async (req, res) => {
  const userId = req.params.id;
  const user = await User.findById(userId);
  res.json(user); // Returns all user data including sensitive info
});

// XSS vulnerability - no sanitization - VULNERABILITY
app.post('/api/comment', async (req, res) => {
  const comment = req.body.comment;
  const newComment = new Comment({ 
    text: comment, // No sanitization
    user: req.body.userId 
  });
  await newComment.save();
  res.json(newComment);
});

// Mass assignment vulnerability - VULNERABILITY
app.put('/api/user/:id', async (req, res) => {
  const userId = req.params.id;
  const user = await User.findByIdAndUpdate(userId, req.body, { new: true });
  res.json(user);
});

// Hardcoded API keys - VULNERABILITY
const STRIPE_KEY = "sk_live_51HqLyjWDarjtT1zdp7dcXYZ123";
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";

// Weak cryptography - VULNERABILITY
const crypto = require('crypto');
app.post('/api/encrypt', (req, res) => {
  const text = req.body.text;
  const cipher = crypto.createCipher('des', 'weak-key'); // DES is weak
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  res.json({ encrypted });
});

// Information disclosure - VULNERABILITY
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send({
    error: err.message,
    stack: err.stack, // Exposes stack trace
    env: process.env // Exposes environment variables
  });
});

// Insecure MongoDB connection - VULNERABILITY
mongoose.connect(DB_CONNECTION, { 
  useNewUrlParser: true,
  useUnifiedTopology: false // Outdated option
}).then(() => {
  console.log('Connected to MongoDB with hardcoded credentials');
}).catch(err => console.log(err));

// Import routes
const productRoutes = require('./routes/products');
const userRoutes = require('./routes/users');
const orderRoutes = require('./routes/orders');

app.use('/api/products', productRoutes);
app.use('/api/users', userRoutes);
app.use('/api/orders', orderRoutes);

// Serve static files - potential for directory listing
app.use('/static', express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`JWT Secret: ${JWT_SECRET}`); // Logging secrets
});

// Unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.log('Unhandled Rejection:', reason);
});

module.exports = app;
