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
const { execFile } = require('child_process');
const jwt = require('jsonwebtoken');
const xss = require('xss');
const crypto = require('crypto');

// Environment variables recommended for secrets and credentials
const DB_CONNECTION = process.env.DB_CONNECTION || "mongodb://localhost:27017/ecommerce";
const JWT_SECRET = process.env.JWT_SECRET || "replace_with_strong_jwt_secret";
const STRIPE_KEY = process.env.STRIPE_KEY || "";
const AWS_KEY = process.env.AWS_KEY || "";

const app = express();

// Restrictive CORS configuration
const allowedOrigins = ["https://your-domain.com"];
app.use(cors({
  origin: function(origin, callback) {
    if(!origin) return callback(null, true); // Allow non-browser clients
    if(allowedOrigins.indexOf(origin) === -1){
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(fileUpload());

// Safely handle file downloads - prevent path traversal
app.get('/download', (req, res) => {
  const filename = path.basename(req.query.file || '');
  const filepath = path.join(__dirname, 'uploads', filename);

  // Check file exists
  fs.access(filepath, fs.constants.F_OK, (err) => {
    if (err) {
      return res.status(404).send('File not found');
    }
    res.download(filepath);
  });
});

// Prevent command injection by using execFile and input validation
app.post('/api/ping', (req, res) => {
  const host = req.body.host;

  // Validate input to allow only IP addresses or hostnames without special chars
  if (!host || !/^[a-zA-Z0-9.-]+$/.test(host)) {
    return res.status(400).send('Invalid host');
  }

  execFile('ping', ['-c', '4', host], (error, stdout, stderr) => {
    if (error) {
      return res.status(500).send('Ping failed');
    }
    res.send(stdout);
  });
});

// Remove use of eval to avoid code injection - example uses mathjs or safe parser (for demonstration, simple parsing here)
const math = require('mathjs');
app.post('/api/calculate', (req, res) => {
  const expression = req.body.expression;
  try {
    // Use mathjs to safely evaluate mathematical expressions
    const result = math.evaluate(expression);
    res.json({ result });
  } catch (error) {
    res.status(400).json({ error: 'Invalid mathematical expression' });
  }
});

// Fix XXE by disabling external entities
const libxmljs = require('libxmljs');
app.post('/api/parse-xml', (req, res) => {
  const xmlData = req.body.xml;
  try {
    const xmlDoc = libxmljs.parseXml(xmlData, { 
      noent: false,
      dtdload: false
    });
    res.json({ parsed: xmlDoc.toString() });
  } catch (error) {
    res.status(400).json({ error: 'Invalid XML format' });
  }
});

// Secure file upload - sanitize filename, restrict file size and types
const ALLOWED_EXTENSIONS = ['.png', '.jpg', '.jpeg', '.gif', '.pdf'];
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB

app.post('/api/upload', (req, res) => {
  if (!req.files || Object.keys(req.files).length === 0) {
    return res.status(400).send('No files uploaded.');
  }

  const uploadedFile = req.files.file;

  if (uploadedFile.size > MAX_FILE_SIZE) {
    return res.status(400).send('File too large. Max 5MB allowed.');
  }

  const ext = path.extname(uploadedFile.name).toLowerCase();
  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    return res.status(400).send('File type not allowed.');
  }

  const safeName = path.basename(uploadedFile.name);
  const uploadPath = path.join(__dirname, 'uploads', safeName);

  uploadedFile.mv(uploadPath, (err) => {
    if (err) return res.status(500).send('Failed to upload file.');
    res.send('File uploaded!');
  });
});

// NoSQL Injection mitigation: sanitize inputs or use parameterized queries
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  // Validate type and length
  if (typeof username !== 'string' || typeof password !== 'string' || !username || !password) {
    return res.status(400).json({ success: false, error: 'Invalid credentials' });
  }

  // Use safe queries - assume User schema uses hashed passwords
  try {
    const user = await User.findOne({ username: username }).exec();
    if (!user) return res.status(401).json({ success: false });

    // Validate password with bcrypt
    const bcrypt = require('bcrypt');
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ success: false });

    const token = jwt.sign({ id: user._id }, JWT_SECRET);
    res.json({ success: true, token });
  } catch (err) {
    res.status(500).json({ success: false });
  }
});

// Prevent ID enumeration and data leakage
app.get('/api/user/:id', async (req, res) => {
  const userId = req.params.id;

  // Validate userId format
  if(!mongoose.Types.ObjectId.isValid(userId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }

  const user = await User.findById(userId).select('-password -email -ssn -creditCard').exec();
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json(user); // No sensitive info included
});

// Sanitize inputs to prevent XSS
app.post('/api/comment', async (req, res) => {
  let comment = req.body.comment;
  if (typeof comment !== 'string' || comment.length === 0) {
    return res.status(400).json({ error: 'Invalid comment' });
  }
  comment = xss(comment); // Sanitize

  const newComment = new Comment({ 
    text: comment,
    user: req.body.userId 
  });
  await newComment.save();
  res.json(newComment);
});

// Prevent mass assignment - whitelist allowed fields
app.put('/api/user/:id', async (req, res) => {
  const userId = req.params.id;
  if(!mongoose.Types.ObjectId.isValid(userId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }

  // Whitelist fields allowed to update
  const allowedUpdates = ['name', 'email', 'phone'];
  const updates = {};
  for (const key of allowedUpdates) {
    if (req.body[key]) {
      updates[key] = req.body[key];
    }
  }

  try {
    const user = await User.findByIdAndUpdate(userId, updates, { new: true }).select('-password -ssn -creditCard').exec();
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Update failed' });
  }
});

// Remove hardcoded API keys
// const STRIPE_KEY = process.env.STRIPE_KEY;
// const AWS_KEY = process.env.AWS_KEY;

// Use strong cryptography with AES
app.post('/api/encrypt', (req, res) => {
  const text = req.body.text;
  if (typeof text !== 'string' || text.length === 0) {
    return res.status(400).json({ error: 'Invalid text' });
  }

  try {
    const algorithm = 'aes-256-cbc';
    const key = crypto.scryptSync(process.env.ENCRYPTION_KEY || 'strong_password_here', 'salt', 32);
    const iv = crypto.randomBytes(16);

    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const encryptedData = iv.toString('hex') + ':' + encrypted;

    res.json({ encrypted: encryptedData });
  } catch (e) {
    res.status(500).json({ error: 'Encryption failed' });
  }
});

// Remove information disclosure
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send({
    error: 'Internal Server Error'
  });
});

// Secure MongoDB connection using environment variables and updated options
mongoose.connect(DB_CONNECTION, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('Connected to MongoDB securely');
}).catch(err => console.log(err));

// Import routes
const productRoutes = require('./routes/products');
const userRoutes = require('./routes/users');
const orderRoutes = require('./routes/orders');

app.use('/api/products', productRoutes);
app.use('/api/users', userRoutes);
app.use('/api/orders', orderRoutes);

// Disable directory listing by disabling static listing (default express.static does not enable directory listing)
app.use('/static', express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  // Do not log secrets
});

// Improved unhandled promise rejection handling
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  // Optional: exit or perform cleanup
});

module.exports = app;
