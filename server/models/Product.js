/**
 * ==================================================================================
 * INTENTIONALLY VULNERABLE CODE - SAST TESTING PROJECT
 * ==================================================================================
 * This model contains deliberate XSS and NoSQL injection vulnerabilities.
 * FOR TESTING PURPOSES ONLY - DO NOT USE IN PRODUCTION
 * ==================================================================================
 */

const mongoose = require('mongoose');

const productSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  description: String, // No XSS protection - VULNERABILITY
  price: {
    type: Number,
    required: true
    // No validation for negative prices - VULNERABILITY
  },
  category: String,
  imageUrl: String, // No URL validation - SSRF vulnerability
  stock: {
    type: Number,
    default: 0
  },
  seller: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  reviews: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    rating: Number,
    comment: String // No sanitization - XSS vulnerability
  }],
  tags: [String],
  isPublished: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Vulnerable aggregation - VULNERABILITY
productSchema.statics.searchProducts = function(query) {
  // Using $where with user input
  return this.find({
    $where: `this.name.indexOf('${query}') !== -1`
  });
};

const Product = mongoose.model('Product', productSchema);

module.exports = Product;
