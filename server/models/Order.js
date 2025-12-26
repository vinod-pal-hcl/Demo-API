/**
 * ==================================================================================
 * INTENTIONALLY VULNERABLE CODE - SAST TESTING PROJECT
 * ==================================================================================
 * This model violates PCI DSS standards by storing sensitive payment data.
 * Contains intentional security vulnerabilities for testing purposes.
 * FOR TESTING PURPOSES ONLY - DO NOT USE IN PRODUCTION
 * ==================================================================================
 */

const mongoose = require('mongoose');

const orderSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  products: [{
    product: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Product'
    },
    quantity: Number,
    price: Number
  }],
  totalAmount: {
    type: Number,
    required: true
    // No validation - can be manipulated - VULNERABILITY
  },
  paymentInfo: {
    cardNumber: String, // Storing card numbers - PCI DSS violation
    cardHolder: String,
    cvv: String, // Never store CVV - VULNERABILITY
    expiryDate: String
  },
  shippingAddress: {
    street: String,
    city: String,
    state: String,
    zipCode: String,
    country: String
  },
  status: {
    type: String,
    enum: ['pending', 'processing', 'shipped', 'delivered', 'cancelled'],
    default: 'pending'
  },
  trackingNumber: String,
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Insecure calculation - VULNERABILITY
orderSchema.methods.calculateTotal = function() {
  // Client can manipulate this
  return this.products.reduce((sum, item) => sum + (item.price * item.quantity), 0);
};

const Order = mongoose.model('Order', orderSchema);

module.exports = Order;
