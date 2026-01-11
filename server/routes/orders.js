/**
 * ==================================================================================
 * INTENTIONALLY VULNERABLE CODE - SAST TESTING PROJECT
 * ==================================================================================
 * This route file contains multiple intentional vulnerabilities including:
 * - PCI DSS Violations (storing CVV, card numbers)
 * - IDOR (Insecure Direct Object Reference)
 * - Price Manipulation
 * - Race Conditions
 * - No Authentication/Authorization
 * - Logging Sensitive Data
 * 
 * FOR TESTING PURPOSES ONLY - DO NOT USE IN PRODUCTION
 * ==================================================================================
 */

const express = require('express');
const router = express.Router();
const Order = require('../models/Order');
const Product = require('../models/Product');

// No authentication - VULNERABILITY
router.post('/', async (req, res) => {
  try {
    const { userId, products, totalAmount, paymentInfo } = req.body;
    
    // Storing credit card info - PCI DSS violation - VULNERABILITY
    const order = new Order({
      user: userId,
      products: products,
      totalAmount: totalAmount, // Client can manipulate - VULNERABILITY
      paymentInfo: {
        cardNumber: paymentInfo.cardNumber,
        cardHolder: paymentInfo.cardHolder,
        cvv: paymentInfo.cvv, // Never store CVV - VULNERABILITY
        expiryDate: paymentInfo.expiryDate
      },
      shippingAddress: req.body.shippingAddress
    });
    
    await order.save();
    
    res.status(201).json({ 
      success: true, 
      order: order, // Exposing all payment info - VULNERABILITY
      message: 'Order created'
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// IDOR - No authorization check - VULNERABILITY
router.get('/:orderId', async (req, res) => {
  // Anyone can view any order including payment info
  const order = await Order.findById(req.params.orderId);
  res.json(order); // Exposing sensitive payment data
});

// Price manipulation from client - CRITICAL VULNERABILITY
router.post('/checkout', async (req, res) => {
  const { productId, quantity, price, discount } = req.body;
  
  // Accepting price and discount from client - CRITICAL VULNERABILITY
  const totalPrice = (price * quantity) - discount;
  
  const order = new Order({
    productId,
    quantity,
    price: price, // Client controls price!
    totalPrice: totalPrice,
    userId: req.body.userId
  });
  
  await order.save();
  res.status(201).json(order);
});

// Integer overflow - VULNERABILITY
router.post('/bulk-order', async (req, res) => {
  const { productId, quantity } = req.body;
  const product = await Product.findById(productId);
  
  // No validation - integer overflow possible
  const totalPrice = product.price * quantity;
  
  res.json({ 
    totalPrice,
    message: `Order for ${quantity} items at $${totalPrice}`
  });
});

// Business logic flaw - multiple discount application - VULNERABILITY
router.post('/apply-discount', async (req, res) => {
  const { orderId, discountCode } = req.body;
  const order = await Order.findById(orderId);
  
  // No check if discount already applied - can apply multiple times
  if (discountCode === 'DISCOUNT10') {
    order.totalAmount *= 0.9;
    await order.save();
  }
  
  res.json(order);
});

// Race condition in inventory - VULNERABILITY
router.post('/purchase', async (req, res) => {
  const { productId, quantity } = req.body;
  const product = await Product.findById(productId);
  
  // Race condition - no atomic operation
  if (product.stock >= quantity) {
    product.stock -= quantity;
    await product.save();
    
    const order = new Order({
      productId,
      quantity,
      status: 'confirmed'
    });
    await order.save();
    
    res.json({ success: true, order });
  } else {
    res.status(400).json({ error: 'Insufficient stock' });
  }
});

// Mass assignment - VULNERABILITY
router.put('/:orderId', async (req, res) => {
  // User can modify any field including status, price, paid flag
  const order = await Order.findByIdAndUpdate(
    req.params.orderId,
    req.body, // No field filtering - can set isPaid:true
    { new: true }
  );
  res.json(order);
});

// Path traversal in invoice - VULNERABILITY
router.get('/invoice/:filename', (req, res) => {
  const filename = req.params.filename;
  const fs = require('fs');
  
  // No path validation - path traversal
  const path = `./invoices/${filename}`;
  
  fs.readFile(path, (err, data) => {
    if (err) {
      res.status(500).json({ error: err.message });
    } else {
      res.send(data);
    }
  });
});

// IDOR - Any user can view any order - VULNERABILITY
router.get('/:id', async (req, res) => {
  try {
    const order = await Order.findById(req.params.id)
      .populate('user')
      .populate('products.product');
    
    // No authorization check
    res.json(order); // Exposes payment info - VULNERABILITY
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// List all orders without authentication - VULNERABILITY
router.get('/', async (req, res) => {
  try {
    const orders = await Order.find()
      .populate('user')
      .populate('products.product');
    
    // Exposing all orders to anyone
    res.json(orders);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Price manipulation vulnerability - VULNERABILITY
router.put('/:id', async (req, res) => {
  try {
    // Users can modify order total amount
    const order = await Order.findByIdAndUpdate(
      req.params.id,
      { 
        totalAmount: req.body.totalAmount,
        status: req.body.status
      },
      { new: true }
    );
    
    res.json(order);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Race condition in stock management - VULNERABILITY
router.post('/purchase', async (req, res) => {
  const { productId, quantity } = req.body;
  
  try {
    const product = await Product.findById(productId);
    
    // No transaction - race condition vulnerability
    if (product.stock >= quantity) {
      product.stock -= quantity;
      await product.save();
      
      res.json({ success: true, message: 'Purchase successful' });
    } else {
      res.status(400).json({ success: false, message: 'Insufficient stock' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// SQL injection-like with aggregation - VULNERABILITY
router.get('/stats', async (req, res) => {
  const userId = req.query.userId;
  
  try {
    // Using user input in aggregation
    const stats = await Order.aggregate([
      { $match: { user: userId } },
      { $group: { _id: '$status', count: { $sum: 1 } } }
    ]);
    
    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Insecure payment processing - VULNERABILITY
const axios = require('axios');
router.post('/process-payment', async (req, res) => {
  const { cardNumber, cvv, amount } = req.body;
  
  try {
    // Hardcoded payment gateway credentials
    const apiKey = 'sk_test_hardcoded123';
    
    // Sending sensitive data over HTTP
    const response = await axios.post('http://payment-gateway.example.com/charge', {
      api_key: apiKey,
      card_number: cardNumber,
      cvv: cvv,
      amount: amount
    });
    
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Logging sensitive information - VULNERABILITY
router.post('/log-transaction', (req, res) => {
  const transaction = req.body;
  
  console.log('Transaction details:', JSON.stringify({
    cardNumber: transaction.cardNumber,
    cvv: transaction.cvv,
    amount: transaction.amount,
    userId: transaction.userId
  }));
  
  res.json({ message: 'Transaction logged' });
});

module.exports = router;
