/**
 * ==================================================================================
 * INTENTIONALLY VULNERABLE CODE - SAST TESTING PROJECT
 * ==================================================================================
 * This file exposes sensitive configuration and contains XSS vulnerabilities.
 * FOR TESTING PURPOSES ONLY - DO NOT USE IN PRODUCTION
 * ==================================================================================
 */

import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';
import App from './App';

ReactDOM.render(
  <App />, 
  document.getElementById('root')
);

// Exposing sensitive config - VULNERABILITY
window.API_CONFIG = {
  apiKey: 'pk_test_51HqLyjWDarjtT1zdp7dc',
  apiUrl: 'http://localhost:5000/api'
  // Removed jwtSecret from client side to protect sensitive data
};

// Using eval with user input - VULNERABILITY
window.executeCode = function(code) {
  // Removed eval call to prevent arbitrary code execution
  console.warn('Execution of arbitrary code is disabled for security reasons.');
};

// XSS vulnerability - setting innerHTML - FIXED by sanitizing HTML input
import DOMPurify from 'dompurify';

window.renderHTML = function(html) {
  const cleanHTML = DOMPurify.sanitize(html);
  document.getElementById('content').innerHTML = cleanHTML;
};