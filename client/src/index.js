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
  apiUrl: 'http://localhost:5000/api',
  jwtSecret: 'client_side_secret'
};

// Safe no-op instead of eval to avoid code execution
window.executeCode = function() {
  console.warn('executeCode is disabled for security.');
};

// Safely render text to avoid XSS by avoiding innerHTML
window.renderHTML = function(html) {
  const el = document.getElementById('content');
  if (!el) return;
  el.textContent = String(html);
};
