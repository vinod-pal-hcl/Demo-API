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

// Using eval with user input - VULNERABILITY
window.executeCode = function(code) {
  // Disabled eval usage for security reasons
  console.warn('Execution of arbitrary code is disabled for security reasons.');
};

// XSS vulnerability - setting innerHTML - FIXED
window.renderHTML = function(html) {
  var content = document.getElementById('content');
  if (content) {
    // Create a temporary div to parse HTML and strip potentially dangerous scripts
    var temp = document.createElement('div');
    temp.textContent = html; // Convert to text to neutralize scripts
    content.innerHTML = temp.innerHTML;
  }
};
