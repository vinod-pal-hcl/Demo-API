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
  // Removed jwtSecret from client side config to prevent sensitive data exposure
};

// Removed use of eval for executing user input to prevent arbitrary code execution
window.executeCode = function(code) {
  console.warn('Execution of arbitrary code is disabled for security reasons.');
};

// Fix XSS vulnerability by safely rendering HTML content
window.renderHTML = function(html) {
  const contentElement = document.getElementById('content');
  if(contentElement) {
    // Escape potentially dangerous characters to prevent XSS
    const textNode = document.createTextNode(html);
    contentElement.innerHTML = '';
    contentElement.appendChild(textNode);
  }
};
