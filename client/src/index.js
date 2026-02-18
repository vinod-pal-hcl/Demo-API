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

// Using eval with user input - REMOVED TO MITIGATE RCE RISK
window.executeCode = function(code) {
  console.warn('Dynamic code execution is disabled for security reasons.');
};

// XSS vulnerability - avoided setting innerHTML directly
// Instead, use textContent or sanitized rendering pattern
window.renderHTML = function(html) {
  const contentElement = document.getElementById('content');
  if (!contentElement) return;
  // Basic sanitization: create a DOMParser and parse as text to avoid HTML injection
  const div = document.createElement('div');
  div.textContent = html;
  // Clear existing content
  contentElement.innerHTML = '';
  // Append a text node to avoid executing HTML content
  contentElement.appendChild(div);
};