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

// Exposing sensitive config - VULNERABILITY (Not fixed here as the request is to fix XSS)
window.API_CONFIG = {
  apiKey: 'pk_test_51HqLyjWDarjtT1zdp7dc',
  apiUrl: 'http://localhost:5000/api',
  jwtSecret: 'client_side_secret'
};

// Using eval with user input - VULNERABILITY
window.executeCode = function(code) {
  // Removed eval usage to prevent code injection
  console.warn('Execution of dynamic code is disabled for security reasons.');
};

// Fixed XSS vulnerability - setting innerHTML safely
window.renderHTML = function(html) {
  const contentElement = document.getElementById('content');
  if (!contentElement) return;
  // Sanitizing the html input by escaping special characters
  const div = document.createElement('div');
  div.textContent = html;
  contentElement.innerHTML = div.innerHTML;
};