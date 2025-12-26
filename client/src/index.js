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
  eval(code);
};

// XSS vulnerability - setting innerHTML - VULNERABILITY
window.renderHTML = function(html) {
  document.getElementById('content').innerHTML = html;
};
