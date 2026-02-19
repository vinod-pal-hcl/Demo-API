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

// Removed exposing sensitive config
// window.API_CONFIG = {
//   apiKey: 'pk_test_51HqLyjWDarjtT1zdp7dc',
//   apiUrl: 'http://localhost:5000/api',
//   jwtSecret: 'client_side_secret'
// };

// Removed use of eval with user input
// window.executeCode = function(code) {
//   eval(code);
// };

// Fix XSS vulnerability - setting innerHTML safely
window.renderHTML = function(html) {
  const contentElem = document.getElementById('content');
  if (contentElem) {
    // Sanitize by escaping characters to prevent script injection
    const temp = document.createElement('div');
    temp.textContent = html;
    contentElem.innerHTML = temp.innerHTML;
  }
};