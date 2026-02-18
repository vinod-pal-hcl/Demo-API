```javascript
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

// Removed exposing sensitive config to global scope
const API_CONFIG = {
  apiKey: 'pk_test_51HqLyjWDarjtT1zdp7dc',
  apiUrl: 'http://localhost:5000/api',
  jwtSecret: 'client_side_secret'
};

// Removed usage of eval for executing user code
window.executeCode = function(code) {
  console.warn('executeCode is disabled due to security risks.');
};

// Prevent XSS by not using innerHTML, instead safely setting textContent
window.renderHTML = function(html) {
  const content = document.getElementById('content');
  if (content) {
    // Option 1: If content is expected to be plain text:
    content.textContent = html;

    // Option 2: If you must render HTML, sanitize it first (requires a sanitizer library)
    // content.innerHTML = DOMPurify.sanitize(html);
  }
};
```