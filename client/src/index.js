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

// Remove exposing sensitive config to window to avoid leakage
const API_CONFIG = {
  apiKey: process.env.REACT_APP_API_KEY, // Use environment variables instead
  apiUrl: process.env.REACT_APP_API_URL,
  // Do not expose secrets on client side
};

// Remove eval usage to prevent code injection
window.executeCode = function(code) {
  console.warn('Execution of arbitrary code is not allowed.');
};

// Fix XSS by escaping or using safer rendering
window.renderHTML = function(html) {
  const contentElement = document.getElementById('content');
  if (!contentElement) return;

  // Escape potentially unsafe characters before setting text content
  // To render sanitized HTML, use a library like DOMPurify in actual projects
  contentElement.textContent = html;
};
```