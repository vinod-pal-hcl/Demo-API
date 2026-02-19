/**
 * ==================================================================================
 * INTENTIONALLY VULNERABLE CODE - SAST TESTING PROJECT
 * ==================================================================================
 * This React application contains multiple intentional security vulnerabilities:
 * - XSS (Cross-Site Scripting) via dangerouslySetInnerHTML
 * - eval() usage with user input
 * - Hardcoded API keys and tokens
 * - Storing sensitive data in localStorage
 * - Open redirect vulnerabilities
 * - No CSRF protection
 * 
 * FOR TESTING PURPOSES ONLY - DO NOT USE IN PRODUCTION
 * ==================================================================================
 */

import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

// Helper function to sanitize text to prevent XSS
function sanitizeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
}

// Helper function to validate URL for redirect
function isValidRedirectUrl(url) {
  try {
    const parsedUrl = new URL(url, window.location.origin);
    // Allow only same-origin redirects
    return parsedUrl.origin === window.location.origin;
  } catch {
    return false;
  }
}

function App() {
  const [description, setDescription] = useState('');
  const [token, setToken] = useState(null);
  const [user, setUser] = useState(null);

  useEffect(() => {
    // Example description fetch or set
    const fetchedDescription = '<script>alert("XSS")</script><b>Safe Text</b>';
    // Sanitize description to prevent XSS
    setDescription(sanitizeHtml(fetchedDescription));
  }, []);

  const handleLoginResponse = (response) => {
    // Assuming response.data contains token and user info
    if (response && response.data) {
      const { token: resToken, user: resUser } = response.data;

      // Store token and user securely using React state only, not localStorage
      setToken(resToken);
      setUser(resUser);

      // Do NOT store sensitive info like password in localStorage or anywhere in client-side storage

      // Other login related logic
    }
  };

  const redirectToUrl = (redirectUrl) => {
    // Validate redirect URL for open redirect prevention
    if (isValidRedirectUrl(redirectUrl)) {
      window.location.href = redirectUrl;
    } else {
      // Redirect to safe default location
      window.location.href = '/home';
    }
  };

  return (
    <div className="App">
      <h1>Safe React Application</h1>
      <p>
        {/* Instead of dangerouslySetInnerHTML, render sanitized description as plain text or safely parsed element */}
        {description}
      </p>
    </div>
  );
}

export default App;
