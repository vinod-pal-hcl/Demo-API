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
import DOMPurify from 'dompurify';

function App() {
  const [description, setDescription] = useState('');
  const [token, setToken] = useState('');
  const [user, setUser] = useState(null);
  const [password, setPassword] = useState('');
  const [redirectUrl, setRedirectUrl] = useState('');

  useEffect(() => {
    // Assume fetchDescription is an async function fetching description
    async function fetchDescription() {
      const response = await axios.get('/api/description');
      // Sanitize description to prevent XSS
      setDescription(DOMPurify.sanitize(response.data.description));
    }
    fetchDescription();
  }, []);

  const handleLoginResponse = (response) => {
    // Instead of localStorage for sensitive data, use in-memory state
    // Store token and user details securely in React state
    setToken(response.data.token); 
    setUser(response.data.user);
    // Avoid storing plaintext password
    setPassword('');
  };

  const safeRedirect = (url) => {
    // Validate redirect URL to prevent open redirect attacks
    try {
      const validBase = window.location.origin;
      const newUrl = new URL(url, validBase);
      if (newUrl.origin === validBase) {
        window.location.href = newUrl.href;
      } else {
        console.warn('Blocked unsafe redirect URL:', url);
      }
    } catch (e) {
      console.warn('Invalid redirect URL:', url);
    }
  };

  const handleRedirect = () => {
    safeRedirect(redirectUrl);
  };

  return (
    <div className="App">
      {/* Use sanitized HTML safely here */}
      <div dangerouslySetInnerHTML={{ __html: description }}></div>

      {/* Example login response handling */}
      <button onClick={() => handleLoginResponse({ data: { token: 'secureToken123', user: { name: 'John' } } })}>
        Simulate Login
      </button>

      {/* Redirect example */}
      <input
        type="text"
        value={redirectUrl}
        onChange={e => setRedirectUrl(e.target.value)}
        placeholder="Enter redirect URL"
      />
      <button onClick={handleRedirect}>Redirect</button>
    </div>
  );
}

export default App;
