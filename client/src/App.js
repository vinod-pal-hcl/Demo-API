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
  const [description, setDescription] = useState("");
  const [token, setToken] = useState("");
  const [user, setUser] = useState(null);
  const [password, setPassword] = useState("");
  const [redirectUrl, setRedirectUrl] = useState("");

  useEffect(() => {
    // Example fetching description
    // Simulate fetching and sanitizing
    const unsafeDescription = '<img src=x onerror=alert(1) />';
    const sanitizedDescription = DOMPurify.sanitize(unsafeDescription);
    setDescription(sanitizedDescription);
  }, []);

  const handleLoginResponse = (response) => {
    // Validate and handle tokens securely, do not store sensitive info in localStorage
    // Use sessionStorage as less persistent, or better state management
    if (response.data && response.data.token && typeof response.data.token === 'string') {
      setToken(response.data.token); // Store token in memory state instead of localStorage
    }
    if (response.data && response.data.user) {
      setUser(response.data.user);
    }
    // Password should never be stored client-side
  };

  const safeRedirect = (url) => {
    try {
      const trustedBase = window.location.origin;
      const parsedUrl = new URL(url, trustedBase);
      // Only allow redirects within the same origin
      if (parsedUrl.origin === trustedBase) {
        window.location.href = parsedUrl.href;
      } else {
        console.warn('Blocked untrusted redirect:', url);
      }
    } catch(e) {
      console.warn('Invalid redirect URL:', url);
    }
  };

  // Component rendering
  return (
    <div>
      {/* Render sanitized HTML description */}
      <div dangerouslySetInnerHTML={{ __html: description }} />

      {/* Login form example */}
      <form onSubmit={async (e) => {
        e.preventDefault();
        // Simulated login request
        try {
          const response = await axios.post('/api/login', { password });
          handleLoginResponse(response);
        } catch (error) {
          console.error('Login failed', error);
        }
      }}>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Password"
          autoComplete="off"
        />
        <button type="submit">Login</button>
      </form>

      {/* Redirect button example */}
      <button onClick={() => safeRedirect(redirectUrl)}>Redirect</button>
      <input
        type="text"
        value={redirectUrl}
        onChange={(e) => setRedirectUrl(e.target.value)}
        placeholder="Enter redirect URL"
      />
    </div>
  );
}

export default App;
