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
  const [redirectUrl, setRedirectUrl] = useState('');
  const [token, setToken] = useState('');
  const [user, setUser] = useState(null);

  // Example function to safely set HTML content
  const createSafeHTML = (html) => {
    const cleanHTML = DOMPurify.sanitize(html);
    return { __html: cleanHTML };
  };

  const handleLoginResponse = (response) => {
    // Remove storing sensitive data directly in localStorage
    // Instead, store only non-sensitive data or use secure httpOnly cookies (not possible directly in frontend)
    if(response.data.token) {
      setToken(response.data.token); // Managing token in React state
    }
    if(response.data.user) {
      setUser(response.data.user); // Managing user in React state
    }
    // Do NOT store plaintext password in localStorage
  };

  const isSafeRedirectUrl = (url) => {
    try {
      const parsedUrl = new URL(url, window.location.origin);
      // Only allow same-origin redirects
      return parsedUrl.origin === window.location.origin;
    } catch (e) {
      return false;
    }
  };

  const handleRedirect = (url) => {
    if(isSafeRedirectUrl(url)) {
      window.location.href = url;
    } else {
      // Redirect to safe default location
      window.location.href = '/';
    }
  };

  // Example JSX with safe HTML rendering
  return (
    <div className="App">
      <h1>My Secure App</h1>
      <div className="description" dangerouslySetInnerHTML={createSafeHTML(description)} />
      {/* The rest of the app components */}
    </div>
  );
}

export default App;
