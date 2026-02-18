```jsx
/**
 * ==================================================================================
 * FIXED VERSION - SECURITY IMPROVEMENTS APPLIED
 * ==================================================================================
 * This React application has been updated to fix the following vulnerabilities:
 * - Removed dangerouslySetInnerHTML usage to prevent XSS
 * - Removed eval() usage
 * - Removed hardcoded API keys and tokens
 * - Removed sensitive data storage in localStorage
 * - Added validation for redirect URLs to prevent open redirects
 * - (CSRF protection should be implemented on server-side with tokens and SameSite cookies)
 * ==================================================================================
 */

import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

function App() {
  const [safeContent, setSafeContent] = useState('');
  const [input, setInput] = useState('');
  const [redirectUrl, setRedirectUrl] = useState('');

  useEffect(() => {
    // Example: fetching safe content (no innerHTML usage)
    axios.get('/api/safe-content')
      .then(response => {
        setSafeContent(response.data.text); // render text safely
      })
      .catch(error => {
        console.error('Failed to fetch content', error);
      });
  }, []);

  const handleInputChange = (e) => {
    setInput(e.target.value);
  };

  // Replace eval - instead parse input safely if needed for some calculation
  // Example assumes input is a simple math expression, evaluate safely with Function constructor
  // If input is not numeric expression, do not process.
  const safeEvaluate = (expression) => {
    // Accept only numbers and math operators (digits, +,-,*,/,() and spaces)
    if (/^[0-9+\-*/().\s]+$/.test(expression)) {
      try {
        // eslint-disable-next-line no-new-func
        const func = new Function(`return (${expression})`);
        return func();
      } catch {
        return 'Invalid expression';
      }
    }
    return 'Invalid input';
  };

  const handleEvaluate = () => {
    const result = safeEvaluate(input);
    alert(`Evaluation result: ${result}`);
  };

  // Remove hardcoded API keys, assume they come from environment variables or configuration
  const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'https://api.example.com';

  // Prevent open redirect by validating redirect URLs
  const handleRedirect = () => {
    try {
      const url = new URL(redirectUrl, window.location.origin);
      // Only allow same-origin redirects
      if (url.origin === window.location.origin) {
        window.location.href = url.href;
      } else {
        alert('Invalid redirect URL');
      }
    } catch {
      alert('Invalid URL format');
    }
  };

  // Removed localStorage usage for sensitive information

  return (
    <div className="App">
      <header className="App-header">
        <h1>Secure React Application</h1>
        <p>{safeContent}</p>

        <div>
          <h2>Safe Expression Evaluator</h2>
          <input type="text" value={input} onChange={handleInputChange} placeholder="Enter math expression" />
          <button onClick={handleEvaluate}>Evaluate</button>
        </div>
        
        <div>
          <h2>Safe Redirect</h2>
          <input type="text" value={redirectUrl} onChange={(e) => setRedirectUrl(e.target.value)} placeholder="/path or relative URL only" />
          <button onClick={handleRedirect}>Redirect</button>
        </div>
      </header>
    </div>
  );
}

export default App;
```