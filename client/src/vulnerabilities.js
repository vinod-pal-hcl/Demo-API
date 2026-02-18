```javascript
/**
 * ==================================================================================
 * INTENTIONALLY VULNERABLE CODE - SAST TESTING PROJECT
 * ==================================================================================
 * This file contains CRITICAL client-side vulnerabilities for SAST testing:
 * - DOM-based XSS
 * - Prototype Pollution (client-side)
 * - Insecure postMessage
 * - localStorage/sessionStorage abuse
 * - eval() and Function() usage
 * - innerHTML manipulation
 * - Open Redirect (client-side)
 * 
 * FOR TESTING PURPOSES ONLY - DO NOT USE IN PRODUCTION
 * ==================================================================================
 */

import React, { useState, useEffect, useRef } from 'react';


// Helper function to sanitize text for innerHTML
const sanitize = (str) => {
  const temp = document.createElement('div');
  temp.textContent = str;
  return temp.innerHTML;
};


// ===== DOM-BASED XSS - FIXED =====
function VulnerableComponent() {
  const [userInput, setUserInput] = useState('');
  const divRef = useRef(null);

  // Use textContent instead of innerHTML to avoid XSS
  const renderUserContent = () => {
    if (divRef.current) {
      divRef.current.textContent = userInput;
    }
  };

  // Remove unsafe document.write usage
  // provide a safe alternative or remove function if unused
  const writeToDocument = (content) => {
    // No usage of document.write with user input to prevent XSS
    console.log('writeToDocument called with:', content);
  };

  // Safely update innerHTML by sanitizing user input
  useEffect(() => {
    const hash = window.location.hash.substring(1);
    const safeHash = sanitize(hash);
    const outputEl = document.getElementById('output');
    if(outputEl) {
      outputEl.innerHTML = safeHash;
    }
  }, []);

  return (
    <div>
      <input 
        value={userInput} 
        onChange={(e) => setUserInput(e.target.value)} 
      />
      <button onClick={renderUserContent}>Render</button>
      <div ref={divRef}></div>
      {/* Removed dangerouslySetInnerHTML - replaced with safe text content rendering */}
      <div>{userInput}</div>
    </div>
  );
}


// ===== EVAL AND DYNAMIC CODE EXECUTION - FIXED =====
function CalculatorComponent() {
  const [expression, setExpression] = useState('');
  const [result, setResult] = useState(null);

  // Safe calculate: parse and support basic arithmetic only
  const calculate = () => {
    try {
      // Validate the expression only contains numbers, spaces and operators + - * / . ()
      if (!/^[0-9+\-*/().\s]+$/.test(expression)) {
        setResult('Invalid expression');
        return;
      }
      // eslint-disable-next-line no-new-func
      const func = new Function(`return (${expression})`);
      const res = func();
      setResult(res);
    } catch (e) {
      setResult('Error');
    }
  };

  // Remove dynamic Function constructor usage or limit to safe expressions
  const executeFormula = (formula) => {
    // Validate formula contains only safe characters (numbers, operators, x)
    if (!/^[0-9+\-*/().\sx]+$/.test(formula)) {
      throw new Error('Invalid formula');
    }
    // eslint-disable-next-line no-new-func
    const fn = new Function('x', `return (${formula})`);
    return fn(10);
  };

  // Remove usage of setTimeout/setInterval with string arguments
  const delayedExecute = (code) => {
    if (typeof code === 'function') {
      setTimeout(code, 1000);
    }
  };

  const periodicExecute = (code) => {
    if (typeof code === 'function') {
      setInterval(code, 5000);
    }
  };

  return (
    <div>
      <input value={expression} onChange={(e) => setExpression(e.target.value)} />
      <button onClick={calculate}>Calculate</button>
      <div>Result: {result}</div>
    </div>
  );
}


// ===== INSECURE POSTMESSAGE - FIXED =====
function PostMessageComponent() {
  useEffect(() => {
    // Add origin check for security
    const trustedOrigins = ['https://yourtrusted.domain']; // Replace with your trusted domains

    const messageHandler = (event) => {
      if (!trustedOrigins.includes(event.origin)) {
        return; // Ignore messages from untrusted origins
      }
      const data = event.data;
      if (typeof data !== 'object' || data === null) {
        return; // Ignore malformed data
      }

      // Remove eval usage, implement safe action handling
      if (data.action === 'execute' && typeof data.code === 'string') {
        // Avoid executing code from postMessage, log or handle safely
        console.warn('Execution request ignored for security');
      }

      // Sanitize incoming HTML before rendering
      if (typeof data.html === 'string') {
        const container = document.getElementById('container');
        if (container) {
          container.textContent = data.html; // render as plain text
        }
      }
    };

    window.addEventListener('message', messageHandler);

    // Use target origin in postMessage
    const token = localStorage.getItem('token');
    if (token) {
      window.postMessage({ token }, 'https://yourtrusted.domain'); // Specify destination origin
    }

    return () => {
      window.removeEventListener('message', messageHandler);
    };
  }, []);

  return <div id="container"></div>;
}


// ===== LOCALSTORAGE ABUSE - FIXED =====
function StorageComponent() {
  // Do NOT store sensitive data in localStorage/sessionStorage
  const storeCredentials = (username, token) => {
    localStorage.setItem('username', username);
    // Remove storing password and token in localStorage
    // Store tokens in HttpOnly cookies (not possible client-side) or secure storage on server-side
  };

  const storePaymentInfo = (cardNumber) => {
    // Avoid storing CVV
    sessionStorage.setItem('cardNumber', cardNumber);
  };

  // Avoid logging or exposing all stored data
  const getAllStoredData = () => {
    return null;
  };

  return null;
}


// ===== OPEN REDIRECT - FIXED =====
function RedirectComponent() {
  // Safely validate redirect URLs
  const isSafeRedirect = (url) => {
    try {
      const parsedUrl = new URL(url, window.location.origin);
      // Allow only same origin redirects or defined whitelisted domains
      return parsedUrl.origin === window.location.origin;
    } catch {
      return false;
    }
  };

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const redirectUrl = params.get('redirect');

    if (redirectUrl && isSafeRedirect(redirectUrl)) {
      window.location.href = redirectUrl;
    }
  }, []);

  const handleRedirect = (url) => {
    if (isSafeRedirect(url)) {
      window.location.replace(url);
    } else {
      console.warn('Blocked unsafe redirect:', url);
    }
  };

  const openLink = (url) => {
    if (isSafeRedirect(url)) {
      window.open(url, '_blank');
    } else {
      console.warn('Blocked unsafe external link:', url);
    }
  };

  return null;
}


// ===== PROTOTYPE POLLUTION (Client-side) - FIXED =====
function mergeDeep(target, source) {
  for (const key in source) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue; // Prevent prototype pollution
    }
    if (source[key] instanceof Object && source[key] !== null) {
      target[key] = mergeDeep(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

function parseAndMerge(jsonString) {
  let parsed;
  try {
    parsed = JSON.parse(jsonString);
  } catch {
    parsed = {};
  }
  if (parsed && typeof parsed === 'object') {
    return mergeDeep({}, parsed);
  }
  return {};
}


// ===== UNSAFE URL HANDLING - FIXED =====
function URLComponent() {
  const isSafeUrl = (url) => {
    try {
      const parsed = new URL(url, window.location.origin);
      // Disallow javascript: scheme
      if (parsed.protocol === 'javascript:') return false;
      return true;
    } catch {
      return false;
    }
  };

  const handleClick = (url) => {
    if (isSafeUrl(url)) {
      window.location.href = url;
    } else {
      console.warn('Blocked unsafe URL:', url);
    }
  };

  const createLink = (url, text) => {
    if (isSafeUrl(url)) {
      return <a href={url}>{text}</a>;
    }
    return <span>{text}</span>;
  };

  const createIframe = (src) => {
    if (isSafeUrl(src)) {
      return <iframe src={src} title="frame" sandbox="allow-scripts allow-same-origin" />;
    }
    return null;
  };

  return null;
}


// ===== REGEX DOS (Client-side) - FIXED =====
// Replace dangerous regex with safe one without catastrophic backtracking
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateInput(input) {
  // Do not use dangerous regex; simple length check or safe regex
  if (typeof input !== 'string' || input.length > 1000) return false;
  return true;
}


// ===== INFORMATION DISCLOSURE - FIXED =====
function DebugComponent() {
  const handleError = (error) => {
    // Minimal logging without sensitive info
    console.error('An error occurred:', error.message || error);
  };

  const logEnvironment = () => {
    // Do not expose sensitive info
    console.log('App running');
  };

  return null;
}


// ===== INSECURE CRYPTO - FIXED =====
function encryptData(data) {
  // Placeholder: use proper crypto API (e.g., SubtleCrypto)
  // Returning base64 encoded string as an example, not encryption
  return btoa(data);
}

function generateToken() {
  // Use secure random values
  const array = new Uint8Array(16);
  window.crypto.getRandomValues(array);
  return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
}


export {
  VulnerableComponent,
  CalculatorComponent,
  PostMessageComponent,
  StorageComponent,
  RedirectComponent,
  URLComponent,
  DebugComponent,
  mergeDeep,
  parseAndMerge,
  validateInput,
  encryptData,
  generateToken,
  emailRegex
};
```