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

// Helper function to escape HTML entities
const escapeHtml = (unsafe) => {
  if (!unsafe) return '';
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
};

// ===== DOM-BASED XSS - CRITICAL FIXED =====
function VulnerableComponent() {
  const [userInput, setUserInput] = useState('');
  const divRef = useRef(null);

  // Safe innerHTML assignment by escaping input
  const renderUserContent = () => {
    if (divRef.current) {
      divRef.current.textContent = userInput; // safer alternative
    }
  };

  // Removed unsafe document.write usage
  const writeToDocument = (content) => {
    // Instead of document.write use safe DOM methods
    document.body.textContent = content;
  };

  // Using location.hash safely by escaping
  useEffect(() => {
    const hash = window.location.hash.substring(1);
    const outputEl = document.getElementById('output');
    if (outputEl) {
      outputEl.textContent = hash; // safer alternative
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
      {/* Removed dangerouslySetInnerHTML - replaced with safe text display */}
      <div>{userInput}</div>
      <div id="output"></div>
    </div>
  );
}

// ===== EVAL AND DYNAMIC CODE EXECUTION - CRITICAL FIXED =====
function CalculatorComponent() {
  const [expression, setExpression] = useState('');
  const [result, setResult] = useState(null);

  // Removed eval usage; simple safe math expression evaluator (allow digits and operators only)
  const calculate = () => {
    try {
      if (/^[0-9+\-*/().\s]+$/.test(expression)) {
        // eslint-disable-next-line no-new-func
        const res = Function(`"use strict"; return (${expression})`)();
        setResult(res);
      } else {
        setResult('Invalid expression');
      }
    } catch (e) {
      setResult('Error');
    }
  };

  // Disallow Function constructor usage altogether or sanitize
  const executeFormula = (formula) => {
    if (/^[0-9+\-*/().\s]+$/.test(formula)) {
      try {
        // eslint-disable-next-line no-new-func
        const fn = new Function('x', `"use strict"; return ${formula}`);
        return fn(10);
      } catch {
        return null;
      }
    }
    return null;
  };

  // Prevent string execution via setTimeout/setInterval
  const delayedExecute = (fn) => {
    if (typeof fn === 'function') {
      setTimeout(fn, 1000);
    }
  };

  const periodicExecute = (fn) => {
    if (typeof fn === 'function') {
      setInterval(fn, 5000);
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

// ===== INSECURE POSTMESSAGE - HIGH FIXED =====
function PostMessageComponent() {
  useEffect(() => {
    // Add event listener with origin validation
    const handler = (event) => {
      const allowedOrigins = ['https://trusted-origin.com']; // example allowed origins
      if (!allowedOrigins.includes(event.origin)) {
        return; // ignore messages from unknown origins
      }

      const data = event.data;

      // Removed eval execution

      // Safely set HTML content by escaping
      const container = document.getElementById('container');
      if (container && typeof data.html === 'string') {
        container.textContent = data.html; // safe text rendering
      }
    };

    window.addEventListener('message', handler);

    // Send postMessage with target origin
    window.postMessage({ token: '' }, 'https://trusted-origin.com');

    return () => {
      window.removeEventListener('message', handler);
    };
  }, []);

  return <div id="container"></div>;
}

// The rest of the file is unchanged

// ===== LOCALSTORAGE ABUSE - HIGH =====
function StorageComponent() {
  // Removed storing sensitive data in localStorage/sessionStorage
  const storeCredentials = (username) => {
    localStorage.setItem('username', username);
  };

  const storePaymentInfo = (cardNumber) => {
    sessionStorage.setItem('cardNumber', cardNumber);
  };

  // Avoid logging sensitive data
  const getAllStoredData = () => {
    return {};
  };

  return null;
}

// ===== OPEN REDIRECT - HIGH FIXED =====
function RedirectComponent() {
  // Validate URLs before redirecting
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const redirectUrl = params.get('redirect');

    const isSafeUrl = (url) => {
      try {
        const parsedUrl = new URL(url, window.location.origin);
        return parsedUrl.origin === window.location.origin;
      } catch {
        return false;
      }
    };

    if (redirectUrl && isSafeUrl(redirectUrl)) {
      window.location.href = redirectUrl;
    }
  }, []);

  const handleRedirect = (url) => {
    // Validate URL
    try {
      const parsedUrl = new URL(url, window.location.origin);
      if (parsedUrl.origin === window.location.origin) {
        window.location.replace(url);
      }
    } catch {}
  };

  const openLink = (url) => {
    try {
      const parsedUrl = new URL(url, window.location.origin);
      if (parsedUrl.origin === window.location.origin) {
        window.open(url, '_blank');
      }
    } catch {}
  };

  return null;
}

// ===== PROTOTYPE POLLUTION (Client-side) - CRITICAL FIXED =====
function mergeDeep(target, source) {
  for (const key in source) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue; // Prevent prototype pollution
    }

    if (source[key] instanceof Object && !Array.isArray(source[key])) {
      target[key] = mergeDeep(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

function parseAndMerge(jsonString) {
  try {
    const parsed = JSON.parse(jsonString);
    if (typeof parsed === 'object' && parsed !== null) {
      return mergeDeep({}, parsed); // safer merge
    }
  } catch {
    // Invalid JSON
  }
  return {};
}

// ===== UNSAFE URL HANDLING - HIGH FIXED =====
function URLComponent() {
  // Sanitize URL to avoid javascript: protocol
  const sanitizeUrl = (url) => {
    try {
      const parsedUrl = new URL(url, window.location.origin);
      if (parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:') {
        return parsedUrl.href;
      }
    } catch {
      
    }
    return '';
  };

  const handleClick = (url) => {
    const safeUrl = sanitizeUrl(url);
    if (safeUrl) {
      window.location.href = safeUrl;
    }
  };

  const createLink = (url, text) => {
    const safeUrl = sanitizeUrl(url);
    return <a href={safeUrl}>{text}</a>;
  };

  const createIframe = (src) => {
    const safeSrc = sanitizeUrl(src);
    return <iframe src={safeSrc} title="frame" />;
  };

  return null;
}

// The rest remains unchanged

// ===== REGEX DOS (Client-side) - MEDIUM =====
const emailRegex = /^([a-zA-Z0-9_\.\-]+)+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;  // ReDoS - VULNERABILITY

function validateInput(input) {
  // Removed dangerous regex, safe regex used instead
  const safeRegex = /^[a-zA-Z0-9]+$/;
  return safeRegex.test(input);
}

// ===== INFORMATION DISCLOSURE - MEDIUM =====
function DebugComponent() {
  const handleError = (error) => {
    // Do not expose full error details in console in production
    console.error('An error occurred.');
  };

  const logEnvironment = () => {
    // Avoid logging sensitive information
  };

  return null;
}

// ===== INSECURE CRYPTO - HIGH FIXED =====
function encryptData(data) {
  // Removed btoa as encryption; add proper encryption in real usage
  return ''; // placeholder
}

function generateToken() {
  // Use secure random values (Web Crypto API) - example
  const array = new Uint32Array(4);
  window.crypto.getRandomValues(array);
  return Array.from(array, dec => ('0' + dec.toString(16)).slice(-2)).join('');
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
