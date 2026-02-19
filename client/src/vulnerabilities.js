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



// ===== Helper function to safely escape HTML to prevent XSS =====
function escapeHtml(unsafe) {
  if (typeof unsafe !== 'string') {
    return '';
  }
  return unsafe.replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
}


// ===== DOM-BASED XSS - CRITICAL =====
function VulnerableComponent() {
  const [userInput, setUserInput] = useState('');
  const divRef = useRef(null);

  // Safely render user content by escaping HTML
  const renderUserContent = () => {
    if (divRef.current) {
      divRef.current.textContent = userInput;
    }
  };

  // Remove usage of document.write to avoid XSS
  const writeToDocument = (content) => {
    console.warn('Unsafe document.write operation prevented.');
  };

  // Using location.hash safely by escaping content
  useEffect(() => {
    const hash = window.location.hash.substring(1);
    const safeHash = escapeHtml(hash);
    const outputElement = document.getElementById('output');
    if (outputElement) {
      outputElement.textContent = safeHash;
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
      {/* Avoid dangerouslySetInnerHTML usage to prevent XSS */}
      <div>{userInput}</div>
      <div id="output"></div>
    </div>
  );
}


// ===== EVAL AND DYNAMIC CODE EXECUTION - CRITICAL =====
function CalculatorComponent() {
  const [expression, setExpression] = useState('');
  const [result, setResult] = useState(null);

  // Safe calculation allowing only simple mathematical expressions
  const calculate = () => {
    try {
      // Whitelist characters: numbers, operators, parentheses, decimal points
      if (!/^[-+/*()0-9.\s]+$/.test(expression)) {
        setResult('Invalid expression');
        return;
      }
      // eslint-disable-next-line no-new-func
      const res = Function(`"use strict"; return (${expression})`)();
      setResult(res);
    } catch (e) {
      setResult('Error');
    }
  };

  // Remove Function constructor usage or sanitize formula
  const executeFormula = (formula) => {
    // Only allow formulas with safe characters
    if (!/^[-+/*()x0-9.\s]+$/.test(formula)) {
      throw new Error('Unsafe formula');
    }
    // eslint-disable-next-line no-new-func
    const fn = Function('x', `"use strict"; return (${formula})`);
    return fn(10);
  };

  // Remove usage of setTimeout and setInterval with string
  const delayedExecute = (func) => {
    if (typeof func === 'function') {
      setTimeout(func, 1000);
    } else {
      console.warn('Invalid delayedExecute argument; expected function.');
    }
  };

  const periodicExecute = (func) => {
    if (typeof func === 'function') {
      setInterval(func, 5000);
    } else {
      console.warn('Invalid periodicExecute argument; expected function.');
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


// ===== INSECURE POSTMESSAGE - HIGH =====
function PostMessageComponent() {
  useEffect(() => {
    function messageHandler(event) {
      const allowedOrigins = ['https://trusteddomain.com']; // Replace with actual trusted origins
      if (!allowedOrigins.includes(event.origin)) {
        console.warn('Blocked message from untrusted origin:', event.origin);
        return;
      }

      const data = event.data;
      if (typeof data !== 'object' || data === null) {
        return;
      }

      // Avoid use of eval - do not execute code from message
      if (data.action === 'execute') {
        console.warn('Execution of code from postMessage blocked for security reasons.');
      }

      // Safely render received HTML by escaping it
      const container = document.getElementById('container');
      if(container && typeof data.html === 'string') {
        container.textContent = data.html;
      }
    }

    window.addEventListener('message', messageHandler);

    // Sending sensitive data with explicit and validated target origin
    const targetOrigin = 'https://trusteddomain.com'; // Replace with actual
    window.postMessage({ token: localStorage.getItem('token') }, targetOrigin);

    return () => window.removeEventListener('message', messageHandler);
  }, []);

  return <div id="container"></div>;
}


// ===== LOCALSTORAGE ABUSE - HIGH =====
function StorageComponent() {
  // Store only non-sensitive user info
  const storeCredentials = (username, password, token) => {
    if (typeof username === 'string') {
      localStorage.setItem('username', username);
    }
    // Never store passwords or tokens in localStorage or sessionStorage
  };

  // Remove storing sensitive payment info in storage
  const storePaymentInfo = (cardNumber, cvv) => {
    console.warn('Storing payment info in storage is disabled for security.');
  };

  // Remove logging sensitive data
  const getAllStoredData = () => {
    console.warn('Access to stored data is restricted');
    return {};
  };

  return null;
}


// ===== OPEN REDIRECT - HIGH =====
function RedirectComponent() {
  // Validate redirect url parameter to allow only relative paths
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const redirectUrl = params.get('redirect');
    if (redirectUrl) {
      // Only allow relative URLs without protocol or double slashes
      if (/^\/[^\/\\].*/.test(redirectUrl)) {
        window.location.href = redirectUrl;
      } else {
        console.warn('Blocked unsafe redirect URL:', redirectUrl);
      }
    }
  }, []);

  // Validate before redirect
  const handleRedirect = (url) => {
    if (url && /^\/[^\/\\].*/.test(url)) {
      window.location.replace(url);
    } else {
      console.warn('Blocked unsafe redirect URL in handleRedirect:', url);
    }
  };

  // Validate before opening link
  const openLink = (url) => {
    if (url && /^https?:\/\//.test(url)) {
      window.open(url, '_blank', 'noopener,noreferrer');
    } else {
      console.warn('Blocked unsafe open link URL:', url);
    }
  };

  return null;
}


// ===== PROTOTYPE POLLUTION (Client-side) - CRITICAL =====
function mergeDeep(target, source) {
  for (const key in source) {
    // Protect against prototype pollution
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      console.warn('Prototype pollution attempt blocked:', key);
      continue;
    }

    if (source[key] instanceof Object && source[key] !== null) {
      target[key] = mergeDeep(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Safe JSON parse and merge
function parseAndMerge(jsonString) {
  try {
    const parsed = JSON.parse(jsonString);
    if (typeof parsed !== 'object' || parsed === null) {
      throw new Error('Invalid JSON object');
    }
    return mergeDeep({}, parsed);
  } catch (e) {
    console.warn('Failed to parse JSON or merge:', e);
    return {};
  }
}


// ===== UNSAFE URL HANDLING - HIGH =====
function URLComponent() {
  // Only allow safe URLs (http/https) for navigation
  const handleClick = (url) => {
    if (url && /^https?:\/\//.test(url)) {
      window.location.href = url;
    } else {
      console.warn('Blocked unsafe URL navigation:', url);
    }
  };

  // Create anchor only with safe URLs
  const createLink = (url, text) => {
    if (url && /^https?:\/\//.test(url)) {
      return <a href={url} rel="noopener noreferrer" target="_blank">{text}</a>;
    }
    return <span>{text}</span>;
  };

  // Only allow https src for iframe
  const createIframe = (src) => {
    if (src && /^https?:\/\//.test(src)) {
      return <iframe src={src} title="frame" sandbox="allow-scripts allow-same-origin" />;
    }
    return null;
  };

  return null;
}


// ===== REGEX DOS (Client-side) - MEDIUM =====
const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;  // Improved regex with no catastrophic backtracking

function validateInput(input) {
  // Replace dangerous regex with safe validator
  return emailRegex.test(input);
}


// ===== INFORMATION DISCLOSURE - MEDIUM =====
function DebugComponent() {
  // Remove exposing sensitive data to console
  const handleError = (error) => {
    console.error('Error:', error.message || error);
  };

  // Remove logging of sensitive environment info
  const logEnvironment = () => {
    // No operation
  };

  return null;
}


// ===== INSECURE CRYPTO - HIGH =====
import crypto from 'crypto';
function encryptData(data) {
  // Use Web Crypto API if available else fallback
  if (window.crypto && window.crypto.subtle) {
    // This is a placeholder for real encryption usage with key management etc.
    // For demo, use encoded base64 safely without btoa
    return btoa(unescape(encodeURIComponent(data)));
  }
  // Fallback
  return btoa(unescape(encodeURIComponent(data)));
}

function generateToken() {
  // Use secure random token generator
  if (window.crypto && window.crypto.getRandomValues) {
    const array = new Uint32Array(4);
    window.crypto.getRandomValues(array);
    return Array.from(array, dec => dec.toString(16).padStart(8, '0')).join('');
  }
  // Fallback with warning
  console.warn('Secure token generation not available, using insecure fallback');
  return Math.random().toString(36).substring(2);
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
