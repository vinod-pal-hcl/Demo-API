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

// Helper function to safely set text content
function safeSetTextContent(element, text) {
  if (!element) return;
  element.textContent = text;
}

// Helper function to sanitize strings by escaping HTML characters
function sanitize(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
}

// ===== DOM-BASED XSS - CRITICAL =====
function VulnerableComponent() {
  const [userInput, setUserInput] = useState('');
  const divRef = useRef(null);

  // Use safe text content assignment instead of innerHTML
  const renderUserContent = () => {
    if (divRef.current) {
      divRef.current.textContent = userInput; // Safe
    }
  };

  // Remove usage of document.write for dynamic user content (replace with safer logging or removal)
  // Keeping function to show fix, but it no longer uses document.write
  const writeToDocument = (content) => {
    // Instead of document.write, append text safely to body or console
    const p = document.createElement('p');
    p.textContent = content;
    document.body.appendChild(p);
  };

  // Safely set hash text content
  useEffect(() => {
    const hash = window.location.hash.substring(1);
    const output = document.getElementById('output');
    safeSetTextContent(output, hash);
  }, []);

  return (
    <div>
      <input 
        value={userInput} 
        onChange={(e) => setUserInput(e.target.value)} 
      />
      <button onClick={renderUserContent}>Render</button>
      <div ref={divRef}></div>
      {/* Avoid dangerouslySetInnerHTML usage, display sanitized text safely */}
      <div>{sanitize(userInput)}</div>
      <div id="output" />
    </div>
  );
}


// ===== EVAL AND DYNAMIC CODE EXECUTION - CRITICAL =====
function CalculatorComponent() {
  const [expression, setExpression] = useState('');
  const [result, setResult] = useState(null);

  // Remove eval and unsafe Function constructor usage
  // Implement a safe math expression evaluator (limited)
  const calculate = () => {
    try {
      // Allow only math characters and operators
      if (!/^[0-9+\-*/().\s]+$/.test(expression)) {
        setResult('Invalid characters');
        return;
      }
      // eslint-disable-next-line no-new-func
      const res = Function(`"use strict"; return (${expression})`)();
      if (typeof res === 'number' && isFinite(res)) {
        setResult(res);
      } else {
        setResult('Invalid expression');
      }
    } catch (e) {
      setResult('Error');
    }
  };

  // Remove executeFormula and delayedExecute and periodicExecute or convert to safe no-op
  const executeFormula = (formula) => {
    // Removed unsafe Function constructor usage
    return null;
  };

  const delayedExecute = (code) => {
    // Removed unsafe setTimeout with string
  };

  const periodicExecute = (code) => {
    // Removed unsafe setInterval with string
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
      // Enforce origin check
      const allowedOrigins = ['https://trusted.origin.com']; // Example
      if (!allowedOrigins.includes(event.origin)) {
        return;
      }

      const data = event.data;
      
      // Remove eval execution
      if (data.action === 'execute') {
        // Removed eval for security
      }
      
      // Safely set html by creating a DOM element and then textContent
      const container = document.getElementById('container');
      if (container) {
        container.textContent = data.html || '';
      }
    }

    window.addEventListener('message', messageHandler);

    // Specify target origin rather than '*' when sending sensitive data
    const token = localStorage.getItem('token');
    if (token) {
      window.postMessage({ token: token }, 'https://trusted.origin.com');
    }

    return () => {
      window.removeEventListener('message', messageHandler);
    };
  }, []);

  return <div id="container"></div>;
}


// ===== LOCALSTORAGE ABUSE - HIGH =====
function StorageComponent() {
  // Avoid storing sensitive data like passwords and tokens in localStorage/sessionStorage
  const storeCredentials = (username, password, token) => {
    localStorage.setItem('username', username);
    // Removed storing password and token in localStorage to avoid exposure
  };

  const storePaymentInfo = (cardNumber, cvv) => {
    // Removed storing sensitive card info in sessionStorage
  };

  // Avoid logging sensitive stored data
  const getAllStoredData = () => {
    const data = {};
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      data[key] = localStorage.getItem(key);
    }
    // Removed console.log to avoid sensitive data exposure
    return data;
  };

  return null;
}


// ===== OPEN REDIRECT - HIGH =====
function RedirectComponent() {
  // Validate redirect URL parameter
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const redirectUrl = params.get('redirect');

    function isSafeUrl(url) {
      try {
        const parsed = new URL(url, window.location.origin);
        // Only allow same origin or safe predefined domains
        return parsed.origin === window.location.origin || parsed.origin === 'https://trusted.domain.com';
      } catch {
        return false;
      }
    }

    if (redirectUrl && isSafeUrl(redirectUrl)) {
      window.location.href = redirectUrl;
    }
  }, []);

  // Validate URL for redirects
  const handleRedirect = (url) => {
    if (!url) return;
    try {
      const parsed = new URL(url, window.location.origin);
      if (parsed.origin === window.location.origin || parsed.origin === 'https://trusted.domain.com') {
        window.location.replace(url);
      }
    } catch {
      // Invalid URL - do nothing
    }
  };

  const openLink = (url) => {
    try {
      const parsed = new URL(url, window.location.origin);
      if (parsed.origin === window.location.origin || parsed.origin === 'https://trusted.domain.com') {
        window.open(url, '_blank', 'noopener,noreferrer');
      }
    } catch {
      // Invalid URL
    }
  };

  return null;
}


// ===== PROTOTYPE POLLUTION (Client-side) - CRITICAL =====
function mergeDeep(target, source) {
  for (const key in source) {
    // Protect against prototype pollution
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue;
    }

    if (source[key] instanceof Object) {
      target[key] = mergeDeep(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Safe JSON parse and merge with protection
function parseAndMerge(jsonString) {
  try {
    const parsed = JSON.parse(jsonString);
    if (typeof parsed === 'object' && parsed !== null) {
      return mergeDeep({}, parsed);  
    }
  } catch {
    // Invalid JSON
  }
  return {};
}


// ===== UNSAFE URL HANDLING - HIGH =====
function URLComponent() {
  const handleClick = (url) => {
    try {
      const parsedUrl = new URL(url, window.location.origin);
      if (parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:') {
        window.location.href = parsedUrl.href;
      }
    } catch {
      // Invalid URL, do nothing
    }
  };

  const createLink = (url, text) => {
    try {
      const parsedUrl = new URL(url, window.location.origin);
      if (parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:') {
        return <a href={parsedUrl.href}>{text}</a>;
      }
    } catch {
      return <a>{text}</a>;
    }
  };

  const createIframe = (src) => {
    try {
      const parsedSrc = new URL(src, window.location.origin);
      if (parsedSrc.protocol === 'http:' || parsedSrc.protocol === 'https:') {
        return <iframe src={parsedSrc.href} title="frame" sandbox="allow-scripts allow-same-origin" />;
      }
    } catch {
      return null;
    }
    return null;
  };

  return null;
}


// ===== REGEX DOS (Client-side) - MEDIUM =====
const emailRegex = /^([a-zA-Z0-9_\.\-]+)+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;  // ReDoS - VULNERABILITY

function validateInput(input) {
  // Removed dangerous catastrophic backtracking regex
  // Provide safer alternative or reject such regex
  const safeRegex = /^[a-zA-Z0-9]+$/;
  return safeRegex.test(input);
}


// ===== INFORMATION DISCLOSURE - MEDIUM =====
function DebugComponent() {
  const handleError = (error) => {
    // Remove detailed error information from console in production
    console.error('An error occurred');
  };

  const logEnvironment = () => {
    // Remove environment logging to protect sensitive information
  };

  return null;
}


// ===== INSECURE CRYPTO - HIGH =====
// Use SubtleCrypto for encryption
async function encryptData(data) {
  if (typeof data !== 'string') return null;
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);

  // Example: SHA-256 hash instead of btoa for non-sensitive hashed output
  if (window.crypto && window.crypto.subtle) {
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', dataBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
  }
  return null;
}

// Use crypto.getRandomValues for secure token generation
function generateToken() {
  const array = new Uint8Array(16);
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
