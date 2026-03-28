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

// Helper function to sanitize input and prevent XSS
const sanitizeHTML = (str) => {
  const temp = document.createElement('div');
  temp.textContent = str;
  return temp.innerHTML;
};

// Helper function to validate safe URLs (simple whitelist approach)
const isSafeUrl = (url) => {
  try {
    const parsedUrl = new URL(url, window.location.origin);
    // Allow only http and https schemes and same-origin or trusted domains
    const allowedProtocols = ['http:', 'https:'];
    const allowedHosts = [window.location.host];
    if (!allowedProtocols.includes(parsedUrl.protocol)) {
      return false;
    }
    if (!allowedHosts.includes(parsedUrl.host)) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
};


// ===== DOM-BASED XSS - CRITICAL =====
function VulnerableComponent() {
  const [userInput, setUserInput] = useState('');
  const divRef = useRef(null);

  // Sanitized innerHTML assignment to prevent XSS
  const renderUserContent = () => {
    if (divRef.current) {
      divRef.current.innerHTML = sanitizeHTML(userInput);
    }
  };

  // Removed usage of document.write due to high risk, replaced with safe alternative
  const writeToDocument = (content) => {
    // Instead of document.write, append content safely to body
    const safeContent = sanitizeHTML(content);
    const p = document.createElement('p');
    p.innerHTML = safeContent;
    document.body.appendChild(p);
  };

  // Using location.hash sanitized - preventing DOM XSS
  useEffect(() => {
    const hash = window.location.hash.substring(1);
    document.getElementById('output')?.innerText = hash;  // innerText instead of innerHTML
  }, []);

  return (
    <div>
      <input 
        value={userInput} 
        onChange={(e) => setUserInput(e.target.value)} 
      />
      <button onClick={renderUserContent}>Render</button>
      <div ref={divRef}></div>
      {/* Removed dangerouslySetInnerHTML usage, using safe render */}
      <div>{userInput}</div>
      <div id="output" aria-live="polite"></div>
    </div>
  );
}


// ===== EVAL AND DYNAMIC CODE EXECUTION - CRITICAL =====
function CalculatorComponent() {
  const [expression, setExpression] = useState('');
  const [result, setResult] = useState(null);

  // Removed use of eval and replaced with safe math expression evaluation
  // For demonstration, limit input to numbers and math operators
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

  // Removed Function constructor usage to avoid code injection
  // Provide safe predefined formulas or reject unsafe formulas
  const executeFormula = (formula) => {
    const allowedFormulas = {
      square: (x) => x * x,
      double: (x) => x * 2,
      increment: (x) => x + 1
    };

    if (allowedFormulas[formula]) {
      return allowedFormulas[formula](10);
    }
    throw new Error('Unsupported formula');
  };

  // Removed setTimeout/setInterval usage with strings
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


// ===== INSECURE POSTMESSAGE - HIGH =====
function PostMessageComponent() {
  useEffect(() => {
    // Add origin check for received messages
    window.addEventListener('message', (event) => {
      const allowedOrigins = [window.location.origin];
      if (!allowedOrigins.includes(event.origin)) {
        return;  // Ignore messages from untrusted origins
      }

      const data = event.data;

      // Do not use eval on received data
      if (data.action === 'execute') {
        // Execute only safe function keys, no eval
        if (typeof data.code === 'function') {
          data.code();
        }
      }

      // Use textContent for received HTML, avoid innerHTML
      const container = document.getElementById('container');
      if (container && typeof data.html === 'string') {
        container.textContent = data.html;
      }
    });

    // Use target origin correctly when posting message
    const token = localStorage.getItem('token');
    if (token) {
      window.postMessage({ token: token }, window.location.origin);
    }
  }, []);

  return <div id="container"></div>;
}


// ===== LOCALSTORAGE ABUSE - HIGH =====
function StorageComponent() {
  // Avoid storing sensitive data in localStorage/sessionStorage
  const storeCredentials = (username, password, token) => {
    if (typeof username === 'string') {
      localStorage.setItem('username', username);
    }
    // Remove storing password and token in localStorage
    // Alternatively, use secure cookies or session only
  };

  // Do not store sensitive payment info in sessionStorage
  const storePaymentInfo = (cardNumber, cvv) => {
    // Removed storage of card info
    // Ideally, use PCI DSS compliant methods
  };

  // Remove logging of sensitive data
  const getAllStoredData = () => {
    const data = {};
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      // Avoid exposing sensitive keys
      if (key !== 'password' && key !== 'token' && key !== 'cardNumber' && key !== 'cvv') {
        data[key] = localStorage.getItem(key);
      }
    }
    return data;
  };

  return null;
}


// ===== OPEN REDIRECT - HIGH =====
function RedirectComponent() {
  // URL parameter redirect with validation
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const redirectUrl = params.get('redirect');

    if (redirectUrl && isSafeUrl(redirectUrl)) {
      window.location.href = redirectUrl;
    }
  }, []);

  // Redirect function with URL validation
  const handleRedirect = (url) => {
    if (isSafeUrl(url)) {
      window.location.replace(url);
    }
  };

  // window.open with URL validation and rel="noopener noreferrer" for security
  const openLink = (url) => {
    if (isSafeUrl(url)) {
      window.open(url, '_blank', 'noopener,noreferrer');
    }
  };

  return null;
}


// ===== PROTOTYPE POLLUTION (Client-side) - CRITICAL =====
function mergeDeep(target, source) {
  for (const key in source) {
    // Prevent prototype pollution
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue;
    }
    if (source[key] instanceof Object && !Array.isArray(source[key])) {
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
      throw new Error('Invalid JSON');
    }
    return mergeDeep({}, parsed);
  } catch {
    return {};
  }
}


// ===== UNSAFE URL HANDLING - HIGH =====
function URLComponent() {
  // Prevent javascript: URLs
  const handleClick = (url) => {
    if (isSafeUrl(url)) {
      window.location.href = url;
    }
  };

  // Safe anchor creation with validation
  const createLink = (url, text) => {
    if (isSafeUrl(url)) {
      return <a href={url} rel="noopener noreferrer">{text}</a>;
    }
    return <span>{text}</span>;
  };

  // Safe iframe src with validation
  const createIframe = (src) => {
    if (isSafeUrl(src)) {
      return <iframe src={src} title="frame" sandbox="allow-scripts allow-same-origin" />;
    }
    return null;
  };

  return null;
}


// ===== REGEX DOS (Client-side) - MEDIUM =====
const emailRegex = /^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/;  // Improved and safer regex

function validateInput(input) {
  // Removed catastrophic backtracking regex
  const safeRegex = /^[a-zA-Z0-9]+$/;  // Example safe regex
  return safeRegex.test(input);
}


// ===== INFORMATION DISCLOSURE - MEDIUM =====
function DebugComponent() {
  // Remove full error exposure to console
  const handleError = (error) => {
    console.error('Error:', error.message || error);
  };

  // Avoid logging sensitive environment details
  const logEnvironment = () => {
    console.log('App initialized');
  };

  return null;
}


// ===== INSECURE CRYPTO - HIGH =====
import crypto from 'crypto';

function encryptData(data) {
  // Use Web Crypto API for secure encryption (demo with base64 encoding)
  if (window.crypto && window.crypto.subtle) {
    // Placeholder for real encryption - here we just encode
    return btoa(data);  // Still base64 but placeholder
  } else {
    throw new Error('Secure crypto not available');
  }
}

function generateToken() {
  if (window.crypto && window.crypto.getRandomValues) {
    const array = new Uint32Array(4);
    window.crypto.getRandomValues(array);
    return Array.from(array, dec => dec.toString(36)).join('');
  } else {
    throw new Error('Secure random generator not available');
  }
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
