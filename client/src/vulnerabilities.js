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




// ===== DOM-BASED XSS - CRITICAL =====
function VulnerableComponent() {
  const [userInput, setUserInput] = useState('');
  const divRef = useRef(null);

  // Use textContent instead of innerHTML to prevent XSS
  const renderUserContent = () => {
    if (divRef.current) {
      divRef.current.textContent = userInput;
    }
  };

  // Remove document.write usage
  // Disabled writeToDocument or replace with safe alternative
  const writeToDocument = (content) => {
    const safeContent = document.createTextNode(content);
    document.body.appendChild(safeContent);
  };

  // Using location.hash safely by escaping
  useEffect(() => {
    const hash = window.location.hash.substring(1);
    // Escape special characters for safe insertion
    const outputElement = document.getElementById('output');
    if(outputElement) {
      outputElement.textContent = hash;
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
      {/* Remove dangerouslySetInnerHTML */}
      <div>{userInput}</div>
    </div>
  );
}


// ===== EVAL AND DYNAMIC CODE EXECUTION - CRITICAL =====
function CalculatorComponent() {
  const [expression, setExpression] = useState('');
  const [result, setResult] = useState(null);

  // Remove eval(), use safer math expression parser or limit to safe math
  // Simple safe evaluator for demonstration (supports +, -, *, / only)
  const calculate = () => {
    try {
      // Validate expression against allowed characters only
      if (!/^[0-9+\-*/().\s]+$/.test(expression)) {
        throw new Error('Invalid characters in expression');
      }
      // eslint-disable-next-line no-new-func
      const res = Function(`"use strict"; return (${expression})`)();
      setResult(res);
    } catch (e) {
      setResult('Error');
    }
  };

  // Remove Function constructor usage
  const executeFormula = (formula) => {
    // Do not use dynamic Function,
    // alternatively parse formula or reject unsafe inputs
    return null; // Disabled for safety
  };

  // Remove setTimeout/setInterval with string, accept function only
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
    const messageHandler = (event) => {
      // Validate origin strictly
      const allowedOrigins = ['https://trusted-origin.com']; // example allowed origins
      if (!allowedOrigins.includes(event.origin)) {
        return; // Ignore messages from unknown origins
      }

      const data = event.data;

      if (data.action === 'execute') {
        // Remove eval or dynamic execution
        console.warn('Execute action is disabled for security reasons');
      }

      // Avoid innerHTML usage, use textContent 
      const container = document.getElementById('container');
      if(container && typeof data.html === 'string') {
        container.textContent = data.html;
      }
    };

    window.addEventListener('message', messageHandler);

    // Post message specifying target origin
    window.postMessage({ token: null }, 'https://trusted-origin.com');

    return () => {
      window.removeEventListener('message', messageHandler);
    };
  }, []);

  return <div id="container"></div>;
}


// ===== LOCALSTORAGE ABUSE - HIGH =====
function StorageComponent() {
  // Do not store sensitive data like passwords or tokens in localStorage/sessionStorage
  const storeCredentials = (username) => {
    localStorage.setItem('username', username);
    // Remove password and token storage    
  };

  const storePaymentInfo = (cardNumber) => {
    // Do not store CVV in sessionStorage
    sessionStorage.setItem('cardNumber', cardNumber);
    // Remove CVV storage
  };

  // Avoid logging or outputting sensitive data
  const getAllStoredData = () => {
    const data = {};
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      data[key] = localStorage.getItem(key);
    }
    // Remove console logs exposing data
    return data;
  };

  return null;
}


// ===== OPEN REDIRECT - HIGH =====
function RedirectComponent() {
  // Validate redirect URLs to allow only safe internal paths or trusted domains
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const redirectUrl = params.get('redirect');
    // Only allow relative URLs starting with "/"
    if (redirectUrl && /^\/[a-zA-Z0-9\-_/]*$/.test(redirectUrl)) {
      window.location.href = redirectUrl;
    }
  }, []);

  // Validate URLs before redirecting externally
  const handleRedirect = (url) => {
    // Allow only relative URLs or trusted domains
    const isRelative = url.startsWith('/');
    const trustedDomainPattern = /^https:\/\/trusted-domain\.com(\/|$)/;
    if (isRelative || trustedDomainPattern.test(url)) {
      window.location.replace(url);
    } else {
      console.warn('Blocked unsafe redirect URL:', url);
    }
  };

  // Validate before window.open
  const openLink = (url) => {
    const trustedDomainPattern = /^https:\/\/trusted-domain\.com(\/|$)/;
    // Only open trusted domains
    if (trustedDomainPattern.test(url)) {
      window.open(url, '_blank', 'noopener,noreferrer');
    } else {
      console.warn('Blocked unsafe link:', url);
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
    if (source[key] instanceof Object && source[key] !== null) {
      target[key] = mergeDeep(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Sanitize JSON parse and prevent prototype pollution
function parseAndMerge(jsonString) {
  const parsed = JSON.parse(jsonString);
  return mergeDeep({}, parsed);
}


// ===== UNSAFE URL HANDLING - HIGH =====
function URLComponent() {
  // Prevent javascript: URLs
  const handleClick = (url) => {
    if (url.trim().toLowerCase().startsWith('javascript:')) {
      console.warn('Blocked javascript: URL');
      return;
    }
    window.location.href = url;
  };

  const createLink = (url, text) => {
    if (url.trim().toLowerCase().startsWith('javascript:')) {
      return <a href="#" onClick={(e) => e.preventDefault()}>{text}</a>;
    }
    return <a href={url} rel="noopener noreferrer">{text}</a>;
  };

  const createIframe = (src) => {
    if (src.trim().toLowerCase().startsWith('javascript:')) {
      return null;
    }
    return <iframe src={src} title="frame" sandbox="allow-scripts allow-same-origin" />;
  };

  return null;
}


// ===== REGEX DOS (Client-side) - MEDIUM =====
const emailRegex = /^[a-zA-Z0-9_.\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z]{2,6}$/;  // Improved regex with limited length domain TLD

function validateInput(input) {
  // Remove dangerous regex
  // Replace with a safer regex as example below (or validate by other means)
  const safeRegex = /^[a-zA-Z0-9]+$/;
  return safeRegex.test(input);
}


// ===== INFORMATION DISCLOSURE - MEDIUM =====
function DebugComponent() {
  // Do not expose sensitive info or detailed errors in console
  const handleError = (error) => {
    console.error('An error occurred.');
  };

  const logEnvironment = () => {
    console.log('App is running.');
  };

  return null;
}


// ===== INSECURE CRYPTO - HIGH =====
function encryptData(data) {
  // Remove btoa usage, suggest no client-side "encryption"
  console.warn('Client-side encryption is disabled for security.');
  return null;
}

function generateToken() {
  // Use crypto API for secure random token generation
  const array = new Uint8Array(16);
  window.crypto.getRandomValues(array);
  return Array.from(array, dec => dec.toString(16).padStart(2, '0')).join('');
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