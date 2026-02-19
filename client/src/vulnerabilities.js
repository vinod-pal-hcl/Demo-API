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

// Utility function to escape HTML entities
function escapeHtml(unsafe) {
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ===== DOM-BASED XSS - CRITICAL =====
function VulnerableComponent() {
  const [userInput, setUserInput] = useState('');
  const divRef = useRef(null);

  // Safe innerHTML assignment - Escaping to prevent XSS
  const renderUserContent = () => {
    if (divRef.current) {
      divRef.current.textContent = userInput; // safer than innerHTML
    }
  };

  // Removed document.write usage in favor of safer DOM manipulation
  const writeToDocument = (content) => {
    // Instead of document.write, safely append text node
    const body = document.body;
    if (body) {
      const p = document.createElement('p');
      p.textContent = content;
      body.appendChild(p);
    }
  };

  // Using location.hash safely by escaping content
  useEffect(() => {
    const hash = window.location.hash.substring(1);
    const outputEl = document.getElementById('output');
    if (outputEl) {
      outputEl.textContent = hash; // use textContent to avoid XSS
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
      {/* Replaced dangerouslySetInnerHTML with safe text rendering */}
      <div>{userInput}</div>
    </div>
  );
}


// ===== EVAL AND DYNAMIC CODE EXECUTION - CRITICAL =====
function CalculatorComponent() {
  const [expression, setExpression] = useState('');
  const [result, setResult] = useState(null);

  // Safe calculate using math-expression-evaluator or limited parser
  // For demo, allow only numbers and +-*/(). spaces
  const calculate = () => {
    try {
      if (/^[0-9\s+\-*/().]+$/.test(expression)) {
        // eslint-disable-next-line no-new-func
        const fn = new Function('return ' + expression);
        const res = fn();
        setResult(res);
      } else {
        setResult('Invalid expression');
      }
    } catch (e) {
      setResult('Error');
    }
  };

  // Removed unsafe Function constructor usage
  const executeFormula = (formula) => {
    // Implement safe parser or whitelist validation
    throw new Error('executeFormula removed due to security risk');
  };

  // Removed setTimeout with string usage - should use function reference
  const delayedExecute = (code) => {
    if (typeof code === 'function') {
      setTimeout(code, 1000);
    }
  };

  // Removed setInterval with string usage
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
      // Check origin
      const trustedOrigins = [window.location.origin];
      if (!trustedOrigins.includes(event.origin)) {
        return; // ignore untrusted origin
      }

      const data = event.data;
      if (!data || typeof data !== 'object') return;

      // Removed eval execution
      if (data.action === 'execute') {
        console.warn('Execution of code removed for security reasons.');
      }

      // Safe rendering
      const container = document.getElementById('container');
      if (container) {
        container.textContent = data.html || '';
      }
    };

    window.addEventListener('message', messageHandler);

    // Use secure target origin instead of '*'
    const token = localStorage.getItem('token');
    if (token) {
      window.postMessage({ token: token }, window.location.origin);
    }

    return () => {
      window.removeEventListener('message', messageHandler);
    };
  }, []);

  return <div id="container"></div>;
}


// ===== LOCALSTORAGE ABUSE - HIGH =====
function StorageComponent() {
  // Removed storing sensitive info like passwords or tokens in localStorage/sessionStorage
  const storeCredentials = (username) => {
    localStorage.setItem('username', username);
    // Do NOT store passwords or tokens client-side
  };

  const storePaymentInfo = () => {
    // Removed storing credit card info in sessionStorage
    console.warn('Storing payment info on client-side disabled');
  };

  // Removed logging of all stored sensitive data
  const getAllStoredData = () => {
    console.warn('Access to all stored data is disabled for security');
    return {};
  };

  return null;
}


// ===== OPEN REDIRECT - HIGH =====
function RedirectComponent() {
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const redirectUrl = params.get('redirect');
    
    if (redirectUrl) {
      try {
        const urlObj = new URL(redirectUrl, window.location.origin);
        // Allow only relative or same origin redirects
        if (urlObj.origin === window.location.origin) {
          window.location.href = urlObj.pathname + urlObj.search + urlObj.hash;
        } else {
          console.warn('Blocked redirect to external origin');
        }
      } catch (e) {
        console.warn('Invalid redirect URL');
      }
    }
  }, []);

  const handleRedirect = (url) => {
    try {
      const urlObj = new URL(url, window.location.origin);
      if (urlObj.origin === window.location.origin) {
        window.location.replace(urlObj.pathname + urlObj.search + urlObj.hash);
      } else {
        console.warn('Blocked redirect to external origin');
      }
    } catch (e) {
      console.warn('Invalid redirect URL');
    }
  };

  const openLink = (url) => {
    try {
      const urlObj = new URL(url, window.location.origin);
      if (urlObj.origin === window.location.origin) {
        window.open(urlObj.href, '_blank');
      } else {
        console.warn('Blocked opening external link');
      }
    } catch (e) {
      console.warn('Invalid URL to open');
    }
  };

  return null;
}


// ===== PROTOTYPE POLLUTION (Client-side) - CRITICAL =====
function mergeDeep(target, source) {
  for (const key in source) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue; // prevent prototype pollution
    }
    if (source[key] instanceof Object && !Array.isArray(source[key])) {
      if (!target[key]) target[key] = {};
      mergeDeep(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

function parseAndMerge(jsonString) {
  let parsed = {};
  try {
    parsed = JSON.parse(jsonString);
  } catch {
    console.warn('Invalid JSON input');
  }
  return mergeDeep({}, parsed);
}


// ===== UNSAFE URL HANDLING - HIGH =====
function URLComponent() {
  // Validate protocol before navigation
  const handleClick = (url) => {
    try {
      const urlObj = new URL(url, window.location.origin);
      if (urlObj.protocol === 'http:' || urlObj.protocol === 'https:') {
        window.location.href = urlObj.href;
      } else {
        console.warn('Blocked navigation to unsafe protocol');
      }
    } catch {
      console.warn('Invalid URL');
    }
  };

  const createLink = (url, text) => {
    try {
      const urlObj = new URL(url, window.location.origin);
      if (urlObj.protocol === 'http:' || urlObj.protocol === 'https:') {
        return <a href={urlObj.href}>{text}</a>;
      }
    } catch {
      // fallback safe link
    }
    return <a href="#" onClick={(e) => e.preventDefault()}>{text}</a>;
  };

  const createIframe = (src) => {
    try {
      const urlObj = new URL(src, window.location.origin);
      if (urlObj.protocol === 'http:' || urlObj.protocol === 'https:') {
        return <iframe src={urlObj.href} title="frame" sandbox="allow-scripts allow-same-origin" />;
      }
    } catch {
      // refuse invalid or unsafe src
    }
    return null;
  };

  return null;
}


// ===== REGEX DOS (Client-side) - MEDIUM =====
const emailRegex = /^([a-zA-Z0-9_\.\-]+)+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;

function validateInput(input) {
  // Removed dangerous regex to prevent ReDoS
  // Implement safer validations?
  // For now, simple length check
  if (input.length > 1000) {
    return false;
  }
  return true;
}


// ===== INFORMATION DISCLOSURE - MEDIUM =====
function DebugComponent() {
  // Remove console exposure of sensitive information
  const handleError = (error) => {
    // Log minimal error info
    console.error('Error occurred:', error.message);
  };

  const logEnvironment = () => {
    // Do not log sensitive environment or cookies
    console.log('App running');
  };

  return null;
}


// ===== INSECURE CRYPTO - HIGH =====
import crypto from 'crypto';

function encryptData(data) {
  // Using crypto.subtle or Node crypto for real encryption
  // For demo, base64 encode clearly not encryption
  return btoa(data);
}

function generateToken() {
  // Using crypto.getRandomValues in browser or crypto.randomBytes in node
  if (typeof window !== 'undefined' && window.crypto && window.crypto.getRandomValues) {
    const array = new Uint32Array(1);
    window.crypto.getRandomValues(array);
    return array[0].toString(36);
  } else if (typeof crypto !== 'undefined') {
    return crypto.randomBytes(8).toString('hex');
  }
  // fallback - not recommended
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
