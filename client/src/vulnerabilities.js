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

  // Sanitizing user input before innerHTML assignment to prevent XSS
  const sanitize = (str) => {
    const temp = document.createElement('div');
    temp.textContent = str;
    return temp.innerHTML;
  };

  const renderUserContent = () => {
    if (divRef.current) {
      divRef.current.textContent = userInput; // safer than innerHTML
    }
  };

  // Replacing document.write with safer DOM manipulation
  const writeToDocument = (content) => {
    document.body.textContent = content; // safer alternative
  };

  // Using textContent instead of innerHTML for hash display
  useEffect(() => {
    const hash = window.location.hash.substring(1);
    const outputElem = document.getElementById('output');
    if (outputElem) {
      outputElem.textContent = hash;
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
      {/* Removed dangerouslySetInnerHTML due to XSS risk; show escaped content */}
      <div>{userInput}</div>
    </div>
  );
}


// ===== EVAL AND DYNAMIC CODE EXECUTION - CRITICAL =====
function CalculatorComponent() {
  const [expression, setExpression] = useState('');
  const [result, setResult] = useState(null);

  // Replace eval with safer math expression evaluation
  const calculate = () => {
    try {
      // Using Function constructor safely by validating expression
      if (/^[0-9+\-*/. ()]+$/.test(expression)) {
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

  // Remove usage of Function constructor with unchecked formula
  const executeFormula = (formula) => {
    if (/^[0-9+\-*/. x()]+$/.test(formula)) {
      const fn = new Function('x', `"use strict"; return (${formula})`);
      return fn(10);
    }
    throw new Error('Invalid formula');
  };

  // Remove setTimeout and setInterval usage with strings
  const delayedExecute = (code) => {
    // No execution of string code to avoid RCE
    console.warn('delayedExecute has been disabled for safety');
  };

  const periodicExecute = (code) => {
    console.warn('periodicExecute has been disabled for safety');
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
    const handleMessage = (event) => {
      // Validate origin
      const allowedOrigins = ['https://trusted-origin.com'];
      if (!allowedOrigins.includes(event.origin)) {
        return;
      }
      const data = event.data;
      if (data.action === 'execute') {
        // disallow execution of arbitrary code
        console.warn('Execution blocked for security reasons');
      }
      const container = document.getElementById('container');
      if (container) {
        container.textContent = data.html || '';
      }
    };

    window.addEventListener('message', handleMessage);

    // Use target origin instead of '*'
    window.postMessage({ token: localStorage.getItem('token') }, 'https://trusted-origin.com');

    return () => {
      window.removeEventListener('message', handleMessage);
    };
  }, []);

  return <div id="container"></div>;
}


// ===== LOCALSTORAGE ABUSE - HIGH =====
function StorageComponent() {
  // Removed storing sensitive data in localStorage/sessionStorage
  const storeCredentials = (username, password, token) => {
    // Use secure cookies or encrypted storage in production
    console.warn('Storing credentials in localStorage/sessionStorage is unsafe');
  };

  const storePaymentInfo = (cardNumber, cvv) => {
    console.warn('Storing payment info in sessionStorage is unsafe');
  };

  const getAllStoredData = () => {
    console.warn('Exposing stored data is unsafe');
    return {};
  };

  return null;
}


// ===== OPEN REDIRECT - HIGH =====
function RedirectComponent() {
  const isValidUrl = (url) => {
    try {
      const parsed = new URL(url, window.location.origin);
      // Only allow internal links or specific allowed domains
      return parsed.origin === window.location.origin;
    } catch {
      return false;
    }
  };

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const redirectUrl = params.get('redirect');
    if (redirectUrl && isValidUrl(redirectUrl)) {
      window.location.href = redirectUrl;
    }
  }, []);

  const handleRedirect = (url) => {
    if (isValidUrl(url)) {
      window.location.replace(url);
    } else {
      console.warn('Blocked unsafe redirect URL');
    }
  };

  const openLink = (url) => {
    if (isValidUrl(url)) {
      window.open(url, '_blank', 'noopener,noreferrer');
    } else {
      console.warn('Blocked unsafe URL in new window');
    }
  };

  return null;
}


// ===== PROTOTYPE POLLUTION (Client-side) - CRITICAL =====
function mergeDeep(target, source) {
  const isObject = (obj) => obj && typeof obj === 'object';

  for (const key in source) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue; // prevent prototype pollution
    }
    if (isObject(source[key])) {
      if (!isObject(target[key])) {
        target[key] = {};
      }
      mergeDeep(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

function parseAndMerge(jsonString) {
  try {
    const parsed = JSON.parse(jsonString);
    return mergeDeep({}, parsed);
  } catch {
    console.warn('Invalid JSON input');
    return {};
  }
}


// ===== UNSAFE URL HANDLING - HIGH =====
function URLComponent() {
  const isSafeUrl = (url) => {
    try {
      const parsed = new URL(url, window.location.origin);
      return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch {
      return false;
    }
  };

  const handleClick = (url) => {
    if (isSafeUrl(url)) {
      window.location.href = url;
    } else {
      console.warn('Blocked unsafe URL navigation');
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
      return <iframe src={src} title="frame" />;
    }
    return <div>Invalid iframe src</div>;
  };

  return null;
}


// ===== REGEX DOS (Client-side) - MEDIUM =====
const emailRegex = /^[a-zA-Z0-9_\.\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9]{2,6}$/; // simplified safe regex

function validateInput(input) {
  // Removed problematic regex with catastrophic backtracking
  const safeRegex = /^[a]+$/;
  return safeRegex.test(input);
}


// ===== INFORMATION DISCLOSURE - MEDIUM =====
function DebugComponent() {
  const handleError = (error) => {
    // Avoid exposing full error details in production
    console.error('An error occurred');
  };

  const logEnvironment = () => {
    // Avoid logging sensitive information
    console.log('Logging disabled for sensitive info');
  };

  return null;
}


// ===== INSECURE CRYPTO - HIGH =====
function encryptData(data) {
  // Removed insecure btoa use
  console.warn('Encryption method is insecure and disabled');
  return null;
}

function generateToken() {
  // Use cryptographically secure token generation
  const array = new Uint32Array(4);
  window.crypto.getRandomValues(array);
  return Array.from(array, dec => dec.toString(16).padStart(8, '0')).join('');
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
