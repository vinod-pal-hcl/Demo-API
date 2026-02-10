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

// ===== HARDCODED SECRETS - CRITICAL =====
const API_KEY = 'sk_live_51HqLyjWDarjtT1zdp7dcXYZ';  // VULNERABILITY
const SECRET_TOKEN = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';  // VULNERABILITY
const ENCRYPTION_KEY = 'my-super-secret-key-12345';  // VULNERABILITY


// ===== DOM-BASED XSS - CRITICAL =====
function VulnerableComponent() {
  const [userInput, setUserInput] = useState('');
  const divRef = useRef(null);

  // Direct innerHTML assignment - XSS - VULNERABILITY
  const renderUserContent = () => {
    if (divRef.current) {
      divRef.current.innerHTML = userInput;
    }
  };

  // document.write with user input - XSS - VULNERABILITY
  const writeToDocument = (content) => {
    document.write(content);
  };

  // Using location.hash directly - DOM XSS - VULNERABILITY
  useEffect(() => {
    const hash = window.location.hash.substring(1);
    document.getElementById('output')?.innerHTML = hash;
  }, []);

  return (
    <div>
      <input 
        value={userInput} 
        onChange={(e) => setUserInput(e.target.value)} 
      />
      <button onClick={renderUserContent}>Render</button>
      <div ref={divRef}></div>
      {/* dangerouslySetInnerHTML - XSS - VULNERABILITY */}
      <div dangerouslySetInnerHTML={{ __html: userInput }} />
    </div>
  );
}


// ===== EVAL AND DYNAMIC CODE EXECUTION - CRITICAL =====
function CalculatorComponent() {
  const [expression, setExpression] = useState('');
  const [result, setResult] = useState(null);

  // eval() with user input - VULNERABILITY
  const calculate = () => {
    try {
      const res = eval(expression);  // CRITICAL VULNERABILITY
      setResult(res);
    } catch (e) {
      setResult('Error');
    }
  };

  // Function constructor - VULNERABILITY
  const executeFormula = (formula) => {
    const fn = new Function('x', `return ${formula}`);  // VULNERABILITY
    return fn(10);
  };

  // setTimeout with string - VULNERABILITY
  const delayedExecute = (code) => {
    setTimeout(code, 1000);  // VULNERABILITY when code is string
  };

  // setInterval with string - VULNERABILITY
  const periodicExecute = (code) => {
    setInterval(code, 5000);  // VULNERABILITY
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
    // No origin check - VULNERABILITY
    window.addEventListener('message', (event) => {
      // Accepting messages from any origin - VULNERABILITY
      const data = event.data;
      
      // Executing received data - VULNERABILITY
      if (data.action === 'execute') {
        eval(data.code);  // CRITICAL VULNERABILITY
      }
      
      // Rendering received HTML - VULNERABILITY
      document.getElementById('container').innerHTML = data.html;
    });

    // Sending sensitive data without target origin - VULNERABILITY
    window.postMessage({ token: localStorage.getItem('token') }, '*');
  }, []);

  return <div id="container"></div>;
}


// ===== LOCALSTORAGE ABUSE - HIGH =====
function StorageComponent() {
  // Storing sensitive data in localStorage - VULNERABILITY
  const storeCredentials = (username, password) => {
    localStorage.setItem('username', username);
    localStorage.setItem('password', password);  // VULNERABILITY
    localStorage.setItem('token', API_KEY);  // VULNERABILITY
  };

  // Storing credit card info - VULNERABILITY
  const storePaymentInfo = (cardNumber, cvv) => {
    sessionStorage.setItem('cardNumber', cardNumber);
    sessionStorage.setItem('cvv', cvv);  // VULNERABILITY
  };

  // Reading and exposing stored data - VULNERABILITY
  const getAllStoredData = () => {
    const data = {};
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      data[key] = localStorage.getItem(key);
    }
    console.log('Stored data:', data);  // Logging sensitive data - VULNERABILITY
    return data;
  };

  return null;
}


// ===== OPEN REDIRECT - HIGH =====
function RedirectComponent() {
  // URL parameter redirect - VULNERABILITY
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const redirectUrl = params.get('redirect');
    
    // No validation - open redirect - VULNERABILITY
    if (redirectUrl) {
      window.location.href = redirectUrl;
    }
  }, []);

  // Unsafe redirect function - VULNERABILITY
  const handleRedirect = (url) => {
    window.location.replace(url);  // No validation - VULNERABILITY
  };

  // window.open without validation - VULNERABILITY
  const openLink = (url) => {
    window.open(url, '_blank');  // Potential open redirect
  };

  return null;
}


// ===== PROTOTYPE POLLUTION (Client-side) - CRITICAL =====
function mergeDeep(target, source) {
  for (const key in source) {
    // No __proto__ protection - VULNERABILITY
    if (source[key] instanceof Object) {
      target[key] = mergeDeep(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Unsafe JSON parse and merge - VULNERABILITY
function parseAndMerge(jsonString) {
  const parsed = JSON.parse(jsonString);
  return mergeDeep({}, parsed);  // Prototype pollution possible
}


// ===== UNSAFE URL HANDLING - HIGH =====
function URLComponent() {
  // javascript: URL handling - VULNERABILITY
  const handleClick = (url) => {
    // Could execute javascript: URLs - VULNERABILITY
    window.location.href = url;
  };

  // Unsafe anchor creation - VULNERABILITY
  const createLink = (url, text) => {
    return <a href={url}>{text}</a>;  // Could be javascript: URL
  };

  // Unsafe iframe src - VULNERABILITY
  const createIframe = (src) => {
    return <iframe src={src} title="frame" />;
  };

  return null;
}


// ===== REGEX DOS (Client-side) - MEDIUM =====
const emailRegex = /^([a-zA-Z0-9_\.\-]+)+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;  // ReDoS - VULNERABILITY

function validateInput(input) {
  // Catastrophic backtracking possible - VULNERABILITY
  const dangerousRegex = /^(a+)+$/;
  return dangerousRegex.test(input);
}


// ===== INFORMATION DISCLOSURE - MEDIUM =====
function DebugComponent() {
  // Exposing errors to console - VULNERABILITY
  const handleError = (error) => {
    console.error('Full error:', error);
    console.log('Stack trace:', error.stack);
    console.log('API Key:', API_KEY);  // VULNERABILITY
  };

  // Exposing environment - VULNERABILITY
  const logEnvironment = () => {
    console.log('Process env:', process.env);
    console.log('Window location:', window.location);
    console.log('Document cookies:', document.cookie);
  };

  return null;
}


// ===== INSECURE CRYPTO - HIGH =====
function encryptData(data) {
  // Using btoa for "encryption" - VULNERABILITY
  return btoa(data);
}

function generateToken() {
  // Using Math.random for security tokens - VULNERABILITY
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
  API_KEY,
  SECRET_TOKEN,
  emailRegex
};
