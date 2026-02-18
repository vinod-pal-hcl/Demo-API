```jsx
/**
 * ==================================================================================
 * INTENTIONALLY VULNERABLE CODE - SAST TESTING PROJECT
 * ==================================================================================
 * This React application contains multiple intentional security vulnerabilities:
 * - XSS (Cross-Site Scripting) via dangerouslySetInnerHTML
 * - eval() usage with user input
 * - Hardcoded API keys and tokens
 * - Storing sensitive data in localStorage
 * - Open redirect vulnerabilities
 * - No CSRF protection
 * 
 * FOR TESTING PURPOSES ONLY - DO NOT USE IN PRODUCTION
 * ==================================================================================
 */

import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';
```