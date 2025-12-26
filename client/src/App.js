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

// Hardcoded credentials - VULNERABILITY
const API_URL = 'http://localhost:5000/api';
const ADMIN_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.hardcoded';

function App() {
  const [products, setProducts] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [userInput, setUserInput] = useState('');

  useEffect(() => {
    fetchProducts();
  }, []);

  const fetchProducts = async () => {
    try {
      const response = await axios.get(`${API_URL}/products`);
      setProducts(response.data);
    } catch (error) {
      console.error('Error:', error);
    }
  };

  // XSS vulnerability - dangerouslySetInnerHTML - VULNERABILITY
  const renderProductDescription = (description) => {
    return <div dangerouslySetInnerHTML={{ __html: description }} />;
  };

  // SQL injection-like search - VULNERABILITY
  const handleSearch = async () => {
    try {
      // Concatenating user input directly
      const response = await axios.get(`${API_URL}/products/search?q=${searchTerm}`);
      setProducts(response.data);
    } catch (error) {
      console.error('Error:', error);
    }
  };

  // eval() usage - VULNERABILITY
  const executeUserCode = () => {
    try {
      eval(userInput);
    } catch (error) {
      alert('Error: ' + error.message);
    }
  };

  // Storing sensitive data in localStorage - VULNERABILITY
  const handleLogin = async (username, password) => {
    try {
      const response = await axios.post(`${API_URL}/users/login`, {
        username,
        password
      });
      
      // Storing token and sensitive data in localStorage
      localStorage.setItem('token', response.data.token);
      localStorage.setItem('user', JSON.stringify(response.data.user));
      localStorage.setItem('password', password); // Storing password - VULNERABILITY
      localStorage.setItem('creditCard', '4532-1234-5678-9010');
    } catch (error) {
      console.error('Login error:', error);
    }
  };

  // No CSRF protection - VULNERABILITY
  const handlePayment = async (cardNumber, cvv, amount) => {
    try {
      // Sending sensitive data without encryption
      const response = await axios.post(`${API_URL}/orders/process-payment`, {
        cardNumber: cardNumber,
        cvv: cvv,
        amount: amount
      });
      
      alert('Payment processed: ' + JSON.stringify(response.data));
    } catch (error) {
      console.error('Payment error:', error);
    }
  };

  // Open redirect vulnerability - VULNERABILITY
  const handleRedirect = () => {
    const redirectUrl = new URLSearchParams(window.location.search).get('redirect');
    if (redirectUrl) {
      window.location.href = redirectUrl; // No validation
    }
  };

  // Insecure random number generation - VULNERABILITY
  const generateSessionId = () => {
    return Math.random().toString(36).substring(7);
  };

  // Exposing API keys in client code - VULNERABILITY
  const uploadFile = async (file) => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('api_key', 'AIzaSyD1234567890abcdefghijklmnopqr'); // Hardcoded API key
    
    try {
      const response = await axios.post(`${API_URL}/upload`, formData, {
        headers: {
          'Authorization': ADMIN_TOKEN
        }
      });
      
      return response.data;
    } catch (error) {
      console.error('Upload error:', error);
    }
  };

  return (
    <div className="App">
      <header className="App-header">
        <h1>Vulnerable E-Commerce Store</h1>
        
        {/* XSS vulnerability - unescaped output */}
        <div id="welcome">
          <script>alert('XSS')</script>
        </div>
        
        <div className="search-box">
          <input 
            type="text" 
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search products..."
          />
          <button onClick={handleSearch}>Search</button>
        </div>

        <div className="code-executor">
          <h3>Execute Code (Debug Feature)</h3>
          <textarea 
            value={userInput}
            onChange={(e) => setUserInput(e.target.value)}
            placeholder="Enter JavaScript code..."
          />
          <button onClick={executeUserCode}>Execute</button>
        </div>

        <div className="products">
          {products.map(product => (
            <div key={product._id} className="product-card">
              <h3>{product.name}</h3>
              {/* XSS vulnerability */}
              {renderProductDescription(product.description)}
              <p>Price: ${product.price}</p>
              <img src={product.imageUrl} alt={product.name} />
            </div>
          ))}
        </div>
      </header>
    </div>
  );
}

// Exposing internal functions globally - VULNERABILITY
window.App = App;
window.adminLogin = () => {
  localStorage.setItem('role', 'admin');
  localStorage.setItem('adminToken', ADMIN_TOKEN);
};

export default App;
