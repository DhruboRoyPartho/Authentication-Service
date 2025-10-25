// tests/jest.setup.js
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../.env.test') });

// Increase timeout for slow CI environments
jest.setTimeout(30000);

// Silence console during tests except for errors
console.log = jest.fn();
console.info = jest.fn();
console.warn = jest.fn();
// Keep error logging for debugging
// console.error = jest.fn();

// Clean up any test-specific global state
afterAll(async () => {
  // Add any global cleanup needed
});
