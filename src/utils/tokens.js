const crypto = require('crypto');
const bcrypt = require('bcryptjs');

// Generate a random 6-digit code
const createRandomCode = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Hash a token or code for secure storage
const hashToken = async (token) => {
  return await bcrypt.hash(token, 10);
};

// Compare a token/code with its hash
const compareTokens = async (token, hash) => {
  return await bcrypt.compare(token, hash);
};

module.exports = {
  createRandomCode,
  hashToken,
  compareTokens
};