const jwt = require('jsonwebtoken');
const { JWT_SECRET, JWT_EXPIRES_IN, REFRESH_EXPIRES_IN } = require('../config');

const signAccessToken = (payload) => {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
};

const signRefreshToken = (payload) => {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: REFRESH_EXPIRES_IN });
};

const verifyToken = (token) => {
  return jwt.verify(token, JWT_SECRET);
};

module.exports = { signAccessToken, signRefreshToken, verifyToken };
