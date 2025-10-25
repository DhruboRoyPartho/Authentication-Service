const mongoose = require('mongoose');
const dotenv = require('dotenv');

dotenv.config();

const MONGO_URI = process.env.MONGO_URI || '';
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-prod';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '15m';
const REFRESH_EXPIRES_IN = process.env.REFRESH_EXPIRES_IN || '7d';
const VERIFY_CODE_TTL_MS = parseInt(process.env.VERIFY_CODE_TTL_MS || String(1000 * 60 * 10), 10); // default 10 minutes
const VERIFY_RESEND_COOLDOWN_MS = parseInt(process.env.VERIFY_RESEND_COOLDOWN_MS || String(1000 * 60), 10); // default 60 seconds
const VERIFY_MAX_ATTEMPTS = parseInt(process.env.VERIFY_MAX_ATTEMPTS || '5', 10);

const connectDB = async () => {
  // If already connected (e.g. tests using an in-memory server), do nothing
  if (mongoose.connection.readyState && mongoose.connection.readyState !== 0) {
    // 1 = connected, 2 = connecting, 3 = disconnecting
    console.log('Mongoose already connected (state:', mongoose.connection.readyState, '). Skipping connect.');
    return;
  }

  if (!MONGO_URI) {
    console.warn('MONGO_URI not set. Skipping DB connection for tests or local offline runs.');
    return;
  }

  // Newer MongoDB drivers ignore useNewUrlParser/useUnifiedTopology; keep options minimal
  await mongoose.connect(MONGO_URI);
  console.log('Connected to MongoDB');
};

module.exports = {
  connectDB,
  MONGO_URI,
  JWT_SECRET,
  JWT_EXPIRES_IN,
  REFRESH_EXPIRES_IN
  ,VERIFY_CODE_TTL_MS,
  VERIFY_RESEND_COOLDOWN_MS,
  VERIFY_MAX_ATTEMPTS
};
