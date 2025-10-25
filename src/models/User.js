const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  name: { type: String },
  emailVerified: { type: Boolean, default: false },
  verifyTokenHash: { type: String },
  verifyTokenExpires: { type: Date },
  verifyCodeHash: { type: String },
  verifyCodeExpires: { type: Date },
  verifyCodeAttempts: { type: Number, default: 0 },
  lastVerifyCodeSentAt: { type: Date },
  // Password reset fields
  resetTokenHash: { type: String },
  resetTokenExpires: { type: Date },
  resetCodeHash: { type: String },
  resetCodeExpires: { type: Date },
  resetCodeAttempts: { type: Number, default: 0 },
  lastResetCodeSentAt: { type: Date },
  roles: { type: [String], default: ['user'] },
  refreshTokens: { type: [String], default: [] },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', UserSchema);
