const Joi = require('joi');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const User = require('../models/User');
const { signAccessToken, signRefreshToken, verifyToken } = require('../utils/jwt');
const { sendEmail } = require('../utils/mailer');

const registerSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  name: Joi.string().optional()
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required()
});

const register = async (req, res, next) => {
  try {
    const { error, value } = registerSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.message });

    const existing = await User.findOne({ email: value.email });
    if (existing) return res.status(409).json({ error: 'Email already in use' });

    const hashed = await bcrypt.hash(value.password, 10);
    const user = new User({ email: value.email, password: hashed, name: value.name });

    // generate email verification token (store hash)
    const verifyToken = crypto.randomBytes(32).toString('hex');
    const verifyTokenHash = crypto.createHash('sha256').update(verifyToken).digest('hex');
    user.verifyTokenHash = verifyTokenHash;
    user.verifyTokenExpires = Date.now() + 1000 * 60 * 60; // 1 hour

    await user.save();

    const verifyUrl = `${req.protocol}://${req.get('host')}/api/auth/verify?token=${verifyToken}`;

    // send verification email (sandbox or provider)
    const mailResult = await sendEmail({ to: user.email, subject: 'Verify your email', text: `Click to verify: ${verifyUrl}`, html: `<p>Click to verify: <a href="${verifyUrl}">${verifyUrl}</a></p>` });

    const accessToken = signAccessToken({ sub: user._id, roles: user.roles });
    const refreshToken = signRefreshToken({ sub: user._id });
    user.refreshTokens.push(refreshToken);
    await user.save();

    // in sandbox mode mailer may return preview URL
    res.json({ user: { id: user._id, email: user.email, name: user.name, roles: user.roles }, accessToken, refreshToken, verifySent: true, mailResult });
  } catch (err) {
    next(err);
  }
};

const verifyEmail = async (req, res, next) => {
  try {
    const token = req.query.token || req.body.token;
    if (!token) return res.status(400).json({ error: 'Missing token' });

    const hash = crypto.createHash('sha256').update(token).digest('hex');
    const user = await User.findOne({ verifyTokenHash: hash, verifyTokenExpires: { $gt: Date.now() } });
    if (!user) return res.status(400).json({ error: 'Invalid or expired token' });

    user.emailVerified = true;
    user.verifyTokenHash = undefined;
    user.verifyTokenExpires = undefined;
    await user.save();

    res.json({ ok: true, email: user.email });
  } catch (err) {
    next(err);
  }
};

// Send a numeric verification code to the user's email (sandbox via Ethereal by default)
const config = require('../config');

const sendVerificationCode = async (req, res, next) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Missing email' });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const now = Date.now();
    // cooldown check
    if (user.lastVerifyCodeSentAt) {
      const elapsed = now - new Date(user.lastVerifyCodeSentAt).getTime();
      if (elapsed < config.VERIFY_RESEND_COOLDOWN_MS) {
        const retryAfterSec = Math.ceil((config.VERIFY_RESEND_COOLDOWN_MS - elapsed) / 1000);
        return res.status(429).json({ error: 'Too many requests', retryAfterSec });
      }
    }

    // if too many attempts and current code still valid, block
    if (user.verifyCodeAttempts >= config.VERIFY_MAX_ATTEMPTS && user.verifyCodeExpires && user.verifyCodeExpires > now) {
      return res.status(429).json({ error: 'Too many verification attempts, try later' });
    }

    // generate 6-digit code
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const codeHash = crypto.createHash('sha256').update(code).digest('hex');
    user.verifyCodeHash = codeHash;
    user.verifyCodeExpires = new Date(now + config.VERIFY_CODE_TTL_MS);
    user.verifyCodeAttempts = (user.verifyCodeAttempts || 0) + 1;
    user.lastVerifyCodeSentAt = new Date(now);
    await user.save();

    const ttlMinutes = Math.ceil(config.VERIFY_CODE_TTL_MS / 60000);
    const text = `Your verification code is: ${code}\nThis code will expire in ${ttlMinutes} minutes.`;
    const html = `<p>Your verification code is: <strong>${code}</strong></p><p>This code will expire in ${ttlMinutes} minutes.</p>`;
    const mailResult = await sendEmail({ to: user.email, subject: 'Your verification code', text, html });

    res.json({ ok: true, email: user.email, mailResult, nextAllowedInSec: Math.ceil(config.VERIFY_RESEND_COOLDOWN_MS / 1000) });
  } catch (err) {
    next(err);
  }
};

const confirmVerificationCode = async (req, res, next) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) return res.status(400).json({ error: 'Missing email or code' });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (!user.verifyCodeHash || !user.verifyCodeExpires) return res.status(400).json({ error: 'No verification code requested' });
    if (new Date(user.verifyCodeExpires).getTime() < Date.now()) return res.status(400).json({ error: 'Code expired' });

    const codeHash = crypto.createHash('sha256').update(code).digest('hex');
    if (codeHash !== user.verifyCodeHash) {
      // increment attempts and possibly block
      user.verifyCodeAttempts = (user.verifyCodeAttempts || 0) + 1;
      await user.save();
      return res.status(400).json({ error: 'Invalid code' });
    }

    user.emailVerified = true;
    user.verifyCodeHash = undefined;
    user.verifyCodeExpires = undefined;
    user.verifyCodeAttempts = 0;
    user.lastVerifyCodeSentAt = undefined;
    // also clear token-based fields if present
    user.verifyTokenHash = undefined;
    user.verifyTokenExpires = undefined;
    await user.save();

    res.json({ ok: true, email: user.email });
  } catch (err) {
    next(err);
  }
};

const login = async (req, res, next) => {
  try {
    const { error, value } = loginSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.message });

    const user = await User.findOne({ email: value.email });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(value.password, user.password);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const accessToken = signAccessToken({ sub: user._id, roles: user.roles });
    const refreshToken = signRefreshToken({ sub: user._id });
    user.refreshTokens.push(refreshToken);
    await user.save();

    res.json({ user: { id: user._id, email: user.email, name: user.name, roles: user.roles }, accessToken, refreshToken });
  } catch (err) {
    next(err);
  }
};

const refresh = async (req, res, next) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'Missing refresh token' });

    let payload;
    try {
      payload = verifyToken(token);
    } catch (err) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    const user = await User.findById(payload.sub);
    if (!user) return res.status(401).json({ error: 'User not found' });
    if (!user.refreshTokens.includes(token)) return res.status(401).json({ error: 'Refresh token revoked' });

    // issue new tokens
    const accessToken = signAccessToken({ sub: user._id, roles: user.roles });
    const refreshToken = signRefreshToken({ sub: user._id });

    // rotate: remove old token and store new one
    user.refreshTokens = user.refreshTokens.filter((t) => t !== token);
    user.refreshTokens.push(refreshToken);
    await user.save();

    res.json({ accessToken, refreshToken });
  } catch (err) {
    next(err);
  }
};

const logout = async (req, res, next) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'Missing refresh token' });

    let payload;
    try {
      payload = verifyToken(token);
    } catch (err) {
      // still attempt to remove token by value
      // continue
    }

    if (!payload) {
      // best-effort: find user with token and remove
      await User.updateOne({ refreshTokens: token }, { $pull: { refreshTokens: token } });
      return res.json({ ok: true });
    }

    const user = await User.findById(payload.sub);
    if (user) {
      user.refreshTokens = user.refreshTokens.filter((t) => t !== token);
      await user.save();
    }

    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
};

module.exports = { register, login, refresh, logout, verifyEmail, sendVerificationCode, confirmVerificationCode };
