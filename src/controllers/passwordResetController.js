const User = require('../models/User');
const config = require('../config');
const { createRandomCode, hashToken, compareTokens } = require('../utils/tokens');
const { sendEmail } = require('../utils/mailer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// Utility function to validate password
const validatePassword = (password) => {
  const minLength = 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  
  if (password.length < minLength) {
    return { valid: false, reason: `Password must be at least ${minLength} characters long` };
  }
  if (!hasUpperCase || !hasLowerCase || !hasNumbers) {
    return { valid: false, reason: 'Password must contain uppercase, lowercase, and numbers' };
  }
  return { valid: true };
};

// Generate and send reset code/link
const requestResetCode = async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    // Find user - don't reveal if email exists
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(200).json({ ok: true, email }); // Don't reveal email existence
    }

    // Check cooldown
    if (user.lastResetCodeSentAt) {
      const cooldownMs = config.VERIFY_RESEND_COOLDOWN_MS;
      const nextAllowedTime = new Date(user.lastResetCodeSentAt.getTime() + cooldownMs);
      if (Date.now() < nextAllowedTime) {
        const retryAfterSec = Math.ceil((nextAllowedTime - Date.now()) / 1000);
        return res.status(429).json({
          error: 'Too many reset attempts',
          retryAfterSec
        });
      }
    }

    // Check attempts if there's an active code
    if (user.resetCodeExpires && Date.now() < user.resetCodeExpires) {
      if (user.resetCodeAttempts >= config.VERIFY_MAX_ATTEMPTS) {
        const retryAfterSec = Math.ceil((user.resetCodeExpires - Date.now()) / 1000);
        return res.status(429).json({
          error: 'Maximum attempts reached',
          retryAfterSec
        });
      }
    }

    // Generate 6-digit code and reset token
    const code = createRandomCode();
    const token = jwt.sign({ email, type: 'reset' }, config.JWT_SECRET, { expiresIn: '1h' });
    const codeHash = await hashToken(code);
    const tokenHash = await hashToken(token);
    const expiryTime = Date.now() + config.VERIFY_CODE_TTL_MS;

    // Update user with new reset tokens
    await User.updateOne(
      { email },
      {
        resetCodeHash: codeHash,
        resetTokenHash: tokenHash,
        resetCodeExpires: new Date(expiryTime),
        resetTokenExpires: new Date(expiryTime),
        resetCodeAttempts: 0,
        lastResetCodeSentAt: new Date()
      }
    );

    // Send email with both code and link
    const resetUrl = `${req.protocol}://${req.get('host')}/api/auth/password/reset?token=${token}`;
    const mailResult = await sendEmail({
      to: email,
      subject: 'Reset Your Password',
      text: `Your password reset code is: ${code}\n\nOr click this link to reset your password: ${resetUrl}\n\nThis code and link will expire in 10 minutes.`,
      html: `<h3>Reset Your Password</h3>
             <p>Your password reset code is: <strong>${code}</strong></p>
             <p>Or <a href="${resetUrl}">click here to reset your password</a></p>
             <p>This code and link will expire in 10 minutes.</p>`
    });

    return res.status(200).json({
      ok: true,
      email,
      mailResult,
      nextAllowedInSec: config.VERIFY_RESEND_COOLDOWN_MS / 1000
    });
  } catch (error) {
    console.error('Reset code request error:', error);
    return res.status(500).json({ error: 'Failed to process reset request' });
  }
};

// Confirm reset code and set new password
const confirmResetCode = async (req, res) => {
  const { email, code, newPassword } = req.body;
  if (!email || !code || !newPassword) {
    return res.status(400).json({ error: 'Email, code, and new password are required' });
  }

  // Validate password
  const passwordCheck = validatePassword(newPassword);
  if (!passwordCheck.valid) {
    return res.status(400).json({ error: passwordCheck.reason });
  }

  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user || !user.resetCodeHash || !user.resetCodeExpires) {
      return res.status(401).json({ error: 'Invalid or expired reset code' });
    }

    // Check expiry
    if (Date.now() > user.resetCodeExpires) {
      return res.status(401).json({ error: 'Reset code has expired' });
    }

    // Verify code
    const isValidCode = await compareTokens(code, user.resetCodeHash);
    if (!isValidCode) {
      // Increment attempts
      await User.updateOne(
        { email },
        { $inc: { resetCodeAttempts: 1 } }
      );
      return res.status(401).json({ error: 'Invalid reset code' });
    }

    // Set new password and clear reset fields
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await User.updateOne(
      { email },
      {
        password: hashedPassword,
        resetCodeHash: null,
        resetTokenHash: null,
        resetCodeExpires: null,
        resetTokenExpires: null,
        resetCodeAttempts: 0,
        lastResetCodeSentAt: null
      }
    );

    return res.status(200).json({ ok: true, email });
  } catch (error) {
    console.error('Reset code confirmation error:', error);
    return res.status(500).json({ error: 'Failed to process reset confirmation' });
  }
};

// Handle reset link (GET request that redirects to frontend)
const handleResetLink = async (req, res) => {
  const { token } = req.query;
  if (!token) {
    return res.status(400).json({ error: 'Reset token is required' });
  }

  try {
    // Verify JWT format/signature
    const decoded = jwt.verify(token, config.JWT_SECRET);
    if (!decoded.email || decoded.type !== 'reset') {
      return res.status(401).json({ error: 'Invalid reset token' });
    }

    // Frontend URL for password reset form
    const frontendResetUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    return res.redirect(`${frontendResetUrl}/reset-password?token=${token}`);
  } catch (error) {
    console.error('Reset link handling error:', error);
    return res.status(401).json({ error: 'Invalid or expired reset token' });
  }
};

// Reset password with token (from link)
const resetPassword = async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Token and new password are required' });
  }

  // Validate password
  const passwordCheck = validatePassword(newPassword);
  if (!passwordCheck.valid) {
    return res.status(400).json({ error: passwordCheck.reason });
  }

  try {
    // Verify JWT format/signature
    const decoded = jwt.verify(token, config.JWT_SECRET);
    if (!decoded.email || decoded.type !== 'reset') {
      return res.status(401).json({ error: 'Invalid reset token' });
    }

    const user = await User.findOne({ email: decoded.email });
    if (!user || !user.resetTokenHash || !user.resetTokenExpires) {
      return res.status(401).json({ error: 'Invalid or expired reset token' });
    }

    // Check expiry
    if (Date.now() > user.resetTokenExpires) {
      return res.status(401).json({ error: 'Reset token has expired' });
    }

    // Verify token
    const isValidToken = await compareTokens(token, user.resetTokenHash);
    if (!isValidToken) {
      return res.status(401).json({ error: 'Invalid reset token' });
    }

    // Set new password and clear reset fields
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await User.updateOne(
      { email: decoded.email },
      {
        password: hashedPassword,
        resetCodeHash: null,
        resetTokenHash: null,
        resetCodeExpires: null,
        resetTokenExpires: null,
        resetCodeAttempts: 0,
        lastResetCodeSentAt: null
      }
    );

    return res.status(200).json({ ok: true, email: decoded.email });
  } catch (error) {
    console.error('Reset password error:', error);
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid reset token' });
    }
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Reset token has expired' });
    }
    return res.status(500).json({ error: 'Failed to process reset request' });
  }
};

module.exports = {
  requestResetCode,
  confirmResetCode,
  handleResetLink,
  resetPassword
};