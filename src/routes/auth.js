const express = require('express');
const router = express.Router();
const { register, login, refresh, logout, verifyEmail, sendVerificationCode, confirmVerificationCode } = require('../controllers/authController');
const { requireAuth } = require('../middleware/auth');
const passwordResetRoutes = require('./passwordReset');

router.post('/register', register);
router.post('/login', login);
router.post('/refresh', refresh);
router.post('/logout', logout);
router.get('/verify', verifyEmail);
router.post('/verify/code', sendVerificationCode);
router.post('/verify/code/confirm', confirmVerificationCode);

// Mount password reset routes at /password
router.use('/password', passwordResetRoutes);

// example protected route
router.get('/me', requireAuth, (req, res) => {
  res.json({ userId: req.user.sub, roles: req.user.roles });
});

module.exports = router;
