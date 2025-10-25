const express = require('express');
const router = express.Router();
const { requestResetCode, confirmResetCode, handleResetLink, resetPassword } = require('../controllers/passwordResetController');

// Request password reset (sends code and link)
router.post('/reset-code', requestResetCode);

// Reset password with code
router.post('/reset-code/confirm', confirmResetCode);

// Handle reset link (GET for redirect to frontend)
router.get('/reset', handleResetLink);

// Reset password with token
router.post('/reset', resetPassword);

module.exports = router;