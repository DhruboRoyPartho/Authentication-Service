const request = require('supertest');
const mongoose = require('mongoose');
const setup = require('../setup');
const User = require('../../src/models/User');
const { createApp } = require('../../src/app');
const config = require('../../src/config');

// Mock the mailer
jest.mock('../../src/utils/mailer', () => ({
  sendEmail: jest.fn(async ({ to, subject, text, html }) => {
    return { to, subject, text, html, previewUrl: 'http://ethereal.mock' };
  })
}));
const { sendEmail } = require('../../src/utils/mailer');

let app;

beforeAll(async () => {
  await setup.connect();
  app = await createApp();
});

afterAll(async () => {
  await setup.closeDatabase();
});

afterEach(async () => {
  await setup.clearDatabase();
  sendEmail.mockClear();
});

describe('Password Reset Flow', () => {
  test('request reset code -> sends email with code and link', async () => {
    // Create verified user first
    const bcrypt = require('bcryptjs');
    const hashed = await bcrypt.hash('oldpassword', 10);
    const user = new User({
      email: 'reset@example.com',
      password: hashed,
      emailVerified: true
    });
    await user.save();

    const res = await request(app)
      .post('/api/auth/password/reset-code')
      .send({ email: 'reset@example.com' })
      .expect(200);

    expect(res.body).toHaveProperty('ok', true);
    expect(res.body).toHaveProperty('email');
    expect(sendEmail).toHaveBeenCalled();

    // Extract code and token from mock email
    const sent = sendEmail.mock.calls[0][0];
    expect(sent.to).toBe('reset@example.com');
    const codeMatch = sent.text.match(/code is: (\d{6})/);
    expect(codeMatch).toBeTruthy();
    const code = codeMatch[1];
    const tokenMatch = sent.text.match(/reset\?token=([^\s\n]+)/);
    expect(tokenMatch).toBeTruthy();
    const token = tokenMatch[1];

    // User should have reset fields set
    const userAfter = await User.findOne({ email: 'reset@example.com' });
    expect(userAfter.resetCodeHash).toBeTruthy();
    expect(userAfter.resetTokenHash).toBeTruthy();
    expect(userAfter.resetCodeExpires).toBeTruthy();
    expect(userAfter.resetTokenExpires).toBeTruthy();

    // Reset with code
    const resetWithCode = await request(app)
      .post('/api/auth/password/reset-code/confirm')
      .send({
        email: 'reset@example.com',
        code,
        newPassword: 'NewPass123'
      })
      .expect(200);

    expect(resetWithCode.body).toHaveProperty('ok', true);

    // Should be able to login with new password
    const login = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'reset@example.com',
        password: 'NewPass123'
      })
      .expect(200);

    expect(login.body).toHaveProperty('accessToken');
  });

  test('reset with token from link', async () => {
    // Create verified user
    const bcrypt = require('bcryptjs');
    const hashed = await bcrypt.hash('oldpassword', 10);
    const user = new User({
      email: 'token@example.com',
      password: hashed,
      emailVerified: true
    });
    await user.save();

    // Request reset
    await request(app)
      .post('/api/auth/password/reset-code')
      .send({ email: 'token@example.com' })
      .expect(200);

    // Get token from email
    const sent = sendEmail.mock.calls[0][0];
    const tokenMatch = sent.text.match(/reset\?token=([^\s\n]+)/);
    const token = tokenMatch[1];

    // Reset with token
    const resetWithToken = await request(app)
      .post('/api/auth/password/reset')
      .send({
        token,
        newPassword: 'TokenPass123'
      })
      .expect(200);

    expect(resetWithToken.body).toHaveProperty('ok', true);

    // Login with new password
    const login = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'token@example.com',
        password: 'TokenPass123'
      })
      .expect(200);

    expect(login.body).toHaveProperty('accessToken');
  });

  test('respects cooldown between reset requests', async () => {
    const bcrypt = require('bcryptjs');
    const hashed = await bcrypt.hash('oldpassword', 10);
    const user = new User({
      email: 'cooldown@example.com',
      password: hashed,
      emailVerified: true
    });
    await user.save();

    // First request should succeed
    await request(app)
      .post('/api/auth/password/reset-code')
      .send({ email: 'cooldown@example.com' })
      .expect(200);

    // Immediate second request should be blocked
    const retry = await request(app)
      .post('/api/auth/password/reset-code')
      .send({ email: 'cooldown@example.com' })
      .expect(429);

    expect(retry.body).toHaveProperty('retryAfterSec');
  });

  test('invalid/expired tokens are rejected', async () => {
    // Try invalid token
    const invalidToken = await request(app)
      .post('/api/auth/password/reset')
      .send({
        token: 'invalid-token',
        newPassword: 'NewPass123'
      })
      .expect(401);

    expect(invalidToken.body.error).toBeTruthy();

    // Try with expired token (manipulate JWT exp)
    const jwt = require('jsonwebtoken');
    const expiredToken = jwt.sign(
      { email: 'expired@test.com', type: 'reset', exp: Math.floor(Date.now() / 1000) - 3600 },
      config.JWT_SECRET
    );

    const expired = await request(app)
      .post('/api/auth/password/reset')
      .send({
        token: expiredToken,
        newPassword: 'NewPass123'
      })
      .expect(401);

    expect(expired.body.error).toBeTruthy();
  });

  test('password validation requirements', async () => {
    // Create user
    const bcrypt = require('bcryptjs');
    const hashed = await bcrypt.hash('oldpassword', 10);
    const user = new User({
      email: 'validate@example.com',
      password: hashed,
      emailVerified: true
    });
    await user.save();

    // Request reset
    await request(app)
      .post('/api/auth/password/reset-code')
      .send({ email: 'validate@example.com' })
      .expect(200);

    const sent = sendEmail.mock.calls[0][0];
    const code = sent.text.match(/code is: (\d{6})/)[1];

    // Try too short password
    const tooShort = await request(app)
      .post('/api/auth/password/reset-code/confirm')
      .send({
        email: 'validate@example.com',
        code,
        newPassword: 'short'
      })
      .expect(400);

    expect(tooShort.body.error).toMatch(/at least 8 characters/);

    // Try password without uppercase
    const noUpper = await request(app)
      .post('/api/auth/password/reset-code/confirm')
      .send({
        email: 'validate@example.com',
        code,
        newPassword: 'nouppercasepass123'
      })
      .expect(400);

    expect(noUpper.body.error).toMatch(/uppercase/);

    // Try password without number
    const noNumber = await request(app)
      .post('/api/auth/password/reset-code/confirm')
      .send({
        email: 'validate@example.com',
        code,
        newPassword: 'NoNumbersHere'
      })
      .expect(400);

    expect(noNumber.body.error).toMatch(/numbers/);
  });
});