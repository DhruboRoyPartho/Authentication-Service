// tests/auth.integration.test.js
const request = require('supertest');
const mongoose = require('mongoose');
const setup = require('./setup');
const User = require('../src/models/User');

// Mock the mailer so we can inspect sent emails
jest.mock('../src/utils/mailer', () => ({
  sendEmail: jest.fn(async ({ to, subject, text, html }) => {
    // capture message by returning it
    return { to, subject, text, html, previewUrl: 'http://ethereal.mock' };
  })
}));
const { sendEmail } = require('../src/utils/mailer');

const { createApp } = require('../src/app');

let app;

beforeAll(async () => {
  await setup.connect();
  app = await createApp(); // create app (connectDB will skip if MONGO_URI not set)
});

afterAll(async () => {
  await setup.closeDatabase();
});

afterEach(async () => {
  await setup.clearDatabase();
  sendEmail.mockClear();
});

test('register -> sends verification email and returns tokens', async () => {
  const res = await request(app)
    .post('/api/auth/register')
    .send({ email: 'test@example.com', password: 'password1', name: 'Test' })
    .expect(200);

  expect(res.body).toHaveProperty('user');
  expect(res.body).toHaveProperty('accessToken');
  expect(res.body).toHaveProperty('refreshToken');
  expect(res.body.verifySent).toBe(true);
  expect(sendEmail).toHaveBeenCalled();
  const sent = sendEmail.mock.calls[0][0];
  expect(sent.to).toBe('test@example.com');

  // ensure user stored with verifyTokenHash (token flow) or code fields present
  const user = await User.findOne({ email: 'test@example.com' }).lean();
  expect(user).toBeTruthy();
  expect(user.emailVerified).toBe(false);
});

test('send verification code -> confirm code -> emailVerified true', async () => {
  // create a user directly
  const hashed = await require('bcryptjs').hash('password1', 10);
  const user = new User({ email: 'code@example.com', password: hashed });
  await user.save();

  // request code
  const res1 = await request(app)
    .post('/api/auth/verify/code')
    .send({ email: 'code@example.com' })
    .expect(200);

  expect(res1.body.ok).toBe(true);
  expect(sendEmail).toHaveBeenCalledTimes(1);
  const sent = sendEmail.mock.calls[0][0];
  // sent.text or html contains the code. Extract it (we control mock so we can encode code in text)
  // Our mock returns previewUrl, but real sendEmail in tests should be further mocked to return the actual code.
  const match = sent.text.match(/(\d{6})/);
  expect(match).toBeTruthy();
  const code = match[1];

  // confirm code
  const res2 = await request(app)
    .post('/api/auth/verify/code/confirm')
    .send({ email: 'code@example.com', code })
    .expect(200);

  expect(res2.body.ok).toBe(true);

  const userAfter = await User.findOne({ email: 'code@example.com' }).lean();
  expect(userAfter.emailVerified).toBe(true);
});

test('resend cooldown and attempts limit', async () => {
  const hashed = await require('bcryptjs').hash('password1', 10);
  const user = new User({ email: 'limit@example.com', password: hashed });
  await user.save();

  // first send -> ok
  await request(app).post('/api/auth/verify/code').send({ email: 'limit@example.com' }).expect(200);

  // immediate resend -> should be 429 due to cooldown
  const r = await request(app).post('/api/auth/verify/code').send({ email: 'limit@example.com' }).expect(429);
  expect(r.body).toHaveProperty('retryAfterSec');

  // simulate expiry and hitting attempts:
  // manually update user to have attempts = max-1 and codeExpires in future
  const cfg = require('../src/config');
  await User.updateOne({ email: 'limit@example.com' }, { $set: { verifyCodeAttempts: cfg.VERIFY_MAX_ATTEMPTS - 1, verifyCodeExpires: new Date(Date.now() + 5*60000), lastVerifyCodeSentAt: new Date(Date.now() - (cfg.VERIFY_RESEND_COOLDOWN_MS + 1000)) } });

  // request once more -> allowed (becomes max)
  await request(app).post('/api/auth/verify/code').send({ email: 'limit@example.com' }).expect(200);

  // now attempts reached, next request should be blocked with 429 until expiry
  await request(app).post('/api/auth/verify/code').send({ email: 'limit@example.com' }).expect(429);
});

test('login and access protected route', async () => {
  const bcrypt = require('bcryptjs');
  const hashed = await bcrypt.hash('password1', 10);
  const user = new User({ email: 'p@example.com', password: hashed, emailVerified: true });
  await user.save();

  const login = await request(app).post('/api/auth/login').send({ email: 'p@example.com', password: 'password1' }).expect(200);
  expect(login.body).toHaveProperty('accessToken');
  const token = login.body.accessToken;

  const me = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${token}`).expect(200);
  expect(me.body).toHaveProperty('userId');
});