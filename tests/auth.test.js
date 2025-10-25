const request = require('supertest');
const { createApp } = require('../src/app');

let app;
beforeAll(async () => {
  app = await createApp({ skipDBConnect: true });
});

test('health check works', async () => {
  const res = await request(app).get('/api/health');
  expect(res.statusCode).toBe(200);
  expect(res.body).toHaveProperty('ok', true);
});

// minimal validation test for register
test('register with missing body returns 400', async () => {
  const res = await request(app).post('/api/auth/register').send({});
  expect(res.statusCode).toBe(400);
});
