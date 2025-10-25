import http from 'k6/http';
import { check, sleep } from 'k6';
import { randomString } from 'k6/data';

export const options = {
  stages: [
    { duration: '30s', target: 5 },  // Ramp up to 5 users
    { duration: '1m', target: 10 },  // Ramp up to 10 users
    { duration: '2m', target: 10 },  // Stay at 10 users
    { duration: '30s', target: 0 },  // Ramp down to 0 users
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'], // 95% of requests should be below 500ms
    http_req_failed: ['rate<0.01'],   // Less than 1% of requests should fail
  },
};

const BASE_URL = 'http://localhost:4000';

export default function () {
  // Register a new user
  const email = `${randomString(10)}@test.com`;
  const password = 'TestPass123';
  
  const registerRes = http.post(`${BASE_URL}/api/auth/register`, JSON.stringify({
    email: email,
    password: password,
    name: 'Test User'
  }), {
    headers: { 'Content-Type': 'application/json' }
  });

  check(registerRes, {
    'register successful': (r) => r.status === 200,
    'has tokens': (r) => r.json('accessToken') !== undefined && r.json('refreshToken') !== undefined,
  });

  sleep(1);

  // Login with the new user
  const loginRes = http.post(`${BASE_URL}/api/auth/login`, JSON.stringify({
    email: email,
    password: password
  }), {
    headers: { 'Content-Type': 'application/json' }
  });

  check(loginRes, {
    'login successful': (r) => r.status === 200,
    'has access token': (r) => r.json('accessToken') !== undefined,
  });

  const accessToken = loginRes.json('accessToken');

  sleep(1);

  // Access protected route
  const meRes = http.get(`${BASE_URL}/api/auth/me`, {
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    }
  });

  check(meRes, {
    'protected route accessible': (r) => r.status === 200,
    'has user id': (r) => r.json('userId') !== undefined,
  });

  sleep(1);

  // Test verification code request
  const verifyRes = http.post(`${BASE_URL}/api/auth/verify/code`, JSON.stringify({
    email: email
  }), {
    headers: { 'Content-Type': 'application/json' }
  });

  check(verifyRes, {
    'verification code request successful': (r) => r.status === 200,
  });

  sleep(1);
}