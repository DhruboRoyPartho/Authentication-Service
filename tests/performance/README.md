# Performance Testing with k6

This guide explains how to run performance tests for the auth service using k6.

## Prerequisites

1. Install k6:
   - Windows (using Chocolatey): `choco install k6`
   - Windows (using winget): `winget install k6`
   - macOS: `brew install k6`
   - Linux: Follow [k6 installation guide](https://k6.io/docs/getting-started/installation)

## Running Tests

1. Start the auth service in test mode:
   ```bash
   npm run dev
   ```

2. In a new terminal, run the performance test:
   ```bash
   k6 run tests/performance/k6-auth-flow.js
   ```

## Test Scenarios

The performance test includes:
1. User registration
2. Login
3. Protected route access
4. Verification code request

## Performance Targets

- Response Time (95th percentile): < 500ms
- Error Rate: < 1%
- Load Stages:
  - 0-30s: Ramp up to 5 users
  - 30s-90s: Ramp up to 10 users
  - 90s-210s: Stay at 10 users
  - 210s-240s: Ramp down to 0

## Analyzing Results

k6 will output:
- HTTP request statistics
- Response time metrics
- Error rates
- Custom checks results

## Common Issues

1. If MongoDB connection errors occur during high load:
   - Increase MongoDB max connections
   - Add connection pooling
   - Add retry logic

2. If response times are high:
   - Check database indexes
   - Enable request caching
   - Optimize database queries

## Performance Optimization Tips

1. Database:
   - Ensure proper indexes on email and token fields
   - Use connection pooling
   - Consider caching frequent queries

2. API:
   - Use compression middleware
   - Implement rate limiting
   - Cache JWT public key
   - Use connection keep-alive

3. Node.js:
   - Set appropriate max-old-space-size
   - Enable clustering using worker threads
   - Monitor memory usage
   - Use async operations appropriately