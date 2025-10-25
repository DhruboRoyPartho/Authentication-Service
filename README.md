# Auth Service (Node.js + Express + MongoDB)

A customizable authentication microservice scaffold suitable for embedding in microservice systems and for local development.

Features:
- Register, login
- JWT access token + refresh token rotation
- Password hashing (bcrypt)
- Role support on user
- Basic email stub for integration

Getting started (local):

1. Copy `.env.example` to `.env` and fill in `MONGO_URI` and `JWT_SECRET`.
2. Install dependencies:

```powershell
npm install
```

3. Run in development mode (auto-restart on change):

```powershell
npm run dev
```

4. API endpoints:
- POST /api/auth/register { email, password, name? }
- POST /api/auth/login { email, password }
- POST /api/auth/refresh { token }
- POST /api/auth/logout { token }
- GET /api/auth/me (requires Authorization: Bearer <accessToken>)
- GET /api/auth/verify?token=<token> (verify via token link)

Verification code flow (sandbox)
- POST /api/auth/verify/code { email } - send a 6-digit verification code to the provided email (Ethereal sandbox by default)
- POST /api/auth/verify/code/confirm { email, code } - confirm the 6-digit code and mark email as verified

Notes:
- The mailer is a stub in `src/utils/mailer.js`. Swap in a real provider in production.
- Refresh tokens are stored on the user document for simple revocation/rotation. For production, consider persistent storage and more robust rotation.

Customization:
- Replace the mailer with your provider
- Add email verification flows
- Add OAuth providers (Google, Facebook) via additional routes

Email verification details
- By default the service uses Ethereal (nodemailer) in sandbox mode so emails are not delivered to real recipients. The register endpoint sends a verification link and you can also request a numeric verification code using `/api/auth/verify/code`.
- After calling `/api/auth/verify/code`, the response will include a `mailResult` object. For Ethereal this contains a `previewUrl` you can open to see the email with the code.
- Codes expire after 10 minutes. Token links expire after 1 hour.
 - Codes expire after the duration configured by `VERIFY_CODE_TTL_MS` (default 600000 ms = 10 minutes).
 - To prevent abuse there's a resend cooldown controlled by `VERIFY_RESEND_COOLDOWN_MS` (default 60000 ms = 60s). If you request a new code before the cooldown has passed you'll receive a 429 with `retryAfterSec`.
 - Maximum attempts for a code while active are controlled by `VERIFY_MAX_ATTEMPTS` (default 5). After hitting this limit you must wait until the code expires to request a new one.

Configuration via environment variables (add to `.env`):

- VERIFY_CODE_TTL_MS=600000
- VERIFY_RESEND_COOLDOWN_MS=60000
- VERIFY_MAX_ATTEMPTS=5

Testing:

```powershell
npm test
```

License: MIT
