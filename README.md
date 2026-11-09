# LearnHub LMS: login module
Run: `npm install && npm start`, then open http://localhost:3000
Demo account is created on first run (see console). Set `JWT_SECRET` and `NODE_ENV=production` when deploying (HTTPS required).
Integrating: mount `/api/auth/*` and the `auth` middleware in your existing Express app, and point your LMS users table at the same columns.
Still to build: `reset-password.html` + `POST /api/auth/reset` (token is already stored hashed with a 30-minute expiry) and email sending.
