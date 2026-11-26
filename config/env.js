const crypto = require('crypto');

const isProd = process.env.NODE_ENV === 'production';

function resolveJwtSecret() {
  const raw = (process.env.JWT_SECRET || '').trim();
  if (raw && raw !== 'your_secret_key') {
    if (raw.length < 16) {
      console.warn(
        '[SECURITY WARNING] JWT_SECRET is shorter than 16 characters. Consider rotating to a 32+ char secret.'
      );
    }
    return raw;
  }

  // Fallback if JWT_SECRET was not set in hosting dashboard: derive deterministically from MONGO_URI if available
  if (process.env.MONGO_URI) {
    console.warn(
      '[SECURITY WARNING] JWT_SECRET is missing — deriving key via HMAC-SHA256. Set an explicit JWT_SECRET in your environment variables.'
    );
    return crypto
      .createHmac('sha256', process.env.MONGO_URI)
      .update('neurovia-jwt-signing-key-v1')
      .digest('hex');
  }

  return crypto.randomBytes(32).toString('hex');
}

function resolveSessionSecret(jwtSecret) {
  const raw = (process.env.SESSION_SECRET || '').trim();
  if (raw && raw !== 'some-strong-secret') {
    return raw;
  }
  // Derive a distinct strong session secret via HMAC so missing SESSION_SECRET never crashes production deploys
  return crypto
    .createHmac('sha256', jwtSecret)
    .update('neurovia-express-session-key-v1')
    .digest('hex');
}

const JWT_SECRET = resolveJwtSecret();
const SESSION_SECRET = resolveSessionSecret(JWT_SECRET);

const defaultOrigins = [
  'https://neurovia-tech-support.vercel.app',
  'https://neurovia.site',
  'https://www.neurovia.site',
];

if (!isProd) {
  defaultOrigins.push(
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'http://localhost:5173',
    'http://127.0.0.1:5173'
  );
}

if (process.env.FRONTEND_URL) {
  defaultOrigins.push(process.env.FRONTEND_URL.trim().replace(/\/+$/, ''));
}

if (process.env.ALLOWED_ORIGINS) {
  process.env.ALLOWED_ORIGINS.split(',')
    .map((o) => o.trim().replace(/\/+$/, ''))
    .filter(Boolean)
    .forEach((o) => defaultOrigins.push(o));
}

const ALLOWED_ORIGINS = Array.from(new Set(defaultOrigins));

// Company emails that receive Get in Touch, Booking, Beta Tester & Payment alerts
const companyEmailsRaw = process.env.COMPANY_TEAM_EMAILS || process.env.EMAIL_USER || 'support@neurovia.site';
const COMPANY_TEAM_EMAILS = Array.from(
  new Set(
    companyEmailsRaw
      .split(',')
      .map((e) => e.trim())
      .filter(Boolean)
  )
);

module.exports = {
  isProd,
  PORT: Number(process.env.PORT || process.env.APP_PORT || 8080),
  MONGO_URI: process.env.MONGO_URI || '',
  JWT_SECRET,
  SESSION_SECRET,
  FRONTEND_URL: (process.env.FRONTEND_URL || 'https://neurovia-tech-support.vercel.app').replace(/\/+$/, ''),
  BACKEND_URL: (
    process.env.BACKEND_URL ||
    (isProd
      ? 'https://neurovia-backend.onrender.com'
      : `http://localhost:${process.env.PORT || process.env.APP_PORT || 8080}`)
  ).replace(/\/+$/, ''),
  ALLOWED_ORIGINS,
  EMAIL_USER: process.env.EMAIL_USER || '',
  EMAIL_PASS: process.env.EMAIL_PASS || '',
  MAIL_RELAY_URL: (
    process.env.MAIL_RELAY_URL || 'https://neurovia-tech-support.vercel.app/api/mail-relay'
  ).trim(),
  COMPANY_TEAM_EMAILS,
  RAZORPAY_KEY_ID: (process.env.RAZORPAY_KEY_ID || '').trim(),
  RAZORPAY_KEY_SECRET: (process.env.RAZORPAY_KEY_SECRET || '').trim(),
  RAZORPAY_WEBHOOK_SECRET: (process.env.RAZORPAY_WEBHOOK_SECRET || '').trim(),
  ADMIN_USERNAME: (process.env.ADMIN_USERNAME || 'neurovia-admin').trim(),
  ADMIN_EMAIL: (process.env.ADMIN_EMAIL || process.env.EMAIL_USER || 'support@neurovia.site')
    .trim()
    .toLowerCase(),
  ADMIN_PASSWORD: process.env.ADMIN_PASSWORD || '',
};
