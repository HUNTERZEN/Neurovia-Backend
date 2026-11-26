const crypto = require('crypto');

const isProd = process.env.NODE_ENV === 'production';

function resolveSecret(envName) {
  const val = process.env[envName];
  if (val && val.trim().length >= 16) {
    return val.trim();
  }
  if (isProd) {
    throw new Error(`[SECURITY] Missing or weak ${envName} in production environment (must be >= 16 chars).`);
  }
  if (val && val.trim()) {
    console.warn(`[SECURITY WARNING] ${envName} is shorter than 16 characters. Use a stronger secret in production.`);
    return val.trim();
  }
  console.warn(`[SECURITY WARNING] ${envName} is not set. Using ephemeral random secret for local development.`);
  return crypto.randomBytes(32).toString('hex');
}

const JWT_SECRET = resolveSecret('JWT_SECRET');
const SESSION_SECRET = resolveSecret('SESSION_SECRET');

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
  BACKEND_URL: (process.env.BACKEND_URL || (isProd ? 'https://neurovia-backend.onrender.com' : `http://localhost:${process.env.PORT || process.env.APP_PORT || 8080}`)).replace(/\/+$/, ''),
  ALLOWED_ORIGINS,
  EMAIL_USER: process.env.EMAIL_USER || '',
  EMAIL_PASS: process.env.EMAIL_PASS || '',
  COMPANY_TEAM_EMAILS,
  RAZORPAY_KEY_ID: (process.env.RAZORPAY_KEY_ID || '').trim(),
  RAZORPAY_KEY_SECRET: (process.env.RAZORPAY_KEY_SECRET || '').trim(),
  RAZORPAY_WEBHOOK_SECRET: (process.env.RAZORPAY_WEBHOOK_SECRET || '').trim(),
  ADMIN_USERNAME: (process.env.ADMIN_USERNAME || 'neurovia-admin').trim(),
  ADMIN_EMAIL: (process.env.ADMIN_EMAIL || process.env.EMAIL_USER || 'support@neurovia.site').trim().toLowerCase(),
  ADMIN_PASSWORD: process.env.ADMIN_PASSWORD || '',
};

