require('dotenv').config();

const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const twilio = require('twilio');

const connectDB = require('./config/db');
const {
  isProd,
  PORT,
  JWT_SECRET,
  SESSION_SECRET,
  FRONTEND_URL,
  BACKEND_URL,
  ALLOWED_ORIGINS,
  RAZORPAY_KEY_ID,
  RAZORPAY_KEY_SECRET,
} = require('./config/env');
const {
  mongoSanitizeMiddleware,
  cleanStr,
  isValidEmail,
  globalLimiter,
  authLimiter,
} = require('./middleware/security');
const { authMiddleware, optionalAuthMiddleware } = require('./authMiddleware');
const {
  isEmailConfigured,
  sendWelcomeSignupEmail,
  sendPasswordResetEmail,
} = require('./services/emailService');

const User = require('./models/User');
const partnerRoutes = require('./routes/partner');
const paymentRoutes = require('./routes/paymentRoutes');
const formsRoutes = require('./routes/formsRoutes');
const technicianRoutes = require('./routes/technicianRoutes');
const adminRoutes = require('./routes/adminRoutes');

const AccessToken = twilio.jwt.AccessToken;
const VideoGrant = AccessToken.VideoGrant;
const ChatGrant = AccessToken.ChatGrant;

const app = express();

// 1. Trust reverse proxy (Render / Vercel)
app.set('trust proxy', 1);
app.disable('x-powered-by');

// 2. HTTP Security Headers
app.use(
  helmet({
    crossOriginResourcePolicy: { policy: 'cross-origin' },
  })
);

if (!isProd) {
  app.use(morgan('dev'));
}

// 3. Strict CORS Allowlist
app.use(
  cors({
    origin: (origin, callback) => {
      // Allow server-to-server / health checks with no Origin header
      if (!origin) return callback(null, true);
      const normalized = origin.replace(/\/+$/, '');
      if (
        ALLOWED_ORIGINS.includes(normalized) ||
        /^https:\/\/neurovia-tech-support[a-z0-9-]*\.vercel\.app$/i.test(normalized)
      ) {
        return callback(null, true);
      }
      return callback(new Error('Origin not allowed by CORS'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

// 4. Body Parsers with strict payload size limits & NoSQL operator sanitization
// Preserve raw body only on /api/payments/webhook for Razorpay HMAC verification
app.use((req, res, next) => {
  if (req.originalUrl.startsWith('/api/payments/webhook')) {
    return next();
  }
  return express.json({ limit: '1mb' })(req, res, next);
});
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(mongoSanitizeMiddleware);
app.use('/api', globalLimiter);

// 5. Hardened Session Configuration
const cookieOptions = {
  httpOnly: true,
  secure: isProd,
  sameSite: isProd ? 'none' : 'lax',
  maxAge: 24 * 60 * 60 * 1000,
};

app.use(
  session({
    name: 'nv.sid',
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: cookieOptions,
  })
);

app.use(passport.initialize());
app.use(passport.session());

// 6. Connect MongoDB
connectDB().catch((err) => {
  console.error('Database connection failed:', err.message);
  process.exit(1);
});

// 7. Google OAuth Strategy (guarded when credentials exist)
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: `${BACKEND_URL}/api/auth/google/callback`,
        proxy: true,
      },
      async (_accessToken, _refreshToken, profile, done) => {
        try {
          const email = profile.emails?.[0]?.value?.trim().toLowerCase();
          if (!email) {
            return done(new Error('Google profile did not provide an email address'), false);
          }

          let existingUser = await User.findOne({ google_id: profile.id });
          if (existingUser) {
            return done(null, existingUser);
          }

          existingUser = await User.findOne({ email });
          if (existingUser) {
            existingUser.google_id = profile.id;
            await existingUser.save();
            return done(null, existingUser);
          }

          const displayName = cleanStr(profile.displayName || email.split('@')[0], 64);
          const newUser = await User.create({
            username: displayName,
            fullName: displayName,
            email,
            google_id: profile.id,
          });

          return done(null, newUser);
        } catch (err) {
          return done(err, false);
        }
      }
    )
  );
}

passport.serializeUser((user, done) => done(null, user._id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id).select('-password');
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

/* ─── Twilio Routes (Authenticated to prevent quota abuse) ─── */
app.post('/api/twilio/token', authMiddleware, (req, res) => {
  const accountSid = process.env.TWILIO_ACCOUNT_SID;
  const apiKey = process.env.TWILIO_API_KEY;
  const apiSecret = process.env.TWILIO_API_SECRET;
  const chatServiceSid = process.env.TWILIO_CHAT_SERVICE_SID;
  const roomName = cleanStr(req.body.roomName, 80).replace(/[^a-zA-Z0-9_-]/g, '');

  if (!accountSid || !apiKey || !apiSecret) {
    return res.status(503).json({ error: 'Twilio credentials not configured' });
  }

  try {
    const identity = `user_${req.user.userId}`;
    const token = new AccessToken(accountSid, apiKey, apiSecret, {
      identity,
      ttl: 3600,
    });
    if (roomName) token.addGrant(new VideoGrant({ room: roomName }));
    if (chatServiceSid) token.addGrant(new ChatGrant({ serviceSid: chatServiceSid }));
    return res.json({ token: token.toJwt(), identity, roomName });
  } catch (_error) {
    return res.status(500).json({ error: 'Failed to generate token' });
  }
});

app.get('/api/twilio/status', (_req, res) => {
  res.json({ configured: Boolean(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_API_KEY) });
});

/* ─── Google OAuth Routes ─── */
app.get('/api/auth/google', (req, res, next) => {
  if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
    return res.redirect(`${FRONTEND_URL}/signin?error=google_not_configured`);
  }
  return passport.authenticate('google', { scope: ['profile', 'email'] })(req, res, next);
});

app.get(
  '/api/auth/google/callback',
  passport.authenticate('google', { failureRedirect: `${FRONTEND_URL}/signin`, session: false }),
  (req, res) => {
    const token = jwt.sign(
      { userId: req.user._id, username: req.user.username, email: req.user.email, role: req.user.role || 'user' },
      JWT_SECRET,
      { expiresIn: '7d', algorithm: 'HS256' }
    );
    res.redirect(`${FRONTEND_URL}/?token=${encodeURIComponent(token)}`);
  }
);

/* ─── Session / Token Check Route ─── */
app.get('/api/auth/check', optionalAuthMiddleware, async (req, res) => {
  try {
    const userId = req.user?.userId || req.session?.passport?.user;
    if (!userId) {
      return res.json({ authenticated: false });
    }
    const user = await User.findById(userId).select('-password');
    if (!user) {
      return res.json({ authenticated: false });
    }
    return res.json({
      authenticated: true,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        name: user.fullName || user.username,
        role: user.role,
      },
    });
  } catch (_err) {
    return res.json({ authenticated: false });
  }
});

/* ─── User Auth Routes (Hardened against NoSQL injection & brute force) ─── */
app.post('/api/signup', authLimiter, async (req, res) => {
  const username = cleanStr(req.body.username, 64);
  const fullName = cleanStr(req.body.fullName, 120);
  const email = cleanStr(req.body.email, 254).toLowerCase();
  const password = typeof req.body.password === 'string' ? req.body.password : '';

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address' });
  }
  if (password.length < 6 || password.length > 128) {
    return res.status(400).json({ error: 'Password must be between 6 and 128 characters' });
  }

  try {
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(409).json({
        error: existingUser.email === email ? 'Email is already registered' : 'Username is already taken',
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const created = await User.create({
      username,
      fullName: fullName || username,
      email,
      password: hashedPassword,
    });

    sendWelcomeSignupEmail({ email: created.email, name: created.fullName || created.username }).catch(
      (err) => console.error('Signup welcome email error:', err.message)
    );

    return res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Signup error:', error.message);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', authLimiter, async (req, res) => {
  const loginRaw = cleanStr(req.body.login || req.body.username || req.body.email, 254);
  const password = typeof req.body.password === 'string' ? req.body.password : '';

  if (!loginRaw || !password) {
    return res.status(400).json({ error: 'Username/email and password are required' });
  }

  try {
    const user = await User.findOne({
      $or: [{ email: loginRaw.toLowerCase() }, { username: loginRaw }],
    });

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    if (!user.password) {
      return res.status(400).json({
        error: 'This account uses Google Sign-In. Please continue with Google.',
      });
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user._id, username: user.username, email: user.email, role: user.role || 'user' },
      JWT_SECRET,
      { expiresIn: '7d', algorithm: 'HS256' }
    );

    return res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        name: user.fullName || user.username,
        role: user.role,
      },
    });
  } catch (error) {
    console.error('Login error:', error.message);
    return res.status(500).json({ error: 'Server error' });
  }
});

/* ─── Forgot & Reset Password via Email ─── */
app.post('/api/auth/forgot-password', authLimiter, async (req, res) => {
  const email = cleanStr(req.body.email, 254).toLowerCase();
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }

  try {
    const user = await User.findOne({ email });
    // Always return generic success message to prevent email enumeration
    if (user) {
      const rawToken = crypto.randomBytes(32).toString('hex');
      const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
      user.resetPasswordTokenHash = tokenHash;
      user.resetPasswordExpires = new Date(Date.now() + 30 * 60 * 1000);
      await user.save();

      const resetUrl = `${FRONTEND_URL}/reset-password?token=${rawToken}&email=${encodeURIComponent(email)}`;
      await sendPasswordResetEmail({
        email: user.email,
        name: user.fullName || user.username,
        resetUrl,
      });
    }

    return res.json({
      success: true,
      message: 'If an account exists for that email, a password reset link has been sent.',
    });
  } catch (err) {
    console.error('Forgot password error:', err.message);
    return res.status(500).json({ error: 'Unable to process request right now.' });
  }
});

app.post('/api/auth/reset-password', authLimiter, async (req, res) => {
  const email = cleanStr(req.body.email, 254).toLowerCase();
  const token = cleanStr(req.body.token, 128);
  const newPassword = typeof req.body.password === 'string' ? req.body.password : '';

  if (!isValidEmail(email) || !token || newPassword.length < 6 || newPassword.length > 128) {
    return res.status(400).json({ error: 'Invalid reset token or password (min 6 characters).' });
  }

  try {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const user = await User.findOne({
      email,
      resetPasswordTokenHash: tokenHash,
      resetPasswordExpires: { $gt: new Date() },
    }).select('+resetPasswordTokenHash +resetPasswordExpires');

    if (!user) {
      return res.status(400).json({ error: 'Reset link is invalid or has expired.' });
    }

    user.password = await bcrypt.hash(newPassword, 12);
    user.resetPasswordTokenHash = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    return res.json({ success: true, message: 'Password updated! You can now sign in.' });
  } catch (err) {
    console.error('Reset password error:', err.message);
    return res.status(500).json({ error: 'Could not reset password.' });
  }
});

app.post('/api/logout', (req, res) => {
  if (req.session) {
    req.session.destroy(() => {});
  }
  res.clearCookie('nv.sid', {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
  });
  res.clearCookie('connect.sid');
  return res.json({ message: 'Logout successful', success: true });
});

/* ─── Profile Routes (Strict Field Whitelisting) ─── */
app.get('/api/profile', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) return res.status(404).json({ error: 'User not found' });

    const userObj = user.toObject();
    return res.json({ user: { ...userObj, id: userObj._id } });
  } catch (_err) {
    return res.status(500).json({ error: 'Failed to load profile' });
  }
});

const ALLOWED_PROFILE_FIELDS = [
  ['fullName', 120],
  ['phone', 30],
  ['location', 120],
  ['profession', 120],
  ['company', 120],
  ['bio', 1000],
  ['website', 255],
  ['github', 255],
  ['linkedin', 255],
  ['twitter', 255],
  ['profileImage', 500],
];

app.put('/api/profile', authMiddleware, async (req, res) => {
  try {
    const safeUpdate = {};
    for (const [field, maxLen] of ALLOWED_PROFILE_FIELDS) {
      if (Object.prototype.hasOwnProperty.call(req.body, field) && typeof req.body[field] === 'string') {
        safeUpdate[field] = cleanStr(req.body[field], maxLen);
      }
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.user.userId,
      { $set: safeUpdate },
      { new: true, runValidators: true }
    ).select('-password');

    if (!updatedUser) return res.status(404).json({ error: 'User not found' });

    const userObj = updatedUser.toObject();
    return res.json({
      message: 'Profile updated successfully',
      user: { ...userObj, id: userObj._id },
    });
  } catch (err) {
    console.error('Profile update error:', err.message);
    return res.status(400).json({ error: 'Invalid profile update data' });
  }
});

/* ─── Feature Routers ─── */
app.use('/api/partner', partnerRoutes);
app.use('/api/payments', paymentRoutes);
app.use('/api/technician', technicianRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api', formsRoutes);

/* ─── Health & Service Readiness Check ─── */
app.get('/health', (_req, res) => {
  res.status(200).json({
    status: 'ok',
    uptime: process.uptime(),
    services: {
      emailConfigured: isEmailConfigured(),
      razorpayConfigured: Boolean(RAZORPAY_KEY_ID && RAZORPAY_KEY_SECRET),
    },
  });
});

/* ─── Global Error Handler (Never leaks stack traces) ─── */
app.use((err, _req, res, _next) => {
  if (err && err.message === 'Origin not allowed by CORS') {
    return res.status(403).json({ error: 'Origin not allowed by CORS' });
  }
  console.error('Unhandled server error:', err.message);
  return res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`Neurovia server running on port ${PORT}`);
});
