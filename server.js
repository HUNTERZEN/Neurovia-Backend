require('dotenv').config();

const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose'); 
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');

// Import your new MongoDB User model
const User = require('./models/User'); 
const partnerRoutes = require('./routes/partner');

// Twilio imports
const twilio = require('twilio');
const AccessToken = twilio.jwt.AccessToken;
const VideoGrant = AccessToken.VideoGrant;
const ChatGrant = AccessToken.ChatGrant;

const app = express();

// ✅ CRITICAL FIX 1: Trust the Render Proxy
// This ensures that req.protocol returns 'https' instead of 'http'
app.set('trust proxy', 1);

// ✅ CRITICAL FIX 2: Update CORS for Production
const frontendUrl = process.env.FRONTEND_URL || 'https://neurovia-tech-support.vercel.app';

app.use(cors({
  origin: frontendUrl, 
  credentials: true
}));

app.use(express.json());

// Session Configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'some-strong-secret',
  resave: false,
  saveUninitialized: false,
  // ✅ Recommended for production with HTTPS
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('Connected to MongoDB database'))
  .catch((err) => {
    console.error('Database connection failed:', err);
    process.exit(1);
  });

const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key';

// Nodemailer setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// ✅ CRITICAL FIX 3: Passport Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    // Using an absolute URL with https or a relative path
    callbackURL: "https://neurovia-backend.onrender.com/api/auth/google/callback",
    proxy: true // Tells Passport to trust the proxy headers
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      let existingUser = await User.findOne({ google_id: profile.id });

      if (existingUser) {
        return done(null, existingUser);
      }

      existingUser = await User.findOne({ email: profile.emails[0].value });
      if (existingUser) {
        existingUser.google_id = profile.id;
        await existingUser.save();
        return done(null, existingUser);
      }

      const newUser = await User.create({
        username: profile.displayName || '',
        email: profile.emails[0].value,
        google_id: profile.id
      });

      return done(null, newUser);
    } catch (err) {
      return done(err, false);
    }
  }
));

passport.serializeUser((user, done) => done(null, user._id)); 
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Twilio Routes (Unchanged)
app.post('/api/twilio/token', (req, res) => {
  const accountSid = process.env.TWILIO_ACCOUNT_SID;
  const apiKey = process.env.TWILIO_API_KEY;
  const apiSecret = process.env.TWILIO_API_SECRET;
  const chatServiceSid = process.env.TWILIO_CHAT_SERVICE_SID;
  const { identity, roomName } = req.body;

  if (!accountSid || !apiKey || !apiSecret) {
    return res.status(500).json({ error: 'Twilio credentials not configured' });
  }

  try {
    const token = new AccessToken(accountSid, apiKey, apiSecret, {
      identity: identity || `user_${Date.now()}`,
      ttl: 3600,
    });
    if (roomName) token.addGrant(new VideoGrant({ room: roomName }));
    if (chatServiceSid) token.addGrant(new ChatGrant({ serviceSid: chatServiceSid }));
    res.json({ token: token.toJwt(), identity: identity || `user_${Date.now()}`, roomName });
  } catch (error) {
    res.status(500).json({ error: 'Failed to generate token' });
  }
});

app.get('/api/twilio/status', (req, res) => {
  res.json({ configured: !!(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_API_KEY) });
});

// Google OAuth Routes
app.get('/api/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/api/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/signin', session: false }),
  (req, res) => {
    const token = jwt.sign(
      { userId: req.user._id, username: req.user.username, email: req.user.email }, 
      JWT_SECRET,
      { expiresIn: '1h' }
    );
    // Uses the updated frontendUrl variable
    res.redirect(`${frontendUrl}/?token=${token}`);
  }
);

// Sign Up / Login / Profile Routes (Unchanged logic, pointing to MongoDB)
app.post('/api/signup', async (req, res) => {
  const { username, password, email } = req.body;
  if (!username || !password || !email) return res.status(400).json({ error: 'Missing fields' });
  try {
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) return res.status(409).json({ error: 'User exists' });
    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ username, email, password: hashedPassword });
    res.status(201).json({ message: 'User registered' });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { login, password } = req.body;
  try {
    const user = await User.findOne({ $or: [{ email: login }, { username: login }] });
    if (!user || !user.password || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ userId: user._id, username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: 'Login successful', token, user: { id: user._id, username: user.username, email: user.email } });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/logout', (req, res) => {
  if (req.session) req.session.destroy();
  res.clearCookie('connect.sid'); 
  res.json({ message: 'Logout successful', success: true });
});

app.get('/api/profile', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Token required' });
  const token = authHeader.split(' ')[1];
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    // Fetch full user details from DB excluding the password
    const user = await User.findById(decoded.userId).select('-password');
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    // Convert to a format expected by frontend. The _id needs to be accessible as 'id' too
    const userObj = user.toObject();
    res.json({ user: { ...userObj, id: userObj._id } });
  } catch (err) {
    res.status(403).json({ error: 'Invalid token' });
  }
});

// Update Profile route
app.put('/api/profile', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Token required' });
  const token = authHeader.split(' ')[1];
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const updatedData = req.body;
    
    // Prevent sensitive fields from being updated via this route
    delete updatedData.password;
    delete updatedData.email;
    delete updatedData.username;
    
    const updatedUser = await User.findByIdAndUpdate(
      decoded.userId,
      { $set: updatedData },
      { new: true, runValidators: true }
    ).select('-password');
    
    if (!updatedUser) return res.status(404).json({ error: 'User not found' });
    
    const userObj = updatedUser.toObject();
    res.json({ message: 'Profile updated successfully', user: { ...userObj, id: userObj._id } });
  } catch (err) {
    console.error('Profile update error:', err);
    res.status(403).json({ error: 'Invalid token or update failed' });
  }
});

app.use('/api/partner', partnerRoutes);

const PORT = process.env.APP_PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});