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

// Twilio imports
const twilio = require('twilio');
const AccessToken = twilio.jwt.AccessToken;
const VideoGrant = AccessToken.VideoGrant;
const ChatGrant = AccessToken.ChatGrant;

const app = express();

// CORS Configuration
app.use(cors({
  origin: 'http://localhost:3000', // Update for your frontend port
  credentials: true
}));

app.use(express.json());

// Session Configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'some-strong-secret',
  resave: false,
  saveUninitialized: false
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

// Google Strategy Configuration for MongoDB
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/api/auth/google/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      // Check if user already exists
      let existingUser = await User.findOne({ google_id: profile.id });

      if (existingUser) {
        return done(null, existingUser);
      }

      // If not, check if email exists from standard signup
      existingUser = await User.findOne({ email: profile.emails[0].value });
      if (existingUser) {
        // Link google account to existing email
        existingUser.google_id = profile.id;
        await existingUser.save();
        return done(null, existingUser);
      }

      // Create new user
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

// Twilio Token Generation Route 
app.post('/api/twilio/token', (req, res) => {
  const accountSid = process.env.TWILIO_ACCOUNT_SID;
  const apiKey = process.env.TWILIO_API_KEY;
  const apiSecret = process.env.TWILIO_API_SECRET;
  const chatServiceSid = process.env.TWILIO_CHAT_SERVICE_SID;

  const { identity, roomName } = req.body;

  if (!accountSid || !apiKey || !apiSecret) {
    console.error('Missing Twilio credentials');
    return res.status(500).json({ 
      error: 'Twilio credentials not configured'
    });
  }

  try {
    const token = new AccessToken(accountSid, apiKey, apiSecret, {
      identity: identity || `user_${Date.now()}`,
      ttl: 3600,
    });

    if (roomName) {
      const videoGrant = new VideoGrant({ room: roomName });
      token.addGrant(videoGrant);
    }

    if (chatServiceSid) {
      const chatGrant = new ChatGrant({ serviceSid: chatServiceSid });
      token.addGrant(chatGrant);
    }

    res.json({
      token: token.toJwt(),
      identity: identity || `user_${Date.now()}`,
      roomName: roomName
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to generate token' });
  }
});

// Get Twilio Configuration Status
app.get('/api/twilio/status', (req, res) => {
  res.json({
    configured: !!(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_API_KEY && process.env.TWILIO_API_SECRET),
  });
});

// Google OAuth Routes
app.get('/api/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/api/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login', session: false }),
  (req, res) => {
    const token = jwt.sign(
      { userId: req.user._id, username: req.user.username, email: req.user.email }, 
      JWT_SECRET,
      { expiresIn: '1h' }
    );
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    res.redirect(`${frontendUrl}/?token=${token}`);
  }
);

// Sign Up Route for MongoDB
app.post('/api/signup', async (req, res) => {
  const { username, password, email } = req.body;

  if (!username || !password || !email) {
    return res.status(400).json({ error: 'Username, password, and email are required' });
  }

  try {
    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(409).json({ error: 'Username or email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user in MongoDB
    await User.create({
      username,
      email,
      password: hashedPassword
    });

    // Send welcome email
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Welcome to Our App!',
      text: `Hello ${username},\n\nThank you for registering. We're glad to have you!`
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) console.error('Failed to send welcome email:', error);
    });

    res.status(201).json({ message: 'User registered and welcome email sent' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error during sign up' });
  }
});

// Login Route for MongoDB
app.post('/api/login', async (req, res) => {
  const { login, password } = req.body;

  try {
    // Find user by username OR email
    const user = await User.findOne({ $or: [{ email: login }, { username: login }] });

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (!user.password) {
      return res.status(401).json({ error: 'Please sign in with Google' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user._id, username: user.username, email: user.email }, 
      JWT_SECRET, 
      { expiresIn: '1h' }
    );

    res.json({ 
      message: 'Login successful', 
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Logout Route
app.post('/api/logout', (req, res) => {
  if (req.session) req.session.destroy();
  if (req.isAuthenticated && req.isAuthenticated()) req.logout((err) => {});
  
  res.clearCookie('connect.sid'); 
  res.clearCookie('session'); 
  res.clearCookie('authToken');
  
  res.json({ message: 'Logout successful', success: true });
});

// Profile Route
app.get('/api/profile', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Token required' });

  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });

    res.json({ 
      message: 'Access granted', 
      user: {
        id: decoded.userId,
        username: decoded.username,
        email: decoded.email
      }
    });
  });
});

// Start Server
const PORT = process.env.APP_PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});