const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Partner = require('../models/Partner');
const ContactMessage = require('../models/ContactMessage');
const Booking = require('../models/Booking');
const BetaTester = require('../models/BetaTester');
const NewsletterSubscriber = require('../models/NewsletterSubscriber');
const Payment = require('../models/Payment');
const { JWT_SECRET, ADMIN_USERNAME, ADMIN_EMAIL, ADMIN_PASSWORD } = require('../config/env');
const { cleanStr, authLimiter } = require('../middleware/security');
const { adminAuthMiddleware } = require('../authMiddleware');

const router = express.Router();

function timingSafeStringMatch(expected, actual) {
  if (!expected || !actual) return false;
  const h1 = crypto.createHash('sha256').update(String(expected)).digest();
  const h2 = crypto.createHash('sha256').update(String(actual)).digest();
  return crypto.timingSafeEqual(h1, h2);
}

// POST /api/admin/login — Secure backend-verified Admin authentication
router.post('/login', authLimiter, async (req, res) => {
  try {
    const login = cleanStr(req.body.username || req.body.email || req.body.login, 254);
    const password = typeof req.body.password === 'string' ? req.body.password : '';

    if (!login || !password) {
      return res.status(400).json({ error: 'Username/email and password are required.' });
    }

    let authenticatedAdmin = null;

    // 1) Check configured ADMIN_PASSWORD from server environment
    if (ADMIN_PASSWORD) {
      const idMatches =
        timingSafeStringMatch(ADMIN_USERNAME, login) ||
        timingSafeStringMatch(ADMIN_EMAIL, login.toLowerCase());
      const passMatches = timingSafeStringMatch(ADMIN_PASSWORD, password);
      if (idMatches && passMatches) {
        authenticatedAdmin = {
          id: 'env-admin',
          username: ADMIN_USERNAME,
          email: ADMIN_EMAIL,
        };
      }
    }

    // 2) Or check MongoDB User with role === 'admin'
    if (!authenticatedAdmin) {
      const dbAdmin = await User.findOne({
        role: 'admin',
        $or: [{ email: login.toLowerCase() }, { username: login }],
      });
      if (dbAdmin && dbAdmin.password && (await bcrypt.compare(password, dbAdmin.password))) {
        authenticatedAdmin = {
          id: String(dbAdmin._id),
          username: dbAdmin.username,
          email: dbAdmin.email,
        };
      }
    }

    if (!authenticatedAdmin) {
      if (!ADMIN_PASSWORD) {
        return res.status(401).json({
          error:
            'Invalid admin credentials. Set ADMIN_USERNAME & ADMIN_PASSWORD in server123/.env or assign role="admin" to your User in MongoDB.',
        });
      }
      return res.status(401).json({ error: 'Invalid admin credentials.' });
    }

    const token = jwt.sign(
      {
        adminId: authenticatedAdmin.id,
        username: authenticatedAdmin.username,
        email: authenticatedAdmin.email,
        role: 'admin',
      },
      JWT_SECRET,
      { expiresIn: '8h', algorithm: 'HS256' }
    );

    return res.json({
      token,
      admin: authenticatedAdmin,
    });
  } catch (err) {
    console.error('Admin login error:', err.message);
    return res.status(500).json({ error: 'Admin authentication failed.' });
  }
});

// Protect all routes below with adminAuthMiddleware
router.use(adminAuthMiddleware);

// GET /api/admin/overview — Live company dashboard metrics & recent activity
router.get('/overview', async (_req, res) => {
  try {
    const [
      totalUsers,
      totalPartners,
      totalMessages,
      unreadMessages,
      totalBookings,
      pendingBookings,
      totalBetaTesters,
      totalNewsletter,
      paidPayments,
      recentMessages,
      recentBookings,
      recentPayments,
    ] = await Promise.all([
      User.countDocuments({}),
      Partner.countDocuments({}),
      ContactMessage.countDocuments({}),
      ContactMessage.countDocuments({ status: 'new' }),
      Booking.countDocuments({}),
      Booking.countDocuments({ status: 'pending' }),
      BetaTester.countDocuments({}),
      NewsletterSubscriber.countDocuments({ active: true }),
      Payment.find({ status: 'paid' }).select('amountInr').lean(),
      ContactMessage.find({}).sort({ createdAt: -1 }).limit(5).lean(),
      Booking.find({}).sort({ createdAt: -1 }).limit(5).lean(),
      Payment.find({ status: 'paid' }).sort({ createdAt: -1 }).limit(5).lean(),
    ]);

    const totalRevenueInr = paidPayments.reduce((sum, p) => sum + (p.amountInr || 0), 0);

    return res.json({
      stats: {
        totalUsers,
        totalPartners,
        totalMessages,
        unreadMessages,
        totalBookings,
        pendingBookings,
        totalBetaTesters,
        totalNewsletter,
        totalRevenueInr,
        paidOrdersCount: paidPayments.length,
      },
      recentMessages,
      recentBookings,
      recentPayments,
    });
  } catch (err) {
    console.error('Admin overview error:', err.message);
    return res.status(500).json({ error: 'Failed to load dashboard overview.' });
  }
});

// GET /api/admin/messages — All Get-in-Touch messages
router.get('/messages', async (_req, res) => {
  try {
    const messages = await ContactMessage.find({}).sort({ createdAt: -1 }).limit(200).lean();
    return res.json({ messages });
  } catch (_err) {
    return res.status(500).json({ error: 'Failed to fetch contact messages.' });
  }
});

// PATCH /api/admin/messages/:id — Update contact message status
router.patch('/messages/:id', async (req, res) => {
  try {
    const status = cleanStr(req.body.status, 30);
    if (!['new', 'read', 'in_progress', 'resolved'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }
    const updated = await ContactMessage.findByIdAndUpdate(
      req.params.id,
      { $set: { status } },
      { new: true }
    );
    if (!updated) return res.status(404).json({ error: 'Message not found' });
    return res.json({ message: updated });
  } catch (_err) {
    return res.status(500).json({ error: 'Failed to update message status.' });
  }
});

// GET /api/admin/bookings — All support bookings
router.get('/bookings', async (_req, res) => {
  try {
    const bookings = await Booking.find({}).sort({ createdAt: -1 }).limit(200).lean();
    return res.json({ bookings });
  } catch (_err) {
    return res.status(500).json({ error: 'Failed to fetch bookings.' });
  }
});

// PATCH /api/admin/bookings/:id — Update booking status
router.patch('/bookings/:id', async (req, res) => {
  try {
    const status = cleanStr(req.body.status, 30);
    if (!['pending', 'assigned', 'in_progress', 'resolved', 'cancelled'].includes(status)) {
      return res.status(400).json({ error: 'Invalid booking status' });
    }
    const updated = await Booking.findByIdAndUpdate(
      req.params.id,
      { $set: { status } },
      { new: true }
    );
    if (!updated) return res.status(404).json({ error: 'Booking not found' });
    return res.json({ booking: updated });
  } catch (_err) {
    return res.status(500).json({ error: 'Failed to update booking.' });
  }
});

// GET /api/admin/users
router.get('/users', async (_req, res) => {
  try {
    const users = await User.find({}).select('-password').sort({ createdAt: -1 }).limit(200).lean();
    return res.json({ users });
  } catch (_err) {
    return res.status(500).json({ error: 'Failed to fetch users.' });
  }
});

// GET /api/admin/partners
router.get('/partners', async (_req, res) => {
  try {
    const partners = await Partner.find({}).sort({ createdAt: -1 }).limit(200).lean();
    return res.json({ partners });
  } catch (_err) {
    return res.status(500).json({ error: 'Failed to fetch partners.' });
  }
});

// GET /api/admin/beta-testers
router.get('/beta-testers', async (_req, res) => {
  try {
    const [betaTesters, subscribers] = await Promise.all([
      BetaTester.find({}).sort({ createdAt: -1 }).limit(200).lean(),
      NewsletterSubscriber.find({}).sort({ createdAt: -1 }).limit(200).lean(),
    ]);
    return res.json({ betaTesters, subscribers });
  } catch (_err) {
    return res.status(500).json({ error: 'Failed to fetch beta testers.' });
  }
});

// GET /api/admin/payments
router.get('/payments', async (_req, res) => {
  try {
    const payments = await Payment.find({}).sort({ createdAt: -1 }).limit(200).lean();
    return res.json({ payments });
  } catch (_err) {
    return res.status(500).json({ error: 'Failed to fetch payments.' });
  }
});

module.exports = router;

