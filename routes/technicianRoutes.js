const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Partner = require('../models/Partner');
const Booking = require('../models/Booking');
const { JWT_SECRET } = require('../config/env');
const { cleanStr, authLimiter } = require('../middleware/security');
const { technicianAuthMiddleware } = require('../authMiddleware');

const router = express.Router();

// POST /api/technician/login
router.post('/login', authLimiter, async (req, res) => {
  try {
    const email = cleanStr(req.body.email, 254).toLowerCase();
    const password = typeof req.body.password === 'string' ? req.body.password : '';

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await User.findOne({ email });
    if (!user || !user.password) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const partner = await Partner.findOne({ userId: user._id });
    if (user.role !== 'technician' && user.role !== 'partner' && user.role !== 'admin' && !partner) {
      return res.status(403).json({
        error: 'This account is not registered as a Technician or Partner yet.',
      });
    }

    const token = jwt.sign(
      {
        userId: user._id,
        email: user.email,
        role: user.role === 'user' ? 'partner' : user.role,
      },
      JWT_SECRET,
      { expiresIn: '8h', algorithm: 'HS256' }
    );

    const totalTickets = await Booking.countDocuments({});
    const resolvedTickets = await Booking.countDocuments({ status: 'resolved' });

    return res.json({
      token,
      technician: {
        id: user._id,
        name: partner?.ownerName || user.fullName || user.username,
        email: user.email,
        specialization: partner?.specializations?.[0] || user.profession || 'IT Support Specialist',
        rating: 4.9,
        totalTickets,
        resolvedTickets,
        activeTickets: Math.max(0, totalTickets - resolvedTickets),
      },
    });
  } catch (err) {
    console.error('Technician login error:', err.message);
    return res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/technician/profile
router.get('/profile', technicianAuthMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.technician.userId).select('-password');
    if (!user) return res.status(404).json({ error: 'Technician not found' });

    const partner = await Partner.findOne({ userId: user._id });
    const totalTickets = await Booking.countDocuments({});
    const resolvedTickets = await Booking.countDocuments({ status: 'resolved' });

    return res.json({
      technician: {
        id: user._id,
        name: partner?.ownerName || user.fullName || user.username,
        email: user.email,
        phone: partner?.phone || user.phone || '',
        location: partner ? `${partner.city}, ${partner.state}` : user.location || 'Assam, India',
        specialization: partner?.specializations?.join(', ') || user.profession || 'IT Specialist',
        experience: parseInt(partner?.experience || '2', 10) || 2,
        rating: 4.9,
        certifications: partner?.certifications
          ? partner.certifications.split(',').map((c) => c.trim()).filter(Boolean)
          : ['Neurovia Verified Specialist'],
        bio: partner?.description || user.bio || '',
        totalTickets,
        resolvedTickets,
        activeTickets: Math.max(0, totalTickets - resolvedTickets),
      },
    });
  } catch (err) {
    console.error('Technician profile error:', err.message);
    return res.status(500).json({ error: 'Failed to load profile' });
  }
});

// PUT /api/technician/profile
router.put('/profile', technicianAuthMiddleware, async (req, res) => {
  try {
    const allowed = {
      fullName: cleanStr(req.body.name, 120),
      phone: cleanStr(req.body.phone, 30),
      location: cleanStr(req.body.location, 120),
      profession: cleanStr(req.body.specialization, 120),
      bio: cleanStr(req.body.bio, 1000),
    };

    await User.findByIdAndUpdate(req.technician.userId, { $set: allowed });
    return res.json({ success: true });
  } catch (err) {
    console.error('Technician update error:', err.message);
    return res.status(500).json({ error: 'Failed to update profile' });
  }
});

// POST /api/technician/logout
router.post('/logout', (_req, res) => {
  res.json({ success: true });
});

module.exports = router;

