const express = require('express');
const crypto = require('crypto');
const multer = require('multer');
const BetaTester = require('../models/BetaTester');
const ContactMessage = require('../models/ContactMessage');
const Booking = require('../models/Booking');
const NewsletterSubscriber = require('../models/NewsletterSubscriber');
const { cleanStr, isValidEmail, formLimiter } = require('../middleware/security');
const { optionalAuthMiddleware } = require('../authMiddleware');
const {
  sendBetaTesterEmails,
  sendContactMessageEmails,
  sendBookingEmails,
  sendNewsletterEmail,
} = require('../services/emailService');

const router = express.Router();

// Safe memory upload for optional booking screenshots (max 5 images, max 5 MB each)
const ALLOWED_IMAGE_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp']);
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    files: 5,
    fileSize: 5 * 1024 * 1024,
  },
  fileFilter: (_req, file, cb) => {
    if (ALLOWED_IMAGE_TYPES.has(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only JPG, PNG, and WebP images are allowed.'));
    }
  },
});

function generateRef(prefix) {
  const d = new Date();
  const ym = `${String(d.getFullYear()).slice(2)}${String(d.getMonth() + 1).padStart(2, '0')}`;
  const rand = crypto.randomInt(1000, 9999);
  return `${prefix}${ym}-${rand}`;
}

// POST /api/beta-tester — Register Beta Tester & send confirmation + company alert emails
router.post('/beta-tester', formLimiter, async (req, res) => {
  try {
    const email = cleanStr(req.body.email, 254).toLowerCase();
    const name = cleanStr(req.body.name, 120);

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    }

    let existing = await BetaTester.findOne({ email });
    const alreadyRegistered = Boolean(existing);

    if (!existing) {
      existing = await BetaTester.create({ email, name });
    }

    const mailResult = await sendBetaTesterEmails({ email, name, alreadyRegistered });
    if (mailResult.sent && !existing.emailSent) {
      existing.emailSent = true;
      await existing.save();
    }

    return res.status(alreadyRegistered ? 200 : 201).json({
      success: true,
      alreadyRegistered,
      emailSent: mailResult.sent,
      message: alreadyRegistered
        ? "You're already registered in our Beta Programme! We sent a fresh confirmation to your inbox."
        : 'Welcome to the Neurovia Beta Programme! Check your email inbox for confirmation.',
    });
  } catch (err) {
    console.error('Beta tester registration error:', err.message);
    return res.status(500).json({ error: 'Could not complete registration right now. Please try again.' });
  }
});

// POST /api/contact — Get in Touch form: stores inquiry + emails company team & sender
router.post('/contact', formLimiter, async (req, res) => {
  try {
    const name = cleanStr(req.body.name, 120);
    const email = cleanStr(req.body.email, 254).toLowerCase();
    const phone = cleanStr(req.body.phone, 30);
    const subject = cleanStr(req.body.subject, 200);
    const message = cleanStr(req.body.message, 5000);

    if (!name || name.length < 2) {
      return res.status(400).json({ error: 'Please enter your name.' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    }
    if (!subject || subject.length < 2) {
      return res.status(400).json({ error: 'Please enter a subject.' });
    }
    if (!message || message.length < 5) {
      return res.status(400).json({ error: 'Please enter a message (at least 5 characters).' });
    }

    const referenceId = generateRef('MSG-');
    const doc = await ContactMessage.create({
      referenceId,
      name,
      email,
      phone,
      subject,
      message,
    });

    const emailStatus = await sendContactMessageEmails({
      referenceId,
      name,
      email,
      phone,
      subject,
      message,
    });

    if (emailStatus.teamSent) {
      doc.emailNotified = true;
      await doc.save();
    }

    return res.status(201).json({
      success: true,
      referenceId,
      emailSent: emailStatus.senderSent,
      message: 'Message received! Our team has been notified.',
    });
  } catch (err) {
    console.error('Contact form error:', err.message);
    return res.status(500).json({ error: 'Failed to send message. Please try again shortly.' });
  }
});

// POST /api/bookings — Book Support Wizard (multipart/form-data or JSON)
router.post(
  '/bookings',
  formLimiter,
  optionalAuthMiddleware,
  (req, res, next) => {
    const contentType = req.headers['content-type'] || '';
    if (contentType.includes('multipart/form-data')) {
      upload.array('images', 5)(req, res, (err) => {
        if (err) {
          return res.status(400).json({ error: err.message || 'Invalid image upload.' });
        }
        next();
      });
    } else {
      next();
    }
  },
  async (req, res) => {
    try {
      const customerName = cleanStr(req.body.customerName, 120);
      const email = cleanStr(req.body.email, 254).toLowerCase();
      const phone = cleanStr(req.body.phone, 30);
      const deviceType = cleanStr(req.body.deviceType, 80);
      const deviceBrand = cleanStr(req.body.deviceBrand, 120);
      const operatingSystem = cleanStr(req.body.operatingSystem, 80);
      const issueDescription = cleanStr(req.body.issueDescription, 4000);
      const supportType = cleanStr(req.body.supportType, 20).toLowerCase();
      const preferredDate = cleanStr(req.body.preferredDate, 40);
      const preferredTime = cleanStr(req.body.preferredTime, 60);
      const serviceId = cleanStr(req.body.serviceId, 80);

      if (!customerName || !isValidEmail(email) || !phone || !deviceType || !issueDescription) {
        return res.status(400).json({ error: 'Please complete all required booking details.' });
      }
      if (supportType !== 'remote' && supportType !== 'onsite') {
        return res.status(400).json({ error: 'Support type must be remote or onsite.' });
      }

      const attachmentNames = Array.isArray(req.files)
        ? req.files.map((f) => cleanStr(f.originalname, 120)).filter(Boolean)
        : [];

      const bookingNumber = generateRef('NN');
      const booking = await Booking.create({
        bookingNumber,
        userId: req.user?.userId || undefined,
        customerName,
        email,
        phone,
        deviceType,
        deviceBrand,
        operatingSystem,
        issueDescription,
        supportType,
        preferredDate,
        preferredTime,
        attachmentNames,
        serviceId,
        paymentStatus: 'pay_after_fix',
      });

      sendBookingEmails(booking).catch((err) =>
        console.error('Booking email notification error:', err.message)
      );

      return res.status(201).json({
        success: true,
        booking: {
          bookingNumber: booking.bookingNumber,
          customerName: booking.customerName,
          email: booking.email,
          supportType: booking.supportType,
          paymentStatus: booking.paymentStatus,
        },
      });
    } catch (err) {
      console.error('Booking submission error:', err.message);
      return res.status(500).json({ error: 'Failed to create booking. Please try again.' });
    }
  }
);

// POST /api/newsletter — Blog Newsletter Subscription
router.post('/newsletter', formLimiter, async (req, res) => {
  try {
    const email = cleanStr(req.body.email, 254).toLowerCase();
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    }

    await NewsletterSubscriber.findOneAndUpdate(
      { email },
      { $set: { email, active: true } },
      { upsert: true, new: true }
    );

    sendNewsletterEmail(email).catch((err) =>
      console.error('Newsletter email error:', err.message)
    );

    return res.status(201).json({ success: true, message: 'Subscribed successfully!' });
  } catch (err) {
    console.error('Newsletter error:', err.message);
    return res.status(500).json({ error: 'Subscription failed. Please try again.' });
  }
});

module.exports = router;

