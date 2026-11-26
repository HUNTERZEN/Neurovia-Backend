const express = require('express');
const crypto = require('crypto');
const Razorpay = require('razorpay');
const Payment = require('../models/Payment');
const Booking = require('../models/Booking');
const { SERVICE_CATALOG, getServiceById } = require('../config/serviceCatalog');
const { RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET, RAZORPAY_WEBHOOK_SECRET } = require('../config/env');
const { cleanStr, isValidEmail, paymentLimiter } = require('../middleware/security');
const { optionalAuthMiddleware } = require('../authMiddleware');
const { sendPaymentReceiptEmails } = require('../services/emailService');

const router = express.Router();

function getRazorpayInstance() {
  if (!RAZORPAY_KEY_ID || !RAZORPAY_KEY_SECRET) {
    return null;
  }
  return new Razorpay({
    key_id: RAZORPAY_KEY_ID,
    key_secret: RAZORPAY_KEY_SECRET,
  });
}

function generateReceiptNumber() {
  const d = new Date();
  const ym = `${String(d.getFullYear()).slice(2)}${String(d.getMonth() + 1).padStart(2, '0')}`;
  const rand = crypto.randomBytes(3).toString('hex').toUpperCase();
  return `NV-RCPT-${ym}-${rand}`;
}

function safeCompareHex(expectedHex, providedHex) {
  if (typeof expectedHex !== 'string' || typeof providedHex !== 'string') return false;
  const a = Buffer.from(expectedHex, 'utf8');
  const b = Buffer.from(providedHex, 'utf8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// GET /api/payments/services — Public catalog & public Razorpay key_id
router.get('/services', (_req, res) => {
  res.json({
    configured: Boolean(RAZORPAY_KEY_ID && RAZORPAY_KEY_SECRET),
    keyId: RAZORPAY_KEY_ID || null,
    currency: 'INR',
    services: SERVICE_CATALOG,
  });
});

// POST /api/payments/create-order — Create authoritative server-priced Razorpay order
router.post('/create-order', paymentLimiter, optionalAuthMiddleware, async (req, res) => {
  try {
    const serviceId = cleanStr(req.body.serviceId, 80);
    const customerName = cleanStr(req.body.customerName, 120);
    const customerEmail = cleanStr(req.body.customerEmail, 254).toLowerCase();
    const customerPhone = cleanStr(req.body.customerPhone, 30);
    const notes = cleanStr(req.body.notes, 1000);
    const bookingNumber = cleanStr(req.body.bookingNumber, 40);

    const service = getServiceById(serviceId);
    if (!service) {
      return res.status(400).json({ error: 'Invalid service selected.' });
    }
    if (!customerName || customerName.length < 2) {
      return res.status(400).json({ error: 'Please provide your full name.' });
    }
    if (!isValidEmail(customerEmail)) {
      return res.status(400).json({ error: 'Please provide a valid email address.' });
    }

    const razorpay = getRazorpayInstance();
    if (!razorpay) {
      return res.status(503).json({
        error:
          'Online payment gateway is not configured yet (add RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET in server123/.env). You can still book with Pay-After-Fix.',
        code: 'RAZORPAY_NOT_CONFIGURED',
      });
    }

    const receiptNumber = generateReceiptNumber();
    const amountPaise = Math.round(service.amountInr * 100);

    const order = await razorpay.orders.create({
      amount: amountPaise,
      currency: 'INR',
      receipt: receiptNumber,
      notes: {
        serviceId: service.id,
        serviceTitle: service.title,
        customerEmail,
        bookingNumber: bookingNumber || '',
      },
    });

    await Payment.create({
      receiptNumber,
      razorpayOrderId: order.id,
      userId: req.user?.userId || undefined,
      bookingNumber,
      serviceId: service.id,
      serviceTitle: service.title,
      serviceCategory: service.category,
      amountInr: service.amountInr,
      amountPaise,
      currency: order.currency || 'INR',
      customerName,
      customerEmail,
      customerPhone,
      notes,
      status: 'created',
    });

    return res.status(201).json({
      keyId: RAZORPAY_KEY_ID,
      orderId: order.id,
      amount: order.amount,
      amountInr: service.amountInr,
      currency: order.currency || 'INR',
      receiptNumber,
      service: {
        id: service.id,
        title: service.title,
        category: service.category,
      },
    });
  } catch (err) {
    console.error('Razorpay order creation error:', err.message);
    return res.status(500).json({ error: 'Could not create payment order. Please try again.' });
  }
});

// POST /api/payments/verify — Cryptographically verify Razorpay payment signature
router.post('/verify', paymentLimiter, async (req, res) => {
  try {
    if (!RAZORPAY_KEY_SECRET) {
      return res.status(503).json({ error: 'Payment gateway is not configured.' });
    }

    const orderId = cleanStr(req.body.razorpay_order_id, 100);
    const paymentId = cleanStr(req.body.razorpay_payment_id, 100);
    const signature = cleanStr(req.body.razorpay_signature, 256);

    if (!orderId || !paymentId || !signature) {
      return res.status(400).json({ error: 'Missing payment verification parameters.' });
    }

    const expectedSignature = crypto
      .createHmac('sha256', RAZORPAY_KEY_SECRET)
      .update(`${orderId}|${paymentId}`)
      .digest('hex');

    if (!safeCompareHex(expectedSignature, signature)) {
      await Payment.findOneAndUpdate({ razorpayOrderId: orderId }, { $set: { status: 'failed' } });
      return res.status(400).json({ error: 'Invalid payment signature. Verification failed.' });
    }

    const payment = await Payment.findOne({ razorpayOrderId: orderId });
    if (!payment) {
      return res.status(404).json({ error: 'Payment order not found.' });
    }

    if (payment.status !== 'paid') {
      payment.status = 'paid';
      payment.razorpayPaymentId = paymentId;
      payment.razorpaySignature = signature;
      payment.paidAt = new Date();
      await payment.save();

      if (payment.bookingNumber) {
        await Booking.findOneAndUpdate(
          { bookingNumber: payment.bookingNumber },
          {
            $set: {
              paymentStatus: 'paid',
              razorpayOrderId: orderId,
              razorpayPaymentId: paymentId,
              amountInr: payment.amountInr,
              serviceId: payment.serviceId,
            },
          }
        );
      }

      // Send receipt to customer + revenue notification to company team asynchronously
      sendPaymentReceiptEmails(payment).catch((err) =>
        console.error('Receipt email error:', err.message)
      );
    }

    return res.json({
      verified: true,
      receipt: {
        receiptNumber: payment.receiptNumber,
        orderId: payment.razorpayOrderId,
        paymentId: payment.razorpayPaymentId,
        serviceTitle: payment.serviceTitle,
        serviceCategory: payment.serviceCategory,
        amountInr: payment.amountInr,
        currency: payment.currency,
        customerEmail: payment.customerEmail,
        paidAt: payment.paidAt,
      },
    });
  } catch (err) {
    console.error('Razorpay verify error:', err.message);
    return res.status(500).json({ error: 'Payment verification failed due to a server error.' });
  }
});

// POST /api/payments/webhook — Optional Razorpay server-to-server webhook verification
router.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    if (!RAZORPAY_WEBHOOK_SECRET) {
      return res.status(200).json({ received: true });
    }
    const sig = req.headers['x-razorpay-signature'];
    const rawBody = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : JSON.stringify(req.body);
    const expected = crypto.createHmac('sha256', RAZORPAY_WEBHOOK_SECRET).update(rawBody).digest('hex');

    if (!safeCompareHex(expected, String(sig || ''))) {
      return res.status(400).json({ error: 'Invalid webhook signature' });
    }

    const event = Buffer.isBuffer(req.body) ? JSON.parse(rawBody) : req.body;
    if (event?.event === 'payment.captured') {
      const entity = event.payload?.payment?.entity;
      if (entity?.order_id && entity?.id) {
        await Payment.findOneAndUpdate(
          { razorpayOrderId: entity.order_id },
          {
            $set: {
              status: 'paid',
              razorpayPaymentId: entity.id,
              paidAt: new Date(),
            },
          }
        );
      }
    }
    return res.json({ received: true });
  } catch (err) {
    console.error('Razorpay webhook error:', err.message);
    return res.status(500).json({ error: 'Webhook error' });
  }
});

module.exports = router;

