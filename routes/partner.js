const express = require('express');
const router = express.Router();
const Partner = require('../models/Partner');
const User = require('../models/User');
const authMiddleware = require('../authMiddleware');
const { cleanStr, isValidEmail } = require('../middleware/security');

function pickPartnerPayload(body) {
  const specializations = Array.isArray(body.specializations)
    ? body.specializations.map((s) => cleanStr(s, 80)).filter(Boolean).slice(0, 20)
    : [];
  const servicesOffered = Array.isArray(body.servicesOffered)
    ? body.servicesOffered.map((s) => cleanStr(s, 80)).filter(Boolean).slice(0, 20)
    : [];

  return {
    shopName: cleanStr(body.shopName, 120),
    ownerName: cleanStr(body.ownerName, 120),
    email: cleanStr(body.email, 254).toLowerCase(),
    countryCode: cleanStr(body.countryCode || '+91', 10),
    phone: cleanStr(body.phone, 20),
    address: cleanStr(body.address, 250),
    city: cleanStr(body.city, 80),
    state: cleanStr(body.state, 80),
    zipCode: cleanStr(body.zipCode, 20),
    profession: cleanStr(body.profession, 120),
    specializations,
    experience: cleanStr(body.experience, 40),
    description: cleanStr(body.description, 2000),
    servicesOffered,
    availableForCalls: Boolean(body.availableForCalls),
    availableForLiveService: Boolean(body.availableForLiveService),
    workingHours: cleanStr(body.workingHours, 80),
    certifications: cleanStr(body.certifications, 250),
    website: cleanStr(body.website, 250),
  };
}

// GET /api/partner/shops — Public list of registered partner repair shops (redacted PII)
router.get('/shops', async (_req, res) => {
  try {
    const partners = await Partner.find({})
      .select('shopName address city state workingHours countryCode phone servicesOffered specializations availableForLiveService createdAt')
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();

    const shops = partners.map((p) => ({
      id: String(p._id),
      name: p.shopName,
      address: `${p.address}, ${p.city}, ${p.state}`,
      city: p.city,
      state: p.state,
      rating: 4.9,
      hours: p.workingHours || '9:00 AM - 7:00 PM',
      phone: `${p.countryCode || '+91'} ${p.phone}`,
      services: (p.servicesOffered?.length ? p.servicesOffered : p.specializations) || ['Hardware Repair'],
      isPremium: true,
      bookingStatus: p.availableForLiveService ? 'ready-to-pay' : 'available',
    }));

    return res.json({ shops });
  } catch (error) {
    console.error('Error fetching public shops:', error.message);
    return res.status(500).json({ message: 'Failed to load repair shops' });
  }
});

// POST /api/partner/register
router.post('/register', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;

    const existingPartner = await Partner.findOne({ userId });
    if (existingPartner) {
      return res.status(400).json({ message: 'User is already registered as a partner' });
    }

    const payload = pickPartnerPayload(req.body || {});
    if (
      !payload.shopName ||
      !payload.ownerName ||
      !isValidEmail(payload.email) ||
      !payload.phone ||
      !payload.address ||
      !payload.city ||
      !payload.state ||
      !payload.profession ||
      !payload.experience ||
      !payload.description ||
      !payload.workingHours
    ) {
      return res.status(400).json({ message: 'Please complete all required partner fields.' });
    }

    // Bind userId strictly after whitelisting fields to prevent mass-assignment
    const newPartner = await Partner.create({
      ...payload,
      userId,
    });

    await User.findByIdAndUpdate(userId, { $set: { role: 'partner' } });

    return res.status(201).json({ message: 'Partner registered successfully', partner: newPartner });
  } catch (error) {
    console.error('Error in partner registration:', error.message);
    return res.status(500).json({ message: 'Failed to register partner' });
  }
});

// GET /api/partner/profile
router.get('/profile', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    const partner = await Partner.findOne({ userId });

    if (!partner) {
      return res.status(404).json({ message: 'Partner profile not found' });
    }

    return res.status(200).json({ partner });
  } catch (error) {
    console.error('Error fetching partner profile:', error.message);
    return res.status(500).json({ message: 'Failed to fetch partner profile' });
  }
});

module.exports = router;
