const nodemailer = require('nodemailer');
const { EMAIL_USER, EMAIL_PASS, COMPANY_TEAM_EMAILS, FRONTEND_URL } = require('../config/env');
const { escapeHtml } = require('../middleware/security');

let transporter = null;

function getTransporter() {
  if (!EMAIL_USER || !EMAIL_PASS) {
    return null;
  }
  if (!transporter) {
    transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: EMAIL_USER.trim(),
        // Strip spaces automatically in case Google App Password was pasted as "xxxx xxxx xxxx xxxx"
        pass: EMAIL_PASS.replace(/\s+/g, ''),
      },
      pool: true,
      maxConnections: 3,
    });
  }
  return transporter;
}

function isEmailConfigured() {
  return Boolean(EMAIL_USER && EMAIL_PASS);
}

function wrapLayout({ badge, title, bodyHtml, ctaLabel, ctaUrl }) {
  const safeBadge = escapeHtml(badge || 'NEUROVIA NEXUS');
  const safeTitle = escapeHtml(title || '');
  const ctaBlock =
    ctaLabel && ctaUrl
      ? `<div style="margin-top:28px;">
           <a href="${escapeHtml(ctaUrl)}" style="display:inline-block;background:#ffffff;color:#080808;font-weight:700;font-size:14px;padding:13px 26px;border-radius:999px;text-decoration:none;">
             ${escapeHtml(ctaLabel)} →
           </a>
         </div>`
      : '';

  return `<!DOCTYPE html>
<html>
<head><meta charset="utf-8" /></head>
<body style="margin:0;padding:24px;background:#080808;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#e8e8e8;">
  <div style="max-width:600px;margin:0 auto;background:#121214;border:1px solid rgba(255,255,255,0.1);border-radius:20px;overflow:hidden;">
    <div style="padding:24px 32px;border-bottom:1px solid rgba(255,255,255,0.08);background:#0d0d10;">
      <span style="display:inline-block;padding:4px 10px;border-radius:999px;background:rgba(79,127,255,0.15);border:1px solid rgba(79,127,255,0.3);color:#8bb4ff;font-size:11px;font-weight:700;letter-spacing:0.1em;text-transform:uppercase;">
        ${safeBadge}
      </span>
      <h1 style="margin:14px 0 0;font-size:24px;font-weight:800;color:#ffffff;letter-spacing:-0.02em;">
        ${safeTitle}
      </h1>
    </div>
    <div style="padding:28px 32px;font-size:15px;line-height:1.65;color:#cccccc;">
      ${bodyHtml}
      ${ctaBlock}
    </div>
    <div style="padding:20px 32px;border-top:1px solid rgba(255,255,255,0.08);font-size:12px;color:#777777;background:#0b0b0d;">
      <strong style="color:#ffffff;">Neurovia Nexus Pvt. Ltd.</strong> · Guwahati, Assam, India<br/>
      Support: <a href="mailto:support@neurovia.site" style="color:#8bb4ff;text-decoration:none;">support@neurovia.site</a> · +91 88220 96485
    </div>
  </div>
</body>
</html>`;
}

function stripHeaderCrlf(str) {
  return String(str || '').replace(/[\r\n]+/g, ' ').trim();
}

async function sendEmailSafe({ to, subject, html, replyTo }) {
  const tx = getTransporter();
  if (!tx) {
    console.warn(`[EMAIL] Skipped "${subject}" -> ${to} (EMAIL_USER/EMAIL_PASS not configured)`);
    return { sent: false, reason: 'not_configured' };
  }

  try {
    const rawRecipients = Array.isArray(to) ? to : [to];
    const cleanTo = rawRecipients.map(stripHeaderCrlf).filter(Boolean).join(', ');
    const cleanSubject = stripHeaderCrlf(subject);
    const cleanReplyTo = replyTo ? stripHeaderCrlf(replyTo) : undefined;

    const info = await tx.sendMail({
      from: `"Neurovia Nexus" <${stripHeaderCrlf(EMAIL_USER)}>`,
      to: cleanTo,
      subject: cleanSubject,
      html,
      ...(cleanReplyTo ? { replyTo: cleanReplyTo } : {}),
    });
    return { sent: true, messageId: info.messageId };
  } catch (err) {
    console.error(`[EMAIL ERROR] Failed sending "${subject}":`, err.message);
    return { sent: false, reason: err.message };
  }
}

/* ─── 1. Beta Tester Registration ─── */
async function sendBetaTesterEmails({ email, name, alreadyRegistered }) {
  const userResult = await sendEmailSafe({
    to: email,
    subject: alreadyRegistered
      ? "You're on the Neurovia Nexus Beta List!"
      : 'Welcome to the Neurovia Nexus Beta-Testing Programme!',
    html: wrapLayout({
      badge: 'Early Access · Beta Programme',
      title: alreadyRegistered ? "You're already registered!" : "You're in! Welcome to Neurovia Beta.",
      bodyHtml: `
        <p>Hi${name ? ' ' + escapeHtml(name) : ''},</p>
        <p>Thank you for registering for the <strong>Neurovia Nexus Beta-Testing Programme</strong> with <strong style="color:#fff;">${escapeHtml(email)}</strong>.</p>
        <p>As a verified beta tester, you'll receive:</p>
        <ul style="padding-left:20px;color:#dddddd;">
          <li>Early access to <strong>NADT (Autonomous Device Technician)</strong> diagnostic builds</li>
          <li>Priority access to new Remote Support &amp; Smart Ticket features</li>
          <li>Direct feedback channel with our engineering team</li>
        </ul>
        <p>We'll email you as soon as the next beta cohort opens.</p>
      `,
      ctaLabel: 'Explore Neurovia Services',
      ctaUrl: `${FRONTEND_URL}/services`,
    }),
  });

  if (!alreadyRegistered) {
    await sendEmailSafe({
      to: COMPANY_TEAM_EMAILS,
      replyTo: email,
      subject: `[Beta Tester] New registration: ${email}`,
      html: wrapLayout({
        badge: 'Team Notification · Beta Signup',
        title: 'New Beta Tester Registered',
        bodyHtml: `
          <p>A new user just joined the Beta-Testing Programme on the website:</p>
          <div style="background:#18181c;border:1px solid rgba(255,255,255,0.08);border-radius:12px;padding:16px;margin:16px 0;">
            <div><strong>Email:</strong> ${escapeHtml(email)}</div>
            ${name ? `<div><strong>Name:</strong> ${escapeHtml(name)}</div>` : ''}
            <div><strong>Registered At:</strong> ${new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })} IST</div>
          </div>
        `,
        ctaLabel: 'Open Admin Console',
        ctaUrl: `${FRONTEND_URL}/admin`,
      }),
    });
  }

  return userResult;
}

/* ─── 2. Get in Touch / Contact Form ─── */
async function sendContactMessageEmails({ referenceId, name, email, phone, subject, message }) {
  // 1) Notify Company Team (replyTo = sender's email so team can hit Reply directly!)
  const teamResult = await sendEmailSafe({
    to: COMPANY_TEAM_EMAILS,
    replyTo: email,
    subject: `[Get in Touch #${referenceId}] ${subject} — from ${name}`,
    html: wrapLayout({
      badge: `New Inquiry · ${referenceId}`,
      title: subject,
      bodyHtml: `
        <p>A new message was submitted via the <strong>Get in Touch</strong> form on Neurovia Nexus. Hit <strong>Reply</strong> in your email client to respond directly to ${escapeHtml(name)}.</p>
        <div style="background:#18181c;border:1px solid rgba(255,255,255,0.08);border-radius:12px;padding:18px;margin:18px 0;">
          <p style="margin:0 0 8px;"><strong>Reference:</strong> <span style="color:#8bb4ff;">${escapeHtml(referenceId)}</span></p>
          <p style="margin:0 0 8px;"><strong>Name:</strong> ${escapeHtml(name)}</p>
          <p style="margin:0 0 8px;"><strong>Email:</strong> <a href="mailto:${escapeHtml(email)}" style="color:#8bb4ff;">${escapeHtml(email)}</a></p>
          <p style="margin:0 0 8px;"><strong>Phone:</strong> ${escapeHtml(phone || 'Not provided')}</p>
          <p style="margin:0;"><strong>Time:</strong> ${new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })} IST</p>
        </div>
        <div style="background:#0d0d10;border-left:3px solid #4f7fff;padding:16px;border-radius:8px;white-space:pre-wrap;color:#ffffff;">${escapeHtml(message)}</div>
      `,
      ctaLabel: 'View in Admin Console',
      ctaUrl: `${FRONTEND_URL}/admin/tickets`,
    }),
  });

  // 2) Auto-confirmation to Sender
  const senderResult = await sendEmailSafe({
    to: email,
    subject: `We received your message [${referenceId}] — Neurovia Nexus`,
    html: wrapLayout({
      badge: `Reference · ${referenceId}`,
      title: 'Thanks for reaching out!',
      bodyHtml: `
        <p>Hi ${escapeHtml(name)},</p>
        <p>We've received your message regarding <strong style="color:#fff;">"${escapeHtml(subject)}"</strong>. A member of our team will review it and reply within a few hours during business hours (Mon–Sat, 9 AM – 7 PM IST).</p>
        <div style="background:#18181c;border:1px solid rgba(255,255,255,0.08);border-radius:12px;padding:16px;margin:16px 0;">
          <div style="font-size:12px;color:#888888;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:6px;">Your message copy</div>
          <div style="white-space:pre-wrap;color:#dddddd;font-size:14px;">${escapeHtml(message)}</div>
        </div>
        <p style="font-size:13px;color:#999999;">Need urgent tech support right away? Call or WhatsApp us at <strong style="color:#fff;">+91 88220 96485</strong>.</p>
      `,
      ctaLabel: 'Book Priority Support',
      ctaUrl: `${FRONTEND_URL}/book`,
    }),
  });

  return { teamSent: teamResult.sent, senderSent: senderResult.sent };
}

/* ─── 3. Support Booking Confirmation ─── */
async function sendBookingEmails(booking) {
  await sendEmailSafe({
    to: booking.email,
    subject: `Booking Confirmed [${booking.bookingNumber}] — Neurovia Nexus`,
    html: wrapLayout({
      badge: `Booking · ${booking.bookingNumber}`,
      title: 'Your technician request is confirmed!',
      bodyHtml: `
        <p>Hi ${escapeHtml(booking.customerName)},</p>
        <p>Your support booking has been logged. A certified Neurovia technician will be assigned within <strong>30 minutes</strong> during business hours.</p>
        <div style="background:#18181c;border:1px solid rgba(255,255,255,0.08);border-radius:12px;padding:18px;margin:18px 0;font-size:14px;">
          <p style="margin:0 0 8px;"><strong>Booking Reference:</strong> <span style="color:#8bb4ff;font-weight:700;">${escapeHtml(booking.bookingNumber)}</span></p>
          <p style="margin:0 0 8px;"><strong>Device:</strong> ${escapeHtml(booking.deviceType)}${booking.deviceBrand ? ` (${escapeHtml(booking.deviceBrand)})` : ''}</p>
          <p style="margin:0 0 8px;"><strong>Support Mode:</strong> ${escapeHtml(booking.supportType.toUpperCase())}</p>
          <p style="margin:0 0 8px;"><strong>Preferred Slot:</strong> ${escapeHtml(booking.preferredDate || 'Earliest available')} · ${escapeHtml(booking.preferredTime || 'Any time')}</p>
          <p style="margin:0;"><strong>Payment Status:</strong> ${booking.paymentStatus === 'paid' ? '<span style="color:#22c55e;">PAID ✓</span>' : 'Pay After Fix'}</p>
        </div>
      `,
      ctaLabel: 'View Services',
      ctaUrl: `${FRONTEND_URL}/services`,
    }),
  });

  await sendEmailSafe({
    to: COMPANY_TEAM_EMAILS,
    replyTo: booking.email,
    subject: `[New Booking #${booking.bookingNumber}] ${booking.supportType.toUpperCase()} — ${booking.customerName}`,
    html: wrapLayout({
      badge: `Dispatch Alert · ${booking.bookingNumber}`,
      title: `${booking.deviceType} (${booking.supportType})`,
      bodyHtml: `
        <div style="background:#18181c;border:1px solid rgba(255,255,255,0.08);border-radius:12px;padding:18px;margin:12px 0;font-size:14px;">
          <p style="margin:0 0 6px;"><strong>Customer:</strong> ${escapeHtml(booking.customerName)}</p>
          <p style="margin:0 0 6px;"><strong>Phone:</strong> ${escapeHtml(booking.phone)}</p>
          <p style="margin:0 0 6px;"><strong>Email:</strong> ${escapeHtml(booking.email)}</p>
          <p style="margin:0 0 6px;"><strong>Device / OS:</strong> ${escapeHtml(booking.deviceType)} ${escapeHtml(booking.deviceBrand || '')} · ${escapeHtml(booking.operatingSystem || 'N/A')}</p>
          <p style="margin:0 0 6px;"><strong>Slot:</strong> ${escapeHtml(booking.preferredDate || 'ASAP')} · ${escapeHtml(booking.preferredTime || 'Any time')}</p>
          <p style="margin:0;"><strong>Payment:</strong> ${escapeHtml(booking.paymentStatus)}</p>
        </div>
        <div style="background:#0d0d10;border-left:3px solid #22c55e;padding:14px;border-radius:8px;white-space:pre-wrap;color:#fff;">${escapeHtml(booking.issueDescription)}</div>
      `,
      ctaLabel: 'Manage in Admin Console',
      ctaUrl: `${FRONTEND_URL}/admin/tickets`,
    }),
  });
}

/* ─── 4. Razorpay Payment Receipt ─── */
async function sendPaymentReceiptEmails(payment) {
  await sendEmailSafe({
    to: payment.customerEmail,
    subject: `Payment Receipt [${payment.receiptNumber}] — ₹${payment.amountInr} · Neurovia Nexus`,
    html: wrapLayout({
      badge: `Payment Verified · ${payment.receiptNumber}`,
      title: `₹${payment.amountInr.toLocaleString('en-IN')} Paid Successfully`,
      bodyHtml: `
        <p>Hi ${escapeHtml(payment.customerName)},</p>
        <p>Thank you for your payment! Your service order is confirmed and prioritized with our technical team.</p>
        <div style="background:#18181c;border:1px solid rgba(255,255,255,0.08);border-radius:12px;padding:18px;margin:18px 0;font-size:14px;">
          <p style="margin:0 0 8px;"><strong>Receipt No:</strong> <span style="color:#22c55e;">${escapeHtml(payment.receiptNumber)}</span></p>
          <p style="margin:0 0 8px;"><strong>Service:</strong> ${escapeHtml(payment.serviceTitle)}</p>
          <p style="margin:0 0 8px;"><strong>Amount Paid:</strong> ₹${payment.amountInr.toLocaleString('en-IN')} INR</p>
          <p style="margin:0 0 8px;"><strong>Razorpay Payment ID:</strong> ${escapeHtml(payment.razorpayPaymentId)}</p>
          <p style="margin:0;"><strong>Date:</strong> ${new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })} IST</p>
        </div>
        <p>Our specialist will reach out to you shortly to begin your session.</p>
      `,
      ctaLabel: 'Contact Priority Desk',
      ctaUrl: `${FRONTEND_URL}/contact`,
    }),
  });

  await sendEmailSafe({
    to: COMPANY_TEAM_EMAILS,
    replyTo: payment.customerEmail,
    subject: `[Payment Received ₹${payment.amountInr}] ${payment.serviceTitle} — ${payment.customerName}`,
    html: wrapLayout({
      badge: `Razorpay Paid · ${payment.receiptNumber}`,
      title: `₹${payment.amountInr.toLocaleString('en-IN')} Received`,
      bodyHtml: `
        <div style="background:#18181c;border:1px solid rgba(255,255,255,0.08);border-radius:12px;padding:18px;margin:12px 0;font-size:14px;">
          <p style="margin:0 0 6px;"><strong>Customer:</strong> ${escapeHtml(payment.customerName)} (${escapeHtml(payment.customerEmail)})</p>
          <p style="margin:0 0 6px;"><strong>Phone:</strong> ${escapeHtml(payment.customerPhone || 'N/A')}</p>
          <p style="margin:0 0 6px;"><strong>Service:</strong> ${escapeHtml(payment.serviceTitle)} (${escapeHtml(payment.serviceCategory)})</p>
          <p style="margin:0 0 6px;"><strong>Payment ID:</strong> ${escapeHtml(payment.razorpayPaymentId)}</p>
          <p style="margin:0 0 6px;"><strong>Order ID:</strong> ${escapeHtml(payment.razorpayOrderId)}</p>
          ${payment.notes ? `<p style="margin:6px 0 0;"><strong>Notes:</strong> ${escapeHtml(payment.notes)}</p>` : ''}
        </div>
      `,
      ctaLabel: 'View Payments in Admin',
      ctaUrl: `${FRONTEND_URL}/admin`,
    }),
  });
}

/* ─── 5. Newsletter, Welcome & Password Reset ─── */
async function sendNewsletterEmail(email) {
  return sendEmailSafe({
    to: email,
    subject: "You're subscribed to the Neurovia Nexus Loop!",
    html: wrapLayout({
      badge: 'Newsletter',
      title: 'Welcome to the Loop.',
      bodyHtml: `
        <p>Thanks for subscribing with <strong style="color:#fff;">${escapeHtml(email)}</strong>!</p>
        <p>You'll get practical cybersecurity tips, PC care guides, and dispatches from our NADT AI diagnostics research lab — zero spam, ever.</p>
      `,
      ctaLabel: 'Read Latest Articles',
      ctaUrl: `${FRONTEND_URL}/blog`,
    }),
  });
}

async function sendWelcomeSignupEmail({ email, name }) {
  return sendEmailSafe({
    to: email,
    subject: 'Welcome to Neurovia Nexus!',
    html: wrapLayout({
      badge: 'Account Created',
      title: `Welcome aboard, ${name || 'there'}!`,
      bodyHtml: `
        <p>Your Neurovia Nexus account is ready.</p>
        <p>You can now book certified remote or onsite technicians, manage your profile, or register a partner workshop.</p>
      `,
      ctaLabel: 'Go to Neurovia Nexus',
      ctaUrl: FRONTEND_URL,
    }),
  });
}

async function sendPasswordResetEmail({ email, name, resetUrl }) {
  return sendEmailSafe({
    to: email,
    subject: 'Reset your Neurovia Nexus password',
    html: wrapLayout({
      badge: 'Security · Password Reset',
      title: 'Password Reset Request',
      bodyHtml: `
        <p>Hi ${escapeHtml(name || 'there')},</p>
        <p>We received a request to reset the password for your Neurovia Nexus account. Click the button below within <strong>30 minutes</strong> to choose a new password:</p>
        <p style="font-size:12px;color:#888888;margin-top:20px;">If you did not request this, you can safely ignore this email — your password will remain unchanged.</p>
      `,
      ctaLabel: 'Reset Password',
      ctaUrl: resetUrl,
    }),
  });
}

module.exports = {
  isEmailConfigured,
  sendBetaTesterEmails,
  sendContactMessageEmails,
  sendBookingEmails,
  sendPaymentReceiptEmails,
  sendNewsletterEmail,
  sendWelcomeSignupEmail,
  sendPasswordResetEmail,
};

