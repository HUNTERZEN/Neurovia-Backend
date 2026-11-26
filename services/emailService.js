const crypto = require('crypto');
const nodemailer = require('nodemailer');
const {
  EMAIL_USER,
  EMAIL_PASS,
  MAIL_RELAY_URL,
  COMPANY_TEAM_EMAILS,
  FRONTEND_URL,
} = require('../config/env');
const { escapeHtml } = require('../middleware/security');

let transporter = null;
// On Render Free Tier (where process.env.RENDER is set), outbound SMTP ports 465/587 are blocked —
// use the HTTPS Mail Relay immediately with zero timeout delay!
let smtpBlocked = Boolean(process.env.RENDER || process.env.USE_HTTPS_MAIL_RELAY === 'true');

function cleanCredentials() {
  return {
    user: (EMAIL_USER || '').trim(),
    pass: (EMAIL_PASS || '').replace(/\s+/g, ''),
  };
}

function getTransporter() {
  const { user, pass } = cleanCredentials();
  if (!user || !pass) {
    return null;
  }
  if (!transporter) {
    transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 465,
      secure: true,
      auth: { user, pass },
      connectionTimeout: 4500,
      greetingTimeout: 4500,
      socketTimeout: 8000,
    });
  }
  return transporter;
}

function isEmailConfigured() {
  const { user, pass } = cleanCredentials();
  return Boolean(user && pass);
}

function stripHeaderCrlf(str) {
  return String(str || '').replace(/[\r\n]+/g, ' ').trim();
}

async function sendViaHttpsRelay({ user, pass, to, subject, html, replyTo }) {
  if (!MAIL_RELAY_URL) {
    return { sent: false, reason: 'no_relay_url' };
  }
  try {
    const ts = String(Date.now());
    const sig = crypto
      .createHmac('sha256', pass)
      .update(`${ts}:${user.toLowerCase()}:${to}:${subject}`)
      .digest('hex');

    const res = await fetch(MAIL_RELAY_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Neurovia-Relay-Ts': ts,
        'X-Neurovia-Relay-Sig': sig,
      },
      body: JSON.stringify({
        fromUser: user.toLowerCase(),
        appPass: pass,
        to,
        subject,
        html,
        ...(replyTo ? { replyTo } : {}),
      }),
    });

    const data = await res.json().catch(() => ({}));
    if (res.ok && data.sent) {
      return { sent: true, messageId: data.messageId, via: 'https-relay' };
    }
    console.error(`[EMAIL RELAY ERROR] HTTP ${res.status}:`, data.error || 'unknown');
    return { sent: false, reason: data.error || `relay_http_${res.status}` };
  } catch (err) {
    console.error('[EMAIL RELAY NETWORK ERROR]:', err.message);
    return { sent: false, reason: err.message };
  }
}

async function sendEmailSafe({ to, subject, html, replyTo }) {
  const { user, pass } = cleanCredentials();
  if (!user || !pass) {
    console.warn(`[EMAIL] Skipped "${subject}" -> ${to} (EMAIL_USER/EMAIL_PASS not configured)`);
    return { sent: false, reason: 'not_configured' };
  }

  const rawRecipients = Array.isArray(to) ? to : [to];
  const cleanTo = rawRecipients.map(stripHeaderCrlf).filter(Boolean).join(', ');
  const cleanSubject = stripHeaderCrlf(subject);
  const cleanReplyTo = replyTo ? stripHeaderCrlf(replyTo) : undefined;

  // 1) Try direct SMTP first unless we already detected outbound port 465 is blocked
  if (!smtpBlocked) {
    try {
      const tx = getTransporter();
      const info = await tx.sendMail({
        from: `"Neurovia Nexus" <${stripHeaderCrlf(user)}>`,
        to: cleanTo,
        subject: cleanSubject,
        html,
        ...(cleanReplyTo ? { replyTo: cleanReplyTo } : {}),
      });
      return { sent: true, messageId: info.messageId, via: 'smtp' };
    } catch (err) {
      const code = String(err.code || '');
      const msg = String(err.message || '');
      if (
        code === 'ETIMEDOUT' ||
        code === 'ESOCKET' ||
        code === 'ECONNREFUSED' ||
        code === 'ENETUNREACH' ||
        /timeout/i.test(msg)
      ) {
        console.warn('[EMAIL] Direct SMTP port blocked/timed out — switching to HTTPS Mail Relay.');
        smtpBlocked = true;
      } else {
        console.error(`[EMAIL SMTP ERROR] "${cleanSubject}":`, msg);
        return { sent: false, reason: msg };
      }
    }
  }

  // 2) Fallback to HTTPS Mail Relay over port 443 (works on Render Free Tier)
  return sendViaHttpsRelay({
    user,
    pass,
    to: cleanTo,
    subject: cleanSubject,
    html,
    replyTo: cleanReplyTo,
  });
}

/* ═══════════════════════════════════════════════════════════════
   EXECUTIVE PRO HTML EMAIL DESIGN SYSTEM (Gmail / iOS / Outlook Safe)
═══════════════════════════════════════════════════════════════ */
function wrapProEmail({
  preheader,
  badge,
  badgeColor = '#4f7fff',
  headline,
  subheadline,
  bodyHtml,
  primaryCta,
  secondaryCta,
  showSignoff = false,
}) {
  const safePreheader = escapeHtml(preheader || headline || 'Neurovia Nexus');
  const safeBadge = escapeHtml(badge || 'NEUROVIA NEXUS');
  const safeHeadline = escapeHtml(headline || '');
  const safeSub = subheadline ? escapeHtml(subheadline) : '';

  const primaryBtnHtml =
    primaryCta?.label && primaryCta?.url
      ? `<td style="padding-right:12px;padding-bottom:10px;">
           <a href="${escapeHtml(primaryCta.url)}" style="display:inline-block;background-color:#ffffff;color:#080808;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:14px;font-weight:700;text-decoration:none;padding:14px 28px;border-radius:999px;border:1px solid #ffffff;">
             ${escapeHtml(primaryCta.label)} &rarr;
           </a>
         </td>`
      : '';

  const secondaryBtnHtml =
    secondaryCta?.label && secondaryCta?.url
      ? `<td style="padding-bottom:10px;">
           <a href="${escapeHtml(secondaryCta.url)}" style="display:inline-block;background-color:#18181c;color:#e8e8e8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:13px;font-weight:600;text-decoration:none;padding:13px 22px;border-radius:999px;border:1px solid rgba(255,255,255,0.16);">
             ${escapeHtml(secondaryCta.label)}
           </a>
         </td>`
      : '';

  const ctaRow =
    primaryBtnHtml || secondaryBtnHtml
      ? `<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin-top:28px;">
           <tr>${primaryBtnHtml}${secondaryBtnHtml}</tr>
         </table>`
      : '';

  const signoffBlock = showSignoff
    ? `<div style="margin-top:32px;padding-top:24px;border-top:1px solid rgba(255,255,255,0.08);">
         <p style="margin:0 0 4px;font-size:14px;color:#aaaaaa;">Warm regards,</p>
         <p style="margin:0 0 2px;font-size:15px;font-weight:700;color:#ffffff;">The Founding &amp; Engineering Team</p>
         <p style="margin:0;font-size:12px;color:#8bb4ff;">Neurovia Nexus Pvt. Ltd. &middot; Certified IT &amp; AI Systems</p>
       </div>`
    : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta name="color-scheme" content="dark" />
  <title>${safeHeadline}</title>
</head>
<body style="margin:0;padding:0;background-color:#050507;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#e8e8e8;-webkit-font-smoothing:antialiased;">
  <!-- Hidden Inbox Preview Preheader -->
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;">
    ${safePreheader}&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;
  </div>

  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#050507;padding:32px 14px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:620px;background-color:#101014;border:1px solid rgba(255,255,255,0.1);border-radius:24px;overflow:hidden;">
          <!-- Top Accent Line -->
          <tr>
            <td style="height:4px;background:linear-gradient(90deg,#4f7fff 0%,#8bb4ff 50%,#22c55e 100%);font-size:0;line-height:0;">&nbsp;</td>
          </tr>

          <!-- Brand Top Bar -->
          <tr>
            <td style="padding:26px 34px 20px;background-color:#0b0b0f;border-bottom:1px solid rgba(255,255,255,0.07);">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td valign="middle">
                    <table role="presentation" cellpadding="0" cellspacing="0" border="0">
                      <tr>
                        <td style="width:34px;height:34px;background-color:#ffffff;color:#080808;border-radius:9px;text-align:center;font-weight:900;font-size:16px;line-height:34px;">
                          N
                        </td>
                        <td style="padding-left:11px;font-size:16px;font-weight:800;color:#ffffff;letter-spacing:-0.02em;">
                          Neurovia Nexus
                        </td>
                      </tr>
                    </table>
                  </td>
                  <td align="right" valign="middle">
                    <span style="display:inline-block;padding:5px 12px;border-radius:999px;background-color:rgba(79,127,255,0.14);border:1px solid ${badgeColor};color:#cfe0ff;font-size:10px;font-weight:700;letter-spacing:0.1em;text-transform:uppercase;">
                      ${safeBadge}
                    </span>
                  </td>
                </tr>
              </table>

              <h1 style="margin:22px 0 6px;font-size:26px;line-height:1.22;font-weight:800;color:#ffffff;letter-spacing:-0.025em;">
                ${safeHeadline}
              </h1>
              ${
                safeSub
                  ? `<p style="margin:0;font-size:14px;line-height:1.55;color:#9999a3;">${safeSub}</p>`
                  : ''
              }
            </td>
          </tr>

          <!-- Main Body -->
          <tr>
            <td style="padding:30px 34px;font-size:15px;line-height:1.68;color:#d0d0d6;">
              ${bodyHtml}
              ${ctaRow}
              ${signoffBlock}
            </td>
          </tr>

          <!-- Direct Help Bar -->
          <tr>
            <td style="padding:18px 34px;background-color:#14141a;border-top:1px solid rgba(255,255,255,0.07);border-bottom:1px solid rgba(255,255,255,0.07);">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td style="font-size:12px;color:#a0a0ab;">
                    <strong style="color:#ffffff;">Need live assistance?</strong> Call or WhatsApp <strong style="color:#ffffff;">+91 88220 96485</strong> (Mon&ndash;Sat, 9 AM&ndash;7 PM IST)
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Official Footer -->
          <tr>
            <td style="padding:22px 34px;background-color:#09090c;font-size:11px;line-height:1.6;color:#6e6e78;">
              <strong style="color:#b8b8c2;">Neurovia Nexus Pvt. Ltd.</strong> &middot; MCA Incorporated &amp; MASI Certified Startup<br />
              Guwahati, Assam 781001, India &middot;
              <a href="mailto:support@neurovia.site" style="color:#8bb4ff;text-decoration:none;">support@neurovia.site</a> &middot;
              <a href="${escapeHtml(FRONTEND_URL)}" style="color:#8bb4ff;text-decoration:none;">Website</a>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

function featureCardHtml(icon, title, desc) {
  return `
    <div style="background-color:#16161d;border:1px solid rgba(255,255,255,0.08);border-radius:14px;padding:15px 18px;margin-bottom:10px;">
      <div style="font-size:14px;font-weight:700;color:#ffffff;margin-bottom:3px;">
        ${icon}&nbsp;&nbsp;${escapeHtml(title)}
      </div>
      <div style="font-size:13px;line-height:1.55;color:#9d9da8;">
        ${escapeHtml(desc)}
      </div>
    </div>`;
}

/* ─── 1. Executive Pro Beta Tester Welcome Email ─── */
async function sendBetaTesterEmails({ email, name, alreadyRegistered }) {
  const displayGreeting = name ? `Hi ${escapeHtml(name)},` : 'Hello Innovator,';

  const userResult = await sendEmailSafe({
    to: email,
    subject: alreadyRegistered
      ? 'Your Neurovia Nexus Beta Pass — Early Access Status Confirmed'
      : "You're In — Official Neurovia Nexus Beta & NADT Early Access Pass",
    html: wrapProEmail({
      preheader:
        'Welcome to the Neurovia Nexus Beta Programme. Your early-access pass to NADT & autonomous IT diagnostics is active.',
      badge: 'Beta Cohort · Verified Pass',
      badgeColor: 'rgba(34,197,94,0.45)',
      headline: alreadyRegistered
        ? 'Your Beta Access Pass is Active.'
        : 'Welcome to the Neurovia Beta Cohort.',
      subheadline:
        'Official early-access confirmation for NADT & next-generation Neurovia Nexus releases.',
      bodyHtml: `
        <p style="margin-top:0;">${displayGreeting}</p>
        <p>
          Thank you for stepping into the inner circle at <strong style="color:#ffffff;">Neurovia Nexus</strong>. Your email
          (<strong style="color:#8bb4ff;">${escapeHtml(email)}</strong>) is officially registered in our
          <strong style="color:#ffffff;">Beta-Testing Programme</strong>.
        </p>

        <!-- Pass Summary Box -->
        <div style="background-color:#151924;border:1px solid rgba(79,127,255,0.3);border-radius:16px;padding:18px 20px;margin:22px 0;">
          <div style="font-size:10px;font-weight:700;letter-spacing:0.12em;text-transform:uppercase;color:#8bb4ff;margin-bottom:8px;">
            EARLY ACCESS CREDENTIAL
          </div>
          <div style="font-size:14px;color:#ffffff;margin-bottom:4px;"><strong>Member Email:</strong> ${escapeHtml(email)}</div>
          <div style="font-size:14px;color:#ffffff;margin-bottom:4px;"><strong>Cohort Track:</strong> NADT Autonomous Diagnostics &amp; Platform Preview</div>
          <div style="font-size:13px;color:#22c55e;font-weight:600;">&#10003; Priority Invite Status: Confirmed</div>
        </div>

        <p style="font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:#888894;margin:24px 0 12px;">
          What You Unlock as a Beta Member
        </p>
        ${featureCardHtml(
          '🤖',
          'NADT Autonomous Device Technician (Early Builds)',
          'Hands-on preview access to our AI diagnostic engine before public release.'
        )}
        ${featureCardHtml(
          '⚡',
          'Priority Rollouts & Zero-Wait Support Features',
          'Be the first to test Smart Ticket Routing, instant live diagnostics, and proactive system health alerts.'
        )}
        ${featureCardHtml(
          '🎯',
          'Direct Engineering Feedback Loop',
          'Share bug reports and ideas directly with our founding engineers and earn permanent Founding Tester perks.'
        )}

        <p style="margin-top:20px;margin-bottom:0;font-size:14px;color:#b5b5c0;">
          We'll send your private build link and release notes directly to this inbox as each milestone unlocks. Need help with a device today? Our certified technicians are already live.
        </p>
      `,
      primaryCta: {
        label: 'Explore Live Services',
        url: `${FRONTEND_URL}/services`,
      },
      secondaryCta: {
        label: 'Meet Our Team',
        url: `${FRONTEND_URL}/about`,
      },
      showSignoff: true,
    }),
  });

  if (!alreadyRegistered) {
    sendEmailSafe({
      to: COMPANY_TEAM_EMAILS,
      replyTo: email,
      subject: `[Beta Cohort] New Beta Tester Registered: ${email}`,
      html: wrapProEmail({
        preheader: `New beta registration from ${email}`,
        badge: 'Internal Alert · Beta',
        headline: 'New Beta Tester Joined',
        subheadline: 'Recorded in MongoDB and confirmed via automated welcome email.',
        bodyHtml: `
          <div style="background:#16161d;border:1px solid rgba(255,255,255,0.08);border-radius:14px;padding:18px;">
            <p style="margin:0 0 8px;"><strong>Email:</strong> ${escapeHtml(email)}</p>
            ${name ? `<p style="margin:0 0 8px;"><strong>Name:</strong> ${escapeHtml(name)}</p>` : ''}
            <p style="margin:0 0 8px;"><strong>Welcome Email Delivered:</strong> ${userResult.sent ? 'Yes ✓' : 'Pending'}</p>
            <p style="margin:0;"><strong>Time:</strong> ${new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })} IST</p>
          </div>
        `,
        primaryCta: {
          label: 'Open Admin Console',
          url: `${FRONTEND_URL}/admin/settings`,
        },
      }),
    }).catch(() => {});
  }

  return userResult;
}

/* ─── 2. Executive Pro Customer Welcome Email (New Sign-Up & Returning Sign-In via Email or Google) ─── */
async function sendWelcomeSignupEmail({ email, name, authMethod = 'Email', isNewUser = true }) {
  const cleanName = name || email.split('@')[0] || 'there';
  const loginTimeIst = new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });

  const subject = isNewUser
    ? `Welcome to Neurovia Nexus, ${cleanName} — Your Account is Ready`
    : `Welcome Back to Neurovia Nexus, ${cleanName}!`;

  const headline = isNewUser
    ? `Welcome to Neurovia Nexus, ${cleanName}.`
    : `Welcome back, ${cleanName}.`;

  const subheadline = isNewUser
    ? 'Stop settling for broken tech — your personal & business IT command center is live.'
    : `You just signed in to your Neurovia Nexus account via ${authMethod}.`;

  const introParagraph = isNewUser
    ? `We're thrilled to welcome you to <strong style="color:#ffffff;">Neurovia Nexus</strong>. Your account (<strong style="color:#8bb4ff;">${escapeHtml(email)}</strong>) is active and verified via <strong style="color:#ffffff;">${escapeHtml(authMethod)}</strong>.`
    : `Glad to see you back at <strong style="color:#ffffff;">Neurovia Nexus</strong>! Your session for <strong style="color:#8bb4ff;">${escapeHtml(email)}</strong> was just authenticated via <strong style="color:#ffffff;">${escapeHtml(authMethod)}</strong> on ${escapeHtml(loginTimeIst)} IST.`;

  return sendEmailSafe({
    to: email,
    subject,
    html: wrapProEmail({
      preheader: isNewUser
        ? `Welcome to Neurovia Nexus, ${cleanName}! Instant certified remote & onsite tech support across India.`
        : `Welcome back, ${cleanName}! Your Neurovia Nexus account session is active.`,
      badge: isNewUser ? 'Verified New Member' : 'Signed In · Verified',
      badgeColor: 'rgba(79,127,255,0.45)',
      headline,
      subheadline,
      bodyHtml: `
        <p style="margin-top:0;">Hi <strong style="color:#ffffff;">${escapeHtml(cleanName)}</strong>,</p>
        <p>${introParagraph}</p>
        <p>
          Whether you need an urgent OS fix, virus cleanup, doorstep hardware repair, office network setup, or custom cloud &amp; AI solutions — our certified specialists are ready whenever you are.
        </p>

        <p style="font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:#888894;margin:24px 0 12px;">
          Ready Whenever You Need Us
        </p>
        ${featureCardHtml(
          '⚡',
          '30-Minute Technician Assignment',
          'Book remote screen-share diagnostics or doorstep hardware repair in under 2 minutes.'
        )}
        ${featureCardHtml(
          '🛡️',
          'Radical Transparency · No Fix, No Fee',
          'Clear upfront INR pricing, permission-only access, and documented fixes you can trust.'
        )}
        ${featureCardHtml(
          '💳',
          'Instant Razorpay Checkout or Pay-After-Fix',
          'Pay seamlessly via UPI / Google Pay / Cards for priority dispatch or settle after your fix.'
        )}
      `,
      primaryCta: {
        label: 'Explore Services & Book Support',
        url: `${FRONTEND_URL}/services`,
      },
      secondaryCta: {
        label: 'Open My Profile',
        url: `${FRONTEND_URL}/profile`,
      },
      showSignoff: true,
    }),
  });
}

/* ─── 3. Get in Touch / Contact Form ─── */
async function sendContactMessageEmails({ referenceId, name, email, phone, subject, message }) {
  const teamResult = await sendEmailSafe({
    to: COMPANY_TEAM_EMAILS,
    replyTo: email,
    subject: `[Get in Touch #${referenceId}] ${subject} — from ${name}`,
    html: wrapProEmail({
      preheader: `New message from ${name} (${email}): ${subject}`,
      badge: `New Inquiry · ${referenceId}`,
      headline: subject,
      subheadline: `Submitted by ${name} — hit Reply to answer ${email} directly.`,
      bodyHtml: `
        <div style="background:#16161d;border:1px solid rgba(255,255,255,0.08);border-radius:14px;padding:18px;margin-bottom:18px;font-size:14px;">
          <p style="margin:0 0 8px;"><strong>Reference:</strong> <span style="color:#8bb4ff;">${escapeHtml(referenceId)}</span></p>
          <p style="margin:0 0 8px;"><strong>Sender:</strong> ${escapeHtml(name)}</p>
          <p style="margin:0 0 8px;"><strong>Email:</strong> <a href="mailto:${escapeHtml(email)}" style="color:#8bb4ff;">${escapeHtml(email)}</a></p>
          <p style="margin:0 0 8px;"><strong>Phone:</strong> ${escapeHtml(phone || 'Not provided')}</p>
          <p style="margin:0;"><strong>Received:</strong> ${new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })} IST</p>
        </div>
        <div style="background:#0b0b0f;border-left:3px solid #4f7fff;padding:16px 18px;border-radius:10px;white-space:pre-wrap;color:#ffffff;font-size:14px;">${escapeHtml(message)}</div>
      `,
      primaryCta: {
        label: 'Manage in Admin Console',
        url: `${FRONTEND_URL}/admin/tickets`,
      },
    }),
  });

  const senderResult = await sendEmailSafe({
    to: email,
    subject: `We've received your message [${referenceId}] — Neurovia Nexus`,
    html: wrapProEmail({
      preheader: `Reference ${referenceId}: Our team will reply within a few business hours.`,
      badge: `Ticket · ${referenceId}`,
      headline: "We've got your message.",
      subheadline: 'Our team at Neurovia Nexus usually replies within a few business hours.',
      bodyHtml: `
        <p style="margin-top:0;">Hi <strong style="color:#ffffff;">${escapeHtml(name)}</strong>,</p>
        <p>Thank you for getting in touch regarding <strong style="color:#ffffff;">"${escapeHtml(subject)}"</strong>. Your inquiry has been routed to our leadership &amp; support desk under reference <strong style="color:#8bb4ff;">${escapeHtml(referenceId)}</strong>.</p>
        <div style="background:#16161d;border:1px solid rgba(255,255,255,0.08);border-radius:14px;padding:16px 18px;margin:20px 0;">
          <div style="font-size:11px;color:#888894;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:6px;">Your Message Copy</div>
          <div style="white-space:pre-wrap;color:#d8d8e0;font-size:14px;">${escapeHtml(message)}</div>
        </div>
      `,
      primaryCta: {
        label: 'Need Urgent Help? Book Now',
        url: `${FRONTEND_URL}/book`,
      },
      showSignoff: true,
    }),
  });

  return { teamSent: teamResult.sent, senderSent: senderResult.sent };
}

/* ─── 4. Support Booking Confirmation ─── */
async function sendBookingEmails(booking) {
  await sendEmailSafe({
    to: booking.email,
    subject: `Booking Confirmed [${booking.bookingNumber}] — Neurovia Nexus`,
    html: wrapProEmail({
      preheader: `Booking ${booking.bookingNumber} confirmed. A certified technician will be assigned within 30 minutes.`,
      badge: `Booking · ${booking.bookingNumber}`,
      badgeColor: 'rgba(34,197,94,0.45)',
      headline: 'Your Technician Request is Confirmed.',
      subheadline: 'A certified Neurovia specialist is being matched to your device.',
      bodyHtml: `
        <p style="margin-top:0;">Hi <strong style="color:#ffffff;">${escapeHtml(booking.customerName)}</strong>,</p>
        <p>Your support request has been logged. During business hours (Mon&ndash;Sat, 9 AM&ndash;7 PM IST), a certified technician will reach out within <strong style="color:#ffffff;">30 minutes</strong>.</p>
        <div style="background:#16161d;border:1px solid rgba(255,255,255,0.08);border-radius:14px;padding:18px;margin:20px 0;font-size:14px;">
          <p style="margin:0 0 8px;"><strong>Booking Reference:</strong> <span style="color:#8bb4ff;font-weight:700;">${escapeHtml(booking.bookingNumber)}</span></p>
          <p style="margin:0 0 8px;"><strong>Device:</strong> ${escapeHtml(booking.deviceType)}${booking.deviceBrand ? ` (${escapeHtml(booking.deviceBrand)})` : ''}</p>
          <p style="margin:0 0 8px;"><strong>Support Mode:</strong> ${escapeHtml(booking.supportType.toUpperCase())}</p>
          <p style="margin:0 0 8px;"><strong>Preferred Slot:</strong> ${escapeHtml(booking.preferredDate || 'Earliest available')} &middot; ${escapeHtml(booking.preferredTime || 'Any time')}</p>
          <p style="margin:0;"><strong>Payment Status:</strong> ${booking.paymentStatus === 'paid' ? '<span style="color:#22c55e;font-weight:700;">PAID ✓</span>' : 'Pay After Fix'}</p>
        </div>
      `,
      primaryCta: {
        label: 'View Neurovia Services',
        url: `${FRONTEND_URL}/services`,
      },
      showSignoff: true,
    }),
  });

  await sendEmailSafe({
    to: COMPANY_TEAM_EMAILS,
    replyTo: booking.email,
    subject: `[New Booking #${booking.bookingNumber}] ${booking.supportType.toUpperCase()} — ${booking.customerName}`,
    html: wrapProEmail({
      preheader: `${booking.customerName} booked ${booking.supportType} support for ${booking.deviceType}`,
      badge: `Dispatch Alert · ${booking.bookingNumber}`,
      headline: `${booking.deviceType} (${booking.supportType.toUpperCase()})`,
      bodyHtml: `
        <div style="background:#16161d;border:1px solid rgba(255,255,255,0.08);border-radius:14px;padding:18px;margin-bottom:14px;font-size:14px;">
          <p style="margin:0 0 6px;"><strong>Customer:</strong> ${escapeHtml(booking.customerName)}</p>
          <p style="margin:0 0 6px;"><strong>Phone:</strong> ${escapeHtml(booking.phone)}</p>
          <p style="margin:0 0 6px;"><strong>Email:</strong> ${escapeHtml(booking.email)}</p>
          <p style="margin:0 0 6px;"><strong>Device / OS:</strong> ${escapeHtml(booking.deviceType)} ${escapeHtml(booking.deviceBrand || '')} &middot; ${escapeHtml(booking.operatingSystem || 'N/A')}</p>
          <p style="margin:0 0 6px;"><strong>Slot:</strong> ${escapeHtml(booking.preferredDate || 'ASAP')} &middot; ${escapeHtml(booking.preferredTime || 'Any time')}</p>
          <p style="margin:0;"><strong>Payment:</strong> ${escapeHtml(booking.paymentStatus)}</p>
        </div>
        <div style="background:#0b0b0f;border-left:3px solid #22c55e;padding:14px 16px;border-radius:10px;white-space:pre-wrap;color:#ffffff;">${escapeHtml(booking.issueDescription)}</div>
      `,
      primaryCta: {
        label: 'Assign in Admin Console',
        url: `${FRONTEND_URL}/admin/tickets`,
      },
    }),
  });
}

/* ─── 5. Razorpay Payment Receipt ─── */
async function sendPaymentReceiptEmails(payment) {
  await sendEmailSafe({
    to: payment.customerEmail,
    subject: `Official Payment Receipt [${payment.receiptNumber}] — ₹${payment.amountInr.toLocaleString('en-IN')} · Neurovia Nexus`,
    html: wrapProEmail({
      preheader: `Receipt ${payment.receiptNumber} for ₹${payment.amountInr.toLocaleString('en-IN')} — ${payment.serviceTitle}`,
      badge: `Paid ✓ · ${payment.receiptNumber}`,
      badgeColor: 'rgba(34,197,94,0.45)',
      headline: `₹${payment.amountInr.toLocaleString('en-IN')} Payment Confirmed.`,
      subheadline: 'Your priority service order has been verified and queued for immediate dispatch.',
      bodyHtml: `
        <p style="margin-top:0;">Hi <strong style="color:#ffffff;">${escapeHtml(payment.customerName)}</strong>,</p>
        <p>Thank you for choosing <strong style="color:#ffffff;">Neurovia Nexus</strong>. Below is your official Razorpay payment receipt:</p>
        <div style="background:#16161d;border:1px solid rgba(34,197,94,0.28);border-radius:16px;padding:18px 20px;margin:20px 0;font-size:14px;">
          <p style="margin:0 0 8px;"><strong>Receipt Number:</strong> <span style="color:#22c55e;font-weight:700;">${escapeHtml(payment.receiptNumber)}</span></p>
          <p style="margin:0 0 8px;"><strong>Service Package:</strong> ${escapeHtml(payment.serviceTitle)}</p>
          <p style="margin:0 0 8px;"><strong>Amount Paid:</strong> ₹${payment.amountInr.toLocaleString('en-IN')} INR</p>
          <p style="margin:0 0 8px;"><strong>Razorpay Payment ID:</strong> ${escapeHtml(payment.razorpayPaymentId)}</p>
          <p style="margin:0;"><strong>Date:</strong> ${new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })} IST</p>
        </div>
      `,
      primaryCta: {
        label: 'Contact Priority Desk',
        url: `${FRONTEND_URL}/contact`,
      },
      showSignoff: true,
    }),
  });

  await sendEmailSafe({
    to: COMPANY_TEAM_EMAILS,
    replyTo: payment.customerEmail,
    subject: `[Payment ₹${payment.amountInr}] ${payment.serviceTitle} — ${payment.customerName}`,
    html: wrapProEmail({
      preheader: `Verified Razorpay payment of ₹${payment.amountInr} from ${payment.customerName}`,
      badge: `Razorpay Paid · ${payment.receiptNumber}`,
      headline: `₹${payment.amountInr.toLocaleString('en-IN')} Received`,
      bodyHtml: `
        <div style="background:#16161d;border:1px solid rgba(255,255,255,0.08);border-radius:14px;padding:18px;font-size:14px;">
          <p style="margin:0 0 6px;"><strong>Customer:</strong> ${escapeHtml(payment.customerName)} (${escapeHtml(payment.customerEmail)})</p>
          <p style="margin:0 0 6px;"><strong>Phone:</strong> ${escapeHtml(payment.customerPhone || 'N/A')}</p>
          <p style="margin:0 0 6px;"><strong>Service:</strong> ${escapeHtml(payment.serviceTitle)} (${escapeHtml(payment.serviceCategory)})</p>
          <p style="margin:0 0 6px;"><strong>Payment ID:</strong> ${escapeHtml(payment.razorpayPaymentId)}</p>
          <p style="margin:0;"><strong>Order ID:</strong> ${escapeHtml(payment.razorpayOrderId)}</p>
        </div>
      `,
      primaryCta: {
        label: 'View in Admin Console',
        url: `${FRONTEND_URL}/admin/analytics`,
      },
    }),
  });
}

/* ─── 6. Newsletter & Password Reset ─── */
async function sendNewsletterEmail(email) {
  return sendEmailSafe({
    to: email,
    subject: "Welcome to The Neurovia Loop — Insights, Cybersecurity & AI Research",
    html: wrapProEmail({
      preheader: 'Subscribed to Neurovia Nexus insights & NADT AI research updates.',
      badge: 'The Loop · Subscribed',
      headline: "You're in the Loop.",
      subheadline: 'Practical IT care, SME cybersecurity playbooks, and NADT research dispatches.',
      bodyHtml: `
        <p style="margin-top:0;">Thanks for subscribing with <strong style="color:#8bb4ff;">${escapeHtml(email)}</strong>!</p>
        <p>Expect concise, high-signal articles written directly by our engineers — zero fluff and zero spam.</p>
      `,
      primaryCta: {
        label: 'Read Latest Articles',
        url: `${FRONTEND_URL}/blog`,
      },
      showSignoff: true,
    }),
  });
}

async function sendPasswordResetEmail({ email, name, resetUrl }) {
  return sendEmailSafe({
    to: email,
    subject: 'Reset Your Neurovia Nexus Password',
    html: wrapProEmail({
      preheader: 'Password reset link valid for 30 minutes.',
      badge: 'Security · Password Reset',
      headline: 'Password Reset Request',
      subheadline: 'This secure link expires in 30 minutes.',
      bodyHtml: `
        <p style="margin-top:0;">Hi <strong style="color:#ffffff;">${escapeHtml(name || 'there')}</strong>,</p>
        <p>We received a request to reset the password for your Neurovia Nexus account (<strong style="color:#8bb4ff;">${escapeHtml(email)}</strong>). Click the button below to choose a new password:</p>
        <p style="font-size:12px;color:#888894;margin-top:20px;">If you did not request a password reset, you can safely ignore this email — your account remains secure.</p>
      `,
      primaryCta: {
        label: 'Set New Password',
        url: resetUrl,
      },
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
