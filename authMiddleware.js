const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('./config/env');

function extractBearerToken(req) {
  const header = req.header('Authorization') || req.header('authorization') || '';
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) {
    return null;
  }
  const token = header.slice(7).trim();
  return token || null;
}

function authMiddleware(req, res, next) {
  const token = extractBearerToken(req);
  if (!token) {
    return res.status(401).json({ error: 'Authentication required', message: 'Access Denied' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    if (!decoded || !decoded.userId) {
      return res.status(403).json({ error: 'Invalid token payload', message: 'Invalid Token' });
    }
    req.user = decoded;
    next();
  } catch (_err) {
    return res.status(403).json({ error: 'Invalid or expired token', message: 'Invalid Token' });
  }
}

function optionalAuthMiddleware(req, _res, next) {
  const token = extractBearerToken(req);
  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
      if (decoded && decoded.userId) {
        req.user = decoded;
      }
    } catch (_err) {
      // Ignore invalid optional token
    }
  }
  next();
}

function adminAuthMiddleware(req, res, next) {
  const token = extractBearerToken(req);
  if (!token) {
    return res.status(401).json({ error: 'Admin authentication required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    if (!decoded || decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Admin privileges required' });
    }
    req.admin = decoded;
    next();
  } catch (_err) {
    return res.status(403).json({ error: 'Invalid or expired admin session' });
  }
}

function technicianAuthMiddleware(req, res, next) {
  const token = extractBearerToken(req);
  if (!token) {
    return res.status(401).json({ error: 'Technician authentication required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    if (!decoded || (decoded.role !== 'technician' && decoded.role !== 'partner' && !decoded.userId)) {
      return res.status(403).json({ error: 'Technician privileges required' });
    }
    req.technician = decoded;
    next();
  } catch (_err) {
    return res.status(403).json({ error: 'Invalid or expired technician token' });
  }
}

module.exports = authMiddleware;
module.exports.authMiddleware = authMiddleware;
module.exports.optionalAuthMiddleware = optionalAuthMiddleware;
module.exports.adminAuthMiddleware = adminAuthMiddleware;
module.exports.technicianAuthMiddleware = technicianAuthMiddleware;
