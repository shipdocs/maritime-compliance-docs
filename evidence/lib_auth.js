// lib/auth.js - Authentication utilities for Vercel API routes
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { supabase } = require('./supabase.js');
const { logAuthorizationFailure } = require('./securityLogger');
const configManager = require('./security/SecureConfigManager');
const securityAuditLogger = require('./security/SecurityAuditLogger');
const EnhancedSessionManager = require('./security/EnhancedSessionManager');

// Initialize session manager
const sessionManager = new EnhancedSessionManager();

// Generate magic link token
function generateMagicToken(userId = null) {
  const token = crypto.randomBytes(32).toString('hex');
  
  // If userId is provided, we could store the token-user mapping
  // For now, we'll use JWT-style encoding to include userId in token
  if (userId) {
    const payload = {
      userId,
      type: 'magic_link',
      exp: Math.floor(Date.now() / 1000) + (30 * 60) // 30 minutes expiry
    };
    
    try {
      const secret = process.env.JWT_SECRET || 'fallback-secret-key';
      return jwt.sign(payload, secret);
    } catch (error) {
      console.error('Failed to create magic token with userId:', error);
      return token; // Fallback to simple token
    }
  }
  
  return token;
}

// Verify magic link token
function verifyMagicToken(token) {
  try {
    const secret = process.env.JWT_SECRET || 'fallback-secret-key';
    
    // Try to decode as JWT first (new format with userId)
    try {
      const decoded = jwt.verify(token, secret);
      
      if (decoded.type === 'magic_link' && decoded.userId) {
        return {
          valid: true,
          userId: decoded.userId,
          exp: decoded.exp
        };
      }
    } catch (jwtError) {
      // Not a JWT or invalid JWT, treat as legacy token
    }
    
    // For legacy tokens or simple validation
    if (typeof token === 'string' && token.length === 64) {
      // This is a legacy hex token - we can't extract userId from it
      // In a real implementation, you'd look this up in a database
      return {
        valid: true,
        userId: null, // Would need database lookup
        legacy: true
      };
    }
    
    return {
      valid: false,
      error: 'Invalid token format'
    };
    
  } catch (error) {
    return {
      valid: false,
      error: error.message || 'Token verification failed'
    };
  }
}

// Generate device fingerprint from request headers
function generateDeviceFingerprint(req) {
  const userAgent = req.headers['user-agent'] || '';
  const acceptLanguage = req.headers['accept-language'] || '';
  const acceptEncoding = req.headers['accept-encoding'] || '';
  const connection = req.headers['connection'] || '';

  const fingerprintData = `${userAgent}|${acceptLanguage}|${acceptEncoding}|${connection}`;
  return crypto.createHash('sha256').update(fingerprintData).digest('hex').substring(0, 16);
}

// Generate JWT token with enhanced security binding and session management
async function generateJWT(user, req = null) {
  const jti = crypto.randomBytes(16).toString('hex'); // Generate unique JWT ID
  const now = Math.floor(Date.now() / 1000);

  // Create session if request is provided
  let sessionId = null;
  if (req && user.id) {
    const sessionResult = await sessionManager.createSession(user.id, req);
    if (sessionResult.success) {
      sessionId = sessionResult.sessionId;
    } else {
      console.warn('Failed to create session:', sessionResult.error);
    }
  }

  // Extract binding information from request
  const binding = req ? {
    ip: req.headers['x-forwarded-for'] || req.connection?.remoteAddress || 'unknown',
    userAgent: req.headers['user-agent'] || 'unknown',
    deviceFingerprint: generateDeviceFingerprint(req)
  } : null;

  const payload = {
    userId: user.id,
    email: user.email,
    role: user.role,
    firstName: user.first_name,
    lastName: user.last_name,
    sessionId: sessionId, // Include session ID in token
    iat: now,
    // Token binding for theft prevention
    binding: binding ? {
      ipHash: crypto.createHash('sha256').update(binding.ip).digest('hex').substring(0, 16),
      uaHash: crypto.createHash('sha256').update(binding.userAgent).digest('hex').substring(0, 16),
      deviceFingerprint: binding.deviceFingerprint
    } : null
  };

  return jwt.sign(payload, configManager.getString('JWT_SECRET'), {
    expiresIn: '2h', // Reduced from 24h to 2h for enhanced security
    issuer: 'crew-onboarding-app',
    jwtid: jti // Set JWT ID in standard JWT claims
  });
}

// Verify JWT token with enhanced security validation and session checking
async function verifyJWT(token, req = null) {
  try {
    const decoded = jwt.verify(token, configManager.getString('JWT_SECRET'));

    // Validate session if sessionId is present
    if (decoded.sessionId && decoded.userId && req) {
      const sessionValidation = await sessionManager.validateSession(
        decoded.sessionId,
        decoded.userId,
        req
      );

      if (!sessionValidation.valid) {
        console.log('🔒 [AUTH] Session validation failed:', sessionValidation.reason);
        return null;
      }
    }

    // If request is provided, validate token binding
    if (req && decoded.binding) {
      const currentIp = req.headers['x-forwarded-for'] || req.connection?.remoteAddress || 'unknown';
      const currentUserAgent = req.headers['user-agent'] || 'unknown';
      const currentDeviceFingerprint = generateDeviceFingerprint(req);

      // Create hashes for comparison
      const currentIpHash = crypto.createHash('sha256').update(currentIp).digest('hex').substring(0, 16);
      const currentUaHash = crypto.createHash('sha256').update(currentUserAgent).digest('hex').substring(0, 16);

      // Validate binding - fail if any binding check fails
      if (decoded.binding.ipHash !== currentIpHash) {
        console.log('🔒 [AUTH] Token binding validation failed: IP mismatch');
        return null;
      }

      if (decoded.binding.uaHash !== currentUaHash) {
        console.log('🔒 [AUTH] Token binding validation failed: User Agent mismatch');
        return null;
      }

      if (decoded.binding.deviceFingerprint !== currentDeviceFingerprint) {
        console.log('🔒 [AUTH] Token binding validation failed: Device fingerprint mismatch');
        return null;
      }
    }

    return decoded;
  } catch (error) {
    console.log('🔒 [AUTH] Token verification failed:', error.message);
    return null;
  }
}

// Check if token is blacklisted
async function isTokenBlacklisted(token) {
  try {
    const decoded = jwt.decode(token);
    if (!decoded || !decoded.jti) {
      console.log('🔍 [AUTH] Token has no JTI, skipping blacklist check');
      return false; // Old tokens without jti are not blacklisted
    }

    console.log('🔍 [AUTH] Checking token blacklist for JTI:', decoded.jti);

    // Use the pre-configured supabase client
    const { data, error } = await supabase
      .from('token_blacklist')
      .select('id')
      .eq('token_jti', decoded.jti)
      .gt('expires_at', new Date().toISOString())
      .limit(1);

    if (error) {
      console.log('🔍 [AUTH] Blacklist check error:', error.message);
      return false; // On error, assume not blacklisted to avoid blocking legitimate requests
    }

    const isBlacklisted = !!(data && data.length > 0);
    console.log('🔍 [AUTH] Token blacklist result:', isBlacklisted);
    return isBlacklisted;
  } catch (error) {
    console.error('Error checking token blacklist:', error);
    return false; // On error, assume not blacklisted to avoid blocking legitimate requests
  }
}

// Add token to blacklist
async function blacklistToken(token, userId, reason = 'logout', req = null) {
  try {
    const decoded = jwt.decode(token);
    if (!decoded || !decoded.jti) {
      return { success: false, error: 'Token does not have a valid JTI' };
    }

    // Create hash of the token for additional verification
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    // Use service role for inserting into blacklist
    // (the imported supabase client already uses service role)
    const { data, error } = await supabase
      .from('token_blacklist')
      .insert({
        token_jti: decoded.jti,
        user_id: userId,
        token_hash: tokenHash,
        expires_at: new Date(decoded.exp * 1000).toISOString(),
        reason: reason,
        ip_address: req?.headers?.['x-forwarded-for'] || req?.connection?.remoteAddress || null,
        user_agent: req?.headers?.['user-agent'] || null
      });

    if (error) {
      console.error('Error blacklisting token:', error);
      return { success: false, error: error.message };
    }

    return { success: true };
  } catch (error) {
    console.error('Error in blacklistToken:', error);
    return { success: false, error: 'Failed to blacklist token' };
  }
}

// Detect suspicious token activity
async function detectSuspiciousActivity(token, req, decoded) {
  try {
    const suspiciousIndicators = [];

    // Check for rapid location changes (different IP addresses)
    if (decoded.binding && req) {
      const currentIp = req.headers['x-forwarded-for'] || req.connection?.remoteAddress || 'unknown';
      const tokenIpHash = decoded.binding.ipHash;
      const currentIpHash = crypto.createHash('sha256').update(currentIp).digest('hex').substring(0, 16);

      if (tokenIpHash !== currentIpHash) {
        suspiciousIndicators.push('ip_change');
      }
    }

    // Check token age vs usage pattern
    const tokenAge = Date.now() / 1000 - decoded.iat;
    if (tokenAge < 60) { // Token used within 1 minute of creation from different location
      const currentIp = req.headers['x-forwarded-for'] || req.connection?.remoteAddress || 'unknown';
      if (decoded.binding && decoded.binding.ipHash !== crypto.createHash('sha256').update(currentIp).digest('hex').substring(0, 16)) {
        suspiciousIndicators.push('rapid_location_change');
      }
    }

    // Check for unusual user agent patterns
    if (decoded.binding && req) {
      const currentUserAgent = req.headers['user-agent'] || 'unknown';
      const currentUaHash = crypto.createHash('sha256').update(currentUserAgent).digest('hex').substring(0, 16);

      if (decoded.binding.uaHash !== currentUaHash) {
        suspiciousIndicators.push('user_agent_change');
      }
    }

    return {
      isSuspicious: suspiciousIndicators.length > 0,
      indicators: suspiciousIndicators,
      riskLevel: suspiciousIndicators.length >= 2 ? 'high' : suspiciousIndicators.length === 1 ? 'medium' : 'low'
    };
  } catch (error) {
    console.error('Error detecting suspicious activity:', error);
    return { isSuspicious: false, indicators: [], riskLevel: 'low' };
  }
}

// Extract user from request with enhanced security validation
async function authenticateRequest(req) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(' ')[1];

  if (!token) return null;

  // Verify JWT with binding validation and session checking
  const decoded = await verifyJWT(token, req);
  if (!decoded) return null;

  // Check if token is blacklisted (fail-secure)
  try {
    const isBlacklisted = await isTokenBlacklisted(token);
    if (isBlacklisted) {
      console.log('🔒 [AUTH] Token is blacklisted, denying access');
      return null;
    }
  } catch (error) {
    // Fail-secure: if blacklist check fails, deny access
    console.error('🔒 [AUTH] Blacklist check failed, denying access for security:', error.message);
    return null;
  }

  // Detect suspicious activity
  const suspiciousActivity = await detectSuspiciousActivity(token, req, decoded);
  if (suspiciousActivity.isSuspicious && suspiciousActivity.riskLevel === 'high') {
    console.log('🚨 [AUTH] High-risk suspicious activity detected, denying access:', suspiciousActivity.indicators);

    // Blacklist the token due to suspicious activity
    try {
      await blacklistToken(token, decoded.userId, 'suspicious_activity', req);
    } catch (error) {
      console.error('Failed to blacklist suspicious token:', error);
    }

    return null;
  }

  // Log medium-risk suspicious activity but allow access
  if (suspiciousActivity.isSuspicious && suspiciousActivity.riskLevel === 'medium') {
    console.log('⚠️ [AUTH] Medium-risk suspicious activity detected:', suspiciousActivity.indicators);
  }

  return decoded;
}

// Authenticate token and return result object (for compatibility with some API routes)
async function authenticateToken(req) {
  const user = await authenticateRequest(req);
  if (!user) {
    return { success: false, error: 'Access token required' };
  }
  return { success: true, user };
}

// Higher-order function to require authentication
function requireAuth(handler) {
  return async (req, res) => {
    const user = await authenticateRequest(req);
    if (!user) {
      // Log authorization failure (no valid token)
      await logAuthorizationFailure(req, null, 'authenticated', 'unauthenticated');

      // Log authentication failure to security audit logger
      await securityAuditLogger.logAuthentication(
        securityAuditLogger.eventTypes.LOGIN_FAILURE,
        null,
        false,
        { reason: 'no_valid_token', endpoint: req.url },
        req
      );

      return res.status(401).json({ error: 'Access token required' });
    }
    req.user = user;
    return handler(req, res);
  };
}

// Higher-order function to require manager role
function requireManager(handler) {
  return requireAuth(async (req, res) => {
    if (req.user.role !== 'manager') {
      // Log authorization failure (wrong role)
      await logAuthorizationFailure(req, req.user.userId, 'manager', req.user.role);

      // Log authorization failure to security audit logger
      await securityAuditLogger.logAuthorizationFailure(
        req.user.userId,
        'manager',
        req.user.role,
        req.url,
        req
      );

      return res.status(403).json({ error: 'Manager access required' });
    }
    return handler(req, res);
  });
}

// Higher-order function to require crew role
function requireCrew(handler) {
  return requireAuth(async (req, res) => {
    if (req.user.role !== 'crew') {
      // Log authorization failure (wrong role)
      await logAuthorizationFailure(req, req.user.userId, 'crew', req.user.role);

      // Log authorization failure to security audit logger
      await securityAuditLogger.logAuthorizationFailure(
        req.user.userId,
        'crew',
        req.user.role,
        req.url,
        req
      );

      return res.status(403).json({ error: 'Crew member access required' });
    }
    return handler(req, res);
  });
}

// Higher-order function to require admin role
function requireAdmin(handler) {
  return requireAuth(async (req, res) => {
    if (req.user.role !== 'admin') {
      // Log authorization failure (wrong role)
      await logAuthorizationFailure(req, req.user.userId, 'admin', req.user.role);
      return res.status(403).json({ error: 'Administrator access required' });
    }
    return handler(req, res);
  });
}

// Higher-order function to require admin or manager role
function requireManagerOrAdmin(handler) {
  return requireAuth(async (req, res) => {
    if (!['admin', 'manager'].includes(req.user.role)) {
      // Log authorization failure (wrong role)
      await logAuthorizationFailure(req, req.user.userId, 'manager_or_admin', req.user.role);
      return res.status(403).json({ error: 'Manager or Administrator access required' });
    }
    return handler(req, res);
  });
}

// Role hierarchy checker
function hasRoleAccess(userRole, requiredRole) {
  const roleHierarchy = {
    'admin': 3,
    'manager': 2,
    'crew': 1
  };

  return roleHierarchy[userRole] >= roleHierarchy[requiredRole];
}

// Higher-order function for hierarchical role checking
function requireRoleLevel(minimumRole) {
  return (handler) => {
    return requireAuth(async (req, res) => {
      if (!hasRoleAccess(req.user.role, minimumRole)) {
        return res.status(403).json({
          error: `${minimumRole.charAt(0).toUpperCase() + minimumRole.slice(1)} access or higher required`
        });
      }
      return handler(req, res);
    });
  };
}

// Base64url decode helper
function base64urlDecode(str) {
  // Add padding if needed
  str += '=' * (4 - str.length % 4);
  // Replace URL-safe characters
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  // Decode base64
  return Buffer.from(str, 'base64').toString();
}

// Check if token is expired
function isTokenExpired(token) {
  if (!token) return true;

  try {
    const payload = JSON.parse(base64urlDecode(token.split('.')[1]));
    const currentTime = Date.now() / 1000;
    return payload.exp < currentTime;
  } catch (error) {
    return true;
  }
}

// Get token expiration time
function getTokenExpirationTime(token) {
  if (!token) return null;

  try {
    const payload = JSON.parse(base64urlDecode(token.split('.')[1]));
    return payload.exp * 1000; // Convert to milliseconds
  } catch (error) {
    return null;
  }
}

// Check if token is expiring soon
function isTokenExpiringSoon(token, minutesThreshold = 5) {
  const expirationTime = getTokenExpirationTime(token);
  if (!expirationTime) return false;

  const currentTime = Date.now();
  const timeUntilExpiration = expirationTime - currentTime;
  const thresholdMs = minutesThreshold * 60 * 1000;

  return timeUntilExpiration <= thresholdMs && timeUntilExpiration > 0;
}

// Verify authentication and return user with permissions (used in content management APIs)
async function verifyAuth(req, res) {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.split(' ')[1];

    if (!token) {
      res.status(401).json({ error: 'Access token required' });
      return null;
    }

    // Use enhanced JWT verification with binding validation
    const decoded = verifyJWT(token, req);
    if (!decoded) {
      res.status(401).json({ error: 'Invalid or expired token' });
      return null;
    }

    // Check if token is blacklisted (fail-secure)
    try {
      const isBlacklisted = await isTokenBlacklisted(token);
      if (isBlacklisted) {
        res.status(401).json({ error: 'Token has been revoked' });
        return null;
      }
    } catch (error) {
      // Fail-secure: if blacklist check fails, deny access
      console.error('🔒 [AUTH] Blacklist check failed in verifyAuth, denying access:', error.message);
      res.status(500).json({ error: 'Authentication error' });
      return null;
    }

    // Detect suspicious activity
    const suspiciousActivity = await detectSuspiciousActivity(token, req, decoded);
    if (suspiciousActivity.isSuspicious && suspiciousActivity.riskLevel === 'high') {
      console.log('🚨 [AUTH] High-risk suspicious activity detected in verifyAuth:', suspiciousActivity.indicators);

      // Blacklist the token due to suspicious activity
      try {
        await blacklistToken(token, decoded.userId, 'suspicious_activity', req);
      } catch (error) {
        console.error('Failed to blacklist suspicious token in verifyAuth:', error);
      }

      res.status(401).json({ error: 'Suspicious activity detected' });
      return null;
    }

    // Get user details with permissions from database
    // (using the pre-configured supabase client)
    const { data: user, error: userError } = await supabase
      .from('users')
      .select('*')
      .eq('id', decoded.userId)
      .single();

    if (userError || !user) {
      // console.error('Error fetching user:', userError);
      res.status(401).json({ error: 'User not found' });
      return null;
    }

    // For managers, get their permissions
    let permissions = [];
    if (user.role === 'manager') {
      const { data: managerPermissions, error: permError } = await supabase
        .from('manager_permissions')
        .select('permission_key')
        .eq('manager_id', user.id);

      if (!permError && managerPermissions) {
        permissions = managerPermissions.map(p => p.permission_key);
      }
    }

    // Return user object with permissions
    return {
      id: user.id,
      email: user.email,
      role: user.role,
      firstName: user.first_name,
      lastName: user.last_name,
      permissions
    };

  } catch (error) {
    // console.error('Error in verifyAuth:', error);
    res.status(500).json({ error: 'Authentication error' });
    return null;
  }
}

// Generate refresh token
function generateRefreshToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Store refresh token in database
async function storeRefreshToken(userId, refreshToken, req = null) {
  try {
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 30); // 30 days expiration

    const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

    const { data, error } = await supabase
      .from('refresh_tokens')
      .insert({
        user_id: userId,
        token_hash: tokenHash,
        expires_at: expiresAt.toISOString(),
        ip_address: req?.headers?.['x-forwarded-for'] || req?.connection?.remoteAddress || null,
        user_agent: req?.headers?.['user-agent'] || null,
        is_active: true
      });

    if (error) {
      console.error('Error storing refresh token:', error);
      return { success: false, error: error.message };
    }

    return { success: true };
  } catch (error) {
    console.error('Error in storeRefreshToken:', error);
    return { success: false, error: 'Failed to store refresh token' };
  }
}

// Validate refresh token
async function validateRefreshToken(refreshToken) {
  try {
    const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

    const { data, error } = await supabase
      .from('refresh_tokens')
      .select('user_id, expires_at, is_active')
      .eq('token_hash', tokenHash)
      .eq('is_active', true)
      .gt('expires_at', new Date().toISOString())
      .single();

    if (error || !data) {
      return { valid: false, error: 'Invalid or expired refresh token' };
    }

    return { valid: true, userId: data.user_id };
  } catch (error) {
    console.error('Error validating refresh token:', error);
    return { valid: false, error: 'Failed to validate refresh token' };
  }
}

// Rotate refresh token (invalidate old, create new)
async function rotateRefreshToken(oldRefreshToken, req = null) {
  try {
    // First validate the old token
    const validation = await validateRefreshToken(oldRefreshToken);
    if (!validation.valid) {
      return { success: false, error: validation.error };
    }

    // Get user details
    const { data: user, error: userError } = await supabase
      .from('users')
      .select('*')
      .eq('id', validation.userId)
      .single();

    if (userError || !user) {
      return { success: false, error: 'User not found' };
    }

    // Invalidate the old refresh token
    const oldTokenHash = crypto.createHash('sha256').update(oldRefreshToken).digest('hex');
    await supabase
      .from('refresh_tokens')
      .update({ is_active: false })
      .eq('token_hash', oldTokenHash);

    // Generate new tokens
    const newAccessToken = generateJWT(user, req);
    const newRefreshToken = generateRefreshToken();

    // Store new refresh token
    const storeResult = await storeRefreshToken(user.id, newRefreshToken, req);
    if (!storeResult.success) {
      return { success: false, error: storeResult.error };
    }

    return {
      success: true,
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        firstName: user.first_name,
        lastName: user.last_name
      }
    };
  } catch (error) {
    console.error('Error rotating refresh token:', error);
    return { success: false, error: 'Failed to rotate refresh token' };
  }
}

// Blacklist all refresh tokens for a user (on logout)
async function blacklistUserRefreshTokens(userId, reason = 'logout') {
  try {
    const { error } = await supabase
      .from('refresh_tokens')
      .update({ is_active: false })
      .eq('user_id', userId)
      .eq('is_active', true);

    if (error) {
      console.error('Error blacklisting user refresh tokens:', error);
      return { success: false, error: error.message };
    }

    return { success: true };
  } catch (error) {
    console.error('Error in blacklistUserRefreshTokens:', error);
    return { success: false, error: 'Failed to blacklist refresh tokens' };
  }
}

// Generate token pair (access + refresh)
async function generateTokenPair(user, req = null) {
  try {
    const accessToken = await generateJWT(user, req);
    const refreshToken = generateRefreshToken();

    // Store refresh token
    const storeResult = await storeRefreshToken(user.id, refreshToken, req);
    if (!storeResult.success) {
      return { success: false, error: storeResult.error };
    }

    return {
      success: true,
      accessToken,
      refreshToken,
      expiresIn: 2 * 60 * 60, // 2 hours in seconds
      tokenType: 'Bearer'
    };
  } catch (error) {
    console.error('Error generating token pair:', error);
    return { success: false, error: 'Failed to generate token pair' };
  }
}

// Check if access token needs refresh (within 5 minutes of expiry)
function shouldRefreshToken(token) {
  return isTokenExpiringSoon(token, 5);
}

// Export all functions
module.exports = {
  generateMagicToken,
  verifyMagicToken,
  generateJWT,
  verifyJWT,
  authenticateRequest,
  authenticateToken,
  requireAuth,
  requireManager,
  requireCrew,
  requireAdmin,
  requireManagerOrAdmin,
  hasRoleAccess,
  requireRoleLevel,
  isTokenExpired,
  getTokenExpirationTime,
  isTokenExpiringSoon,
  verifyAuth,
  isTokenBlacklisted,
  blacklistToken,
  generateDeviceFingerprint,
  detectSuspiciousActivity,
  generateRefreshToken,
  storeRefreshToken,
  validateRefreshToken,
  rotateRefreshToken,
  blacklistUserRefreshTokens,
  generateTokenPair,
  shouldRefreshToken
};
