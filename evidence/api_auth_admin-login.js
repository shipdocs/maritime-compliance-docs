// Vercel API Route: /api/auth/admin-login.js - Admin login endpoint
const { supabase } = require('../../lib/supabase');
const { generateTokenPair } = require('../../lib/auth');
const { authRateLimit, checkBodySize } = require('../../lib/rateLimit');
const { accountLockout } = require('../../lib/accountLockout');
const bcrypt = require('bcrypt');
const { notificationService } = require('../../lib/notificationService');
const { createAPIHandler, createError, createValidationError, createAuthError, createDatabaseError } = require('../../lib/apiHandler');
const { validators, sanitizers, schema, validateObject } = require('../../lib/validation');
const { 
  createStandardAuthError, 
  createStandardValidationError,
  formatLockoutMessage,
  formatRemainingAttemptsMessage,
  createAuthSuccessResponse,
  validateCompleteAuthRequest,
  sanitizeAuthInput,
  logAuthSecurityEvent
} = require('../../lib/auth/authErrorHandler');
const { withBodySizeLimit } = require('../../lib/middleware/bodySizeLimit');
const { parseJsonBody } = require('../../lib/nodeBodyParser');

// Helper function to log failed login attempts as security events
function logFailedLoginAttempt(email, ipAddress, userAgent, reason) {
  // Use setTimeout to make this non-blocking
  setTimeout(async () => {
    try {
      const { error } = await supabase
        .from('security_events')
        .insert({
          event_id: `auth_fail_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          type: 'authentication_failure',
          severity: 'medium',
          user_id: null,
          ip_address: ipAddress,
          user_agent: userAgent,
          details: {
            email: email,
            reason: reason,
            timestamp: new Date().toISOString()
          },
          threats: ['brute_force_attempt']
        });

      if (error) {
        console.error('Failed to log security event:', error);
      }
    } catch (logError) {
      console.error('Security logging error:', logError);
    }
  }, 0);
}

async function handler(req, res) {
  try {
    // Ensure JSON body is available
    if (!req.body || typeof req.body !== 'object') {
      const parsed = await parseJsonBody(req);
      if (parsed && typeof parsed === 'object') {
        req.body = parsed;
      }
    }

    // Check if environment variables are configured
    if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
      throw createStandardAuthError('SYSTEM_CONFIGURATION_ERROR', 'Database connection not configured', null, req.requestId);
    }

    if (!process.env.JWT_SECRET) {
      throw createStandardAuthError('SYSTEM_CONFIGURATION_ERROR', 'Authentication not configured', null, req.requestId);
    }

  // Comprehensive request validation with admin password strength requirements
  req.body.role = 'admin'; // Mark as admin for password strength validation
  const validationErrors = validateCompleteAuthRequest(req, ['email', 'password']);
  if (validationErrors.length > 0) {
    throw createStandardValidationError('VALIDATION_INVALID_FORMAT', 'Validation failed', { 
      errors: validationErrors 
    }, req.requestId);
  }

  // Get validated and sanitized values
  const email = sanitizeAuthInput(req.body.email);
  const password = sanitizeAuthInput(req.body.password);

  // Get client info for lockout tracking
  const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  const userAgent = sanitizers.log(req.headers['user-agent'] || 'unknown');
  const normalizedEmail = email; // Already normalized by validator

  // Check if account is locked
  const isLocked = await accountLockout.isAccountLocked(normalizedEmail);
  if (isLocked) {
    const lockoutStatus = await accountLockout.getLockoutStatus(normalizedEmail);
    const lockoutSettings = await accountLockout.getLockoutSettings();

    const message = formatLockoutMessage(
      lockoutStatus?.lockedUntil,
      lockoutStatus?.failedAttempts,
      lockoutSettings.maxAttempts
    );

    throw createStandardAuthError('AUTH_ACCOUNT_LOCKED', message, {
      locked: true,
      lockedUntil: lockoutStatus?.lockedUntil,
      failedAttempts: lockoutStatus?.failedAttempts
    }, req.requestId);
  }

  // Get admin user from database
  const { data: user, error: userError } = await supabase
    .from('users')
    .select('*')
    .eq('email', normalizedEmail)
    .eq('role', 'admin')
    .eq('is_active', true)
    .single();

  if (userError) {
    // Record failed attempt for non-existent users too (prevent user enumeration)
    await accountLockout.recordFailedLogin(normalizedEmail, clientIP, userAgent);

    // Log security event
    await logAuthSecurityEvent(supabase, 'failure', normalizedEmail, clientIP, userAgent, { reason: 'user_not_found' });

    throw createStandardAuthError('AUTH_INVALID_CREDENTIALS', 'Invalid email or password', null, req.requestId);
  }

  if (!user) {
    // Let's check if user exists with different conditions
    const { data: anyUser } = await supabase
      .from('users')
      .select('email, role, is_active, status')
      .eq('email', normalizedEmail)
      .single();

    await accountLockout.recordFailedLogin(normalizedEmail, clientIP, userAgent);

    // Log security event
    await logAuthSecurityEvent(supabase, 'failure', normalizedEmail, clientIP, userAgent, { reason: 'user_not_found' });

    throw createStandardAuthError('AUTH_INVALID_CREDENTIALS', 'Invalid email or password', null, req.requestId);
  }

  // Check if user has a password hash
  if (!user.password_hash) {
    await accountLockout.recordFailedLogin(normalizedEmail, clientIP, userAgent);

    // Log security event
    await logAuthSecurityEvent(supabase, 'failure', normalizedEmail, clientIP, userAgent, { reason: 'no_password_configured' });

    throw createStandardAuthError('AUTH_ACCOUNT_NOT_CONFIGURED', 'Account not properly configured. Please contact system administrator.', null, req.requestId);
  }

  // Verify password using bcrypt
  const isValidPassword = await bcrypt.compare(password, user.password_hash);

  if (!isValidPassword) {
    // Record failed login attempt
    const failedResult = await accountLockout.recordFailedLogin(normalizedEmail, clientIP, userAgent);

    // Log security event
    await logAuthSecurityEvent(supabase, 'failure', normalizedEmail, clientIP, userAgent, { reason: 'invalid_password' });

    if (failedResult.locked) {
      const lockoutSettings = await accountLockout.getLockoutSettings();
      const message = formatLockoutMessage(
        new Date(failedResult.locked_until),
        failedResult.attempts,
        lockoutSettings.maxAttempts
      );

      throw createStandardAuthError('AUTH_ACCOUNT_LOCKED', message, {
        locked: true,
        lockedUntil: failedResult.locked_until,
        attempts: failedResult.attempts
      }, req.requestId);
    } else {
      const lockoutSettings = await accountLockout.getLockoutSettings();
      const message = formatRemainingAttemptsMessage(failedResult.attempts, lockoutSettings.maxAttempts);

      throw createStandardAuthError('AUTH_INVALID_CREDENTIALS', message, {
        attemptsRemaining: lockoutSettings.maxAttempts - failedResult.attempts,
        failedAttempts: failedResult.attempts
      }, req.requestId);
    }
  }

  // Check if account is active (admin users don't need specific status check)
  if (user.role !== 'admin' && user.status !== 'fully_completed') {
    throw createAuthError('AUTH_ACCOUNT_NOT_ACTIVE', 'Account is not active', {
      currentStatus: user.status,
      requiredStatus: 'fully_completed'
    });
  }

  // Check for first-time login and trigger notifications (admins usually don't need this, but for consistency)
  try {
    await notificationService.checkAndHandleFirstLogin(user);
  } catch (notificationError) {
    // Don't fail the login for notification errors
  }

  // Record successful login (clears failed attempts)
  await accountLockout.recordSuccessfulLogin(normalizedEmail, clientIP, userAgent);

  // Generate token pair (access + refresh tokens)
  const tokenResult = await generateTokenPair(user, req);

  if (!tokenResult.success) {
    throw createStandardAuthError('AUTH_TOKEN_GENERATION_FAILED', 'Failed to generate authentication tokens', null, req.requestId);
  }

  // Log successful admin login
  await supabase
    .from('audit_log')
    .insert({
      user_id: user.id,
      action: 'admin_login',
      resource_type: 'authentication',
      details: {
        ip_address: clientIP,
        user_agent: userAgent,
        lockout_cleared: true
      },
      ip_address: clientIP,
      user_agent: userAgent
    });

  // Create standardized success response
  const successResponse = createAuthSuccessResponse(
    tokenResult,
    {
      id: user.id,
      email: user.email,
      firstName: user.first_name,
      lastName: user.last_name,
      role: user.role,
      position: user.position,
      status: user.status,
      preferredLanguage: user.preferred_language
    },
    req.requestId
  );

  res.json(successResponse);

  } catch (unexpectedError) {
    // If it's already an APIError, re-throw it to be handled by middleware
    if (unexpectedError.name === 'APIError' || unexpectedError.name === 'AuthError' || unexpectedError.name === 'ValidationError') {
      throw unexpectedError;
    }

    // Handle unexpected errors
    // console.error('Admin login unexpected error:', unexpectedError);
    throw createStandardAuthError('SYSTEM_INTERNAL_ERROR', 'Login failed', {
      originalError: unexpectedError.message
    }, req.requestId);
  }
}

// Create the standardized handler with error handling
const apiHandler = createAPIHandler(handler, {
  allowedMethods: ['POST']
});

// Export with rate limiting and body size limit
module.exports = authRateLimit(withBodySizeLimit(apiHandler, 'auth'));
