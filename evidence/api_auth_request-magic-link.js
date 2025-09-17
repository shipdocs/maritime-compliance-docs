// Vercel API Route: /api/auth/request-magic-link.js
const { supabase } = require('../../lib/supabase');
const { generateMagicToken } = require('../../lib/auth');
const { unifiedEmailService } = require('../../lib/unifiedEmailService');
const { authRateLimit } = require('../../lib/rateLimit');
const { parseJsonBody } = require('../../lib/nodeBodyParser');

// Helper function to log magic link request security events
async function logMagicLinkRequestEvent(email, ipAddress, userAgent, eventType, details = {}) {
  try {
    await supabase
      .from('security_events')
      .insert({
        type: `magic_link_request_${eventType}`,
        severity: eventType === 'rate_limited' || eventType === 'privileged_user' ? 'medium' : 'low',
        user_id: null,
        ip_address: ipAddress,
        user_agent: userAgent,
        details: {
          email: email,
          timestamp: new Date().toISOString(),
          ...details
        },
        threats: eventType === 'rate_limited' ? ['magic_link_abuse'] : []
      });
  } catch (_error) {
    console.error('Failed to log magic link request security event:', _error);
  }
}

// Rate limiting: Check recent magic link requests
async function checkRateLimit(email, ipAddress) {
  const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();

  // Check requests by email (max 3 per 5 minutes)
  const { data: emailRequests } = await supabase
    .from('magic_links')
    .select('id')
    .eq('email', email)
    .gte('created_at', fiveMinutesAgo);

  // Check requests by IP (max 10 per 5 minutes)
  const { data: ipRequests } = await supabase
    .from('security_events')
    .select('id')
    .eq('type', 'magic_link_request_success')
    .eq('ip_address', ipAddress)
    .gte('created_at', fiveMinutesAgo);

  return {
    emailLimited: (emailRequests?.length || 0) >= 3,
    ipLimited: (ipRequests?.length || 0) >= 10
  };
}

async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    // Ensure JSON body is available
    let body = req.body;
    if (!body || typeof body !== 'object') {
      body = await parseJsonBody(req);
    }

    // Enhanced input validation
    if (!body || typeof body !== 'object') {
      return res.status(400).json({
        error: 'Invalid request body',
        code: 'VALIDATION_INVALID_BODY'
      });
    }

    const { email } = body;
    const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown';
    const userAgent = req.headers['user-agent'] || 'unknown';

    // Comprehensive email validation
    if (!email || (typeof email === 'string' && !email.trim())) {
      return res.status(400).json({
        error: 'Email address is required',
        code: 'VALIDATION_EMAIL_REQUIRED'
      });
    }

    if (typeof email !== 'string') {
      return res.status(400).json({
        error: 'Email must be a string',
        code: 'VALIDATION_EMAIL_INVALID_TYPE'
      });
    }

    const emailTrimmed = email.trim();

    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(emailTrimmed)) {
      return res.status(400).json({
        error: 'Please provide a valid email address',
        code: 'VALIDATION_EMAIL_INVALID_FORMAT'
      });
    }

    // Email length validation
    if (emailTrimmed.length > 254) {
      return res.status(400).json({
        error: 'Email address is too long',
        code: 'VALIDATION_EMAIL_TOO_LONG'
      });
    }

    // Normalize email for processing
    const normalizedEmail = emailTrimmed.toLowerCase();

    // If Supabase isn't configured, return a generic success to avoid 500s and user enumeration
    const supabaseConfigured = process.env.NEXT_PUBLIC_SUPABASE_URL &&
      process.env.NEXT_PUBLIC_SUPABASE_URL !== 'https://your-project-id.supabase.co' &&
      process.env.SUPABASE_SERVICE_ROLE_KEY &&
      process.env.SUPABASE_SERVICE_ROLE_KEY !== 'your-service-role-key-here';

    if (!supabaseConfigured) {
      console.warn('[MAGIC LINK] Supabase not configured; returning generic success for', normalizedEmail);
      return res.status(200).json({
        message: 'If an account exists with this email address, a magic link has been sent. Please check your inbox.'
      });
    }

    // Check rate limiting
    const rateLimitCheck = await checkRateLimit(normalizedEmail, clientIP);
    if (rateLimitCheck.emailLimited || rateLimitCheck.ipLimited) {
      await logMagicLinkRequestEvent(normalizedEmail, clientIP, userAgent, 'rate_limited', {
        reason: rateLimitCheck.emailLimited ? 'email_rate_limited' : 'ip_rate_limited'
      });

      return res.status(429).json({
        error: 'Too many requests. Please wait a few minutes before requesting another magic link.'
      });
    }

    // Check if user exists and is a crew member (managers must use Staff Login)
    const { data: user, error: userError } = await supabase
      .from('users')
      .select('*')
      .eq('email', normalizedEmail)
      .single();

    if (userError || !user) {
      // Don't reveal if user exists or not for security - return generic success message
      return res.status(200).json({
        message: 'If an account exists with this email address, a magic link has been sent. Please check your inbox.'
      });
    }

    // Block magic links for privileged users (admin/manager)
    if (['admin', 'manager'].includes(user.role)) {
      await logMagicLinkRequestEvent(normalizedEmail, clientIP, userAgent, 'privileged_user', {
        role: user.role,
        reason: 'Staff members must use password login'
      });

      return res.status(403).json({
        error: 'Staff members must use the Staff Login option with password and MFA. Magic links are only available for crew members.',
        code: 'STAFF_USE_PASSWORD_LOGIN'
      });
    }

    // Only allow crew members to use magic links
    if (user.role !== 'crew') {
      return res.status(403).json({
        error: 'Magic links are only available for crew members. Please contact your administrator.',
        code: 'MAGIC_LINK_NOT_ALLOWED'
      });
    }

    // Check if user is active (different checks for crew vs manager)
    // Crew members can log in if they're in progress or beyond (not if not_started or suspended)
    const allowedCrewStatuses = ['in_progress', 'forms_completed', 'training_completed', 'fully_completed'];
    if (user.role === 'crew' && !allowedCrewStatuses.includes(user.status)) {
      return res.status(403).json({
        error: `Your account is not active (status: ${user.status}). Please contact your manager.`
      });
    }

    if (user.role === 'manager' && !user.is_active) {
      return res.status(403).json({
        error: 'Your manager account is not active. Please contact your administrator.'
      });
    }

    // Generate new magic link
    const token = generateMagicToken();
    const expiresAt = new Date(Date.now() + 3 * 60 * 60 * 1000); // 3 hours

    const { error: linkError } = await supabase
      .from('magic_links')
      .insert({
        email: user.email,
        token,
        expires_at: expiresAt.toISOString()
      });

    if (linkError) {
      // console.error('Error creating magic link:', linkError);
      return res.status(500).json({ error: 'Failed to generate magic link' });
    }

    // Send magic link email using unified service
    try {

      if (user.role === 'manager') {
        // Use manager magic link email service
        await unifiedEmailService.sendManagerMagicLinkEmail(user.id, token);
      } else {
        // Use crew magic link email service
        await unifiedEmailService.sendCrewMagicLinkEmail(user.id, token);
      }

      // Log successful magic link request
      await logMagicLinkRequestEvent(normalizedEmail, clientIP, userAgent, 'success', {
        user_id: user.id,
        role: user.role
      });

      res.json({
        message: 'A new magic link has been sent to your email address. Please check your inbox.'
      });
    } catch (emailError) {
      // console.error('📧 [ERROR] Failed to send magic link:', emailError);
      res.status(500).json({
        error: 'Failed to send magic link. Please try again later or contact your administrator.'
      });
    }
  } catch (_error) {
    console.error('Request magic link error (masked to user):', _error?.message || _error);
    // Return generic success to avoid user enumeration and client crashes
    return res.status(200).json({
      message: 'If an account exists with this email address, a magic link has been sent. Please check your inbox.'
    });
  }
}

module.exports = handler;
