const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const crypto = require('crypto');
const { supabase } = require('./supabase');
const { isEnabled } = require('../config/features');

/**
 * Multi-Factor Authentication Service
 *
 * Provides TOTP-based MFA functionality with encrypted storage,
 * backup codes, and comprehensive security controls.
 */
class MFAService {
  constructor() {
    // Encryption key should be stored in environment variables
    this.encryptionKey = process.env.MFA_ENCRYPTION_KEY;
    if (!this.encryptionKey) {
      console.warn('MFA_ENCRYPTION_KEY environment variable not set. MFA functionality will be limited.');
      // Generate a temporary key for development (not for production!)
      if (process.env.NODE_ENV === 'development') {
        // Use deterministic key for development to prevent breaking existing MFA setups on restart
        this.encryptionKey = 'dev-key-' + crypto.createHash('sha256').update(process.env.USER || 'default').digest('hex').substring(0, 32);
        console.warn('Using deterministic MFA encryption key for development. Set MFA_ENCRYPTION_KEY in production!');
      }
    }

    // MFA configuration
    this.config = {
      issuer: process.env.MFA_ISSUER || 'Burando Maritime Services',
      serviceName: process.env.MFA_SERVICE_NAME || 'Maritime Onboarding',
      secretLength: 32,
      backupCodeCount: 10,
      backupCodeLength: 8,
      totpWindow: 1, // Allow 30-second window
      rateLimitWindow: 15 * 60 * 1000, // 15 minutes in milliseconds
      maxFailures: 5
    };
  }

  /**
   * Check if MFA is enabled via feature flags
   */
  isMFAEnabled() {
    return isEnabled('MFA_ENABLED');
  }

  /**
   * Check if MFA enforcement is enabled
   */
  isMFAEnforcementEnabled() {
    return isEnabled('MFA_ENFORCEMENT');
  }

  /**
   * Check if backup codes are enabled
   */
  areBackupCodesEnabled() {
    return isEnabled('MFA_BACKUP_CODES');
  }

  /**
   * Encrypt MFA secret before storage using AES-256-GCM
   */
  encryptSecret(secret) {
    if (!this.encryptionKey) {
      throw new Error('MFA encryption key not configured');
    }

    const algorithm = 'aes-256-gcm';
    const iv = crypto.randomBytes(16);
    const key = Buffer.from(this.encryptionKey, 'hex');
    const cipher = crypto.createCipheriv(algorithm, key, iv);

    let encrypted = cipher.update(secret, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();

    return {
      encrypted,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
      algorithm
    };
  }

  /**
   * Decrypt MFA secret for verification
   */
  decryptSecret(encryptedData) {
    if (!this.encryptionKey) {
      throw new Error('MFA encryption key not configured');
    }

    try {
      const algorithm = encryptedData.algorithm || 'aes-256-gcm';
      const key = Buffer.from(this.encryptionKey, 'hex');
      const iv = Buffer.from(encryptedData.iv, 'hex');
      const decipher = crypto.createDecipheriv(algorithm, key, iv);

      if (encryptedData.authTag) {
        decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
      }

      let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      return decrypted;
    } catch (error) {
      console.error('Failed to decrypt MFA secret:', error.message);
      throw new Error('Failed to decrypt MFA secret');
    }
  }

  /**
   * Set up MFA for a user
   */
  async setupMFA(userId) {
    if (!this.isMFAEnabled()) {
      throw new Error('MFA is not enabled');
    }

    try {
      // Generate TOTP secret
      const secret = speakeasy.generateSecret({
        name: `${this.config.serviceName} (${userId})`,
        issuer: this.config.issuer,
        length: this.config.secretLength
      });

      // Generate cryptographically secure backup codes
      const backupCodes = this.areBackupCodesEnabled() ?
        this.generateSecureBackupCodes() : [];

      // Encrypt secret before storage
      const encryptedSecret = this.encryptSecret(secret.base32);

      // Encrypt backup codes
      const encryptedBackupCodes = backupCodes.map(code =>
        this.encryptSecret(code).encrypted
      );

      // Store in database with encrypted data
      const { data, error } = await supabase
        .from('user_mfa_settings')
        .upsert({
          user_id: userId,
          secret: JSON.stringify(encryptedSecret),
          backup_codes: encryptedBackupCodes,
          enabled: false,
          updated_at: new Date().toISOString()
        }, {
          onConflict: 'user_id'
        });

      if (error) {
        console.error('Database error during MFA setup:', error);
        throw new Error(`Failed to setup MFA: ${error.message}`);
      }

      // Generate QR code
      const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url, {
        width: 256,
        margin: 2,
        color: {
          dark: '#132545', // Burando navy
          light: '#FFFFFF'
        }
      });

      // Log MFA setup initiation
      await this.logMFAEvent(userId, 'mfa_setup_initiated', {
        backup_codes_count: backupCodes.length
      });

      return {
        qrCode: qrCodeUrl,
        backupCodes: this.areBackupCodesEnabled() ? backupCodes : [],
        manualEntryKey: secret.base32, // Only return for setup, don't store
        issuer: this.config.issuer,
        serviceName: this.config.serviceName
      };
    } catch (error) {
      console.error('MFA setup error:', error);
      throw error;
    }
  }

  /**
   * Verify TOTP code or backup code
   * @param {string} userId - User ID
   * @param {string} token - TOTP or backup code
   * @param {string} ipAddress - Client IP address
   * @param {boolean} allowSetup - Allow verification during setup (before MFA is enabled)
   */
  async verifyTOTP(userId, token, ipAddress = null, allowSetup = false) {
    if (!this.isMFAEnabled()) {
      throw new Error('MFA is not enabled');
    }

    // Check rate limiting first
    const rateLimitCheck = await this.checkMFARateLimit(userId);
    if (!rateLimitCheck.allowed) {
      await this.logMFAEvent(userId, 'mfa_rate_limited', {
        ip_address: ipAddress,
        retry_after: rateLimitCheck.retryAfter
      });

      return {
        success: false,
        error: 'Too many failed attempts. Try again later.',
        retryAfter: rateLimitCheck.retryAfter
      };
    }

    try {
      const { data: mfaSettings, error } = await supabase
        .from('user_mfa_settings')
        .select('secret, backup_codes, enabled')
        .eq('user_id', userId)
        .single();

      if (error || !mfaSettings) {
        return { success: false, error: 'MFA not configured' };
      }

      // Only check if enabled when not in setup mode
      if (!allowSetup && !mfaSettings.enabled) {
        return { success: false, error: 'MFA not enabled for this user' };
      }

      // Clean token input
      const cleanToken = token.replace(/\s/g, '').toUpperCase();

      // Try TOTP verification first
      if (cleanToken.length === 6 && /^\d{6}$/.test(cleanToken)) {
        const decryptedSecret = this.decryptSecret(JSON.parse(mfaSettings.secret));

        const verified = speakeasy.totp.verify({
          secret: decryptedSecret,
          encoding: 'base32',
          token: cleanToken,
          window: this.config.totpWindow
        });

        if (verified) {
          await this.resetMFAFailureCount(userId);
          await this.updateLastUsed(userId);
          await this.logMFAEvent(userId, 'mfa_verification_success', {
            method: 'totp',
            ip_address: ipAddress
          });

          return { success: true, method: 'totp' };
        }
      }

      // Try backup codes if enabled and token format matches
      if (this.areBackupCodesEnabled() &&
          mfaSettings.backup_codes &&
          mfaSettings.backup_codes.length > 0 &&
          cleanToken.length === this.config.backupCodeLength) {

        // Check if any backup code matches
        for (const encryptedCode of mfaSettings.backup_codes) {
          try {
            const decryptedCode = this.decryptSecret({ encrypted: encryptedCode });
            if (decryptedCode === cleanToken) {
              await this.resetMFAFailureCount(userId);
              await this.useBackupCode(userId, encryptedCode);
              await this.logMFAEvent(userId, 'mfa_verification_success', {
                method: 'backup_code',
                ip_address: ipAddress
              });

              return { success: true, method: 'backup_code' };
            }
          } catch (decryptError) {
            // Skip invalid encrypted codes
            continue;
          }
        }
      }

      // Record failed attempt
      await this.recordFailedMFAAttempt(userId, 'totp_invalid', ipAddress);
      await this.logMFAEvent(userId, 'mfa_verification_failed', {
        ip_address: ipAddress,
        token_format: cleanToken.length === 6 ? 'totp' : 'backup_code'
      });

      return { success: false, error: 'Invalid verification code' };

    } catch (error) {
      console.error('MFA verification error:', error);
      await this.logMFAEvent(userId, 'mfa_verification_error', {
        error: error.message,
        ip_address: ipAddress
      });
      return { success: false, error: 'Verification failed due to system error' };
    }
  }

  /**
   * Enable MFA after successful verification
   */
  async enableMFA(userId, verificationToken, ipAddress = null) {
    if (!this.isMFAEnabled()) {
      throw new Error('MFA is not enabled');
    }

    // Allow verification during setup (before MFA is enabled)
    const verification = await this.verifyTOTP(userId, verificationToken, ipAddress, true);

    if (!verification.success) {
      return verification;
    }

    try {
      const { error } = await supabase
        .from('user_mfa_settings')
        .update({
          enabled: true,
          setup_completed_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        })
        .eq('user_id', userId);

      if (error) {
        console.error('Database error enabling MFA:', error);
        return { success: false, error: error.message };
      }

      // Log MFA enablement
      await this.logMFAEvent(userId, 'mfa_enabled', {
        method: verification.method,
        ip_address: ipAddress
      });

      return { success: true };
    } catch (error) {
      console.error('Error enabling MFA:', error);
      return { success: false, error: 'Failed to enable MFA' };
    }
  }

  /**
   * Generate cryptographically secure backup codes
   */
  generateSecureBackupCodes() {
    return Array.from({ length: this.config.backupCodeCount }, () => {
      // Use crypto.randomBytes for cryptographically secure random generation
      const randomBytes = crypto.randomBytes(6);
      return randomBytes.toString('base64')
        .replace(/[+/=]/g, '')
        .substring(0, this.config.backupCodeLength)
        .toUpperCase();
    });
  }

  /**
   * Check MFA rate limiting
   */
  async checkMFARateLimit(userId) {
    try {
      const windowStart = new Date(Date.now() - this.config.rateLimitWindow);

      const { data: attempts, error } = await supabase
        .from('mfa_failure_log')
        .select('*')
        .eq('user_id', userId)
        .gte('created_at', windowStart.toISOString())
        .order('created_at', { ascending: false });

      if (error) {
        console.error('Error checking MFA rate limit:', error);
        return { allowed: true }; // Allow on error to prevent lockout
      }

      const failureCount = attempts?.length || 0;

      if (failureCount >= this.config.maxFailures) {
        return {
          allowed: false,
          retryAfter: new Date(Date.now() + this.config.rateLimitWindow)
        };
      }

      return { allowed: true };
    } catch (error) {
      console.error('Rate limit check error:', error);
      return { allowed: true }; // Allow on error
    }
  }

  /**
   * Record failed MFA attempt
   */
  async recordFailedMFAAttempt(userId, failureType = 'totp_invalid', ipAddress = null) {
    try {
      await supabase
        .from('mfa_failure_log')
        .insert({
          user_id: userId,
          ip_address: ipAddress,
          failure_type: failureType,
          created_at: new Date().toISOString()
        });
    } catch (error) {
      console.error('Error recording MFA failure:', error);
    }
  }

  /**
   * Reset MFA failure count for user
   */
  async resetMFAFailureCount(userId) {
    try {
      await supabase
        .from('mfa_failure_log')
        .delete()
        .eq('user_id', userId);
    } catch (error) {
      console.error('Error resetting MFA failure count:', error);
    }
  }

  /**
   * Update last used timestamp
   */
  async updateLastUsed(userId) {
    try {
      await supabase
        .from('user_mfa_settings')
        .update({
          last_used_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        })
        .eq('user_id', userId);
    } catch (error) {
      console.error('Error updating MFA last used:', error);
    }
  }

  /**
   * Use a backup code (remove it from available codes)
   */
  async useBackupCode(userId, usedEncryptedCode) {
    try {
      const { data: settings, error: fetchError } = await supabase
        .from('user_mfa_settings')
        .select('backup_codes')
        .eq('user_id', userId)
        .single();

      if (fetchError || !settings || !settings.backup_codes) {
        console.error('Error fetching backup codes:', fetchError);
        return;
      }

      // Remove the used code
      const updatedCodes = settings.backup_codes.filter(code => code !== usedEncryptedCode);

      const { error: updateError } = await supabase
        .from('user_mfa_settings')
        .update({
          backup_codes: updatedCodes,
          last_used_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        })
        .eq('user_id', userId);

      if (updateError) {
        console.error('Error updating backup codes:', updateError);
        return;
      }

      // Log backup code usage
      await this.logMFAEvent(userId, 'mfa_backup_code_used', {
        remaining_codes: updatedCodes.length
      });

    } catch (error) {
      console.error('Error using backup code:', error);
    }
  }

  /**
   * Get MFA status for a user
   */
  async getMFAStatus(userId) {
    if (!this.isMFAEnabled()) {
      return {
        configured: false,
        enabled: false,
        available: false,
        reason: 'MFA feature is disabled'
      };
    }

    try {
      const { data, error } = await supabase
        .from('user_mfa_settings')
        .select('enabled, setup_completed_at, last_used_at, backup_codes')
        .eq('user_id', userId)
        .single();

      if (error && error.code !== 'PGRST116') { // PGRST116 = no rows returned
        console.error('Error fetching MFA status:', error);
        return { configured: false, enabled: false, available: true };
      }

      const backupCodesCount = data?.backup_codes?.length || 0;

      return {
        configured: !!data,
        enabled: data?.enabled || false,
        available: true,
        setupCompletedAt: data?.setup_completed_at,
        lastUsedAt: data?.last_used_at,
        backupCodesCount: this.areBackupCodesEnabled() ? backupCodesCount : 0,
        backupCodesEnabled: this.areBackupCodesEnabled(),
        enforcementEnabled: this.isMFAEnforcementEnabled()
      };
    } catch (error) {
      console.error('Error getting MFA status:', error);
      return { configured: false, enabled: false, available: true };
    }
  }

  /**
   * Log MFA events for audit trail
   */
  async logMFAEvent(userId, action, details = {}) {
    try {
      await supabase
        .from('audit_log')
        .insert({
          user_id: userId,
          action: action,
          resource_type: 'user_security',
          details: {
            ...details,
            timestamp: new Date().toISOString(),
            mfa_service_version: '1.0'
          }
        });
    } catch (error) {
      console.error('Error logging MFA event:', error);
    }
  }

  /**
   * Regenerate backup codes for a user
   */
  async regenerateBackupCodes(userId) {
    if (!this.isMFAEnabled() || !this.areBackupCodesEnabled()) {
      throw new Error('Backup codes are not enabled');
    }

    try {
      // Generate new backup codes
      const newBackupCodes = this.generateSecureBackupCodes();

      // Encrypt new backup codes
      const encryptedBackupCodes = newBackupCodes.map(code =>
        this.encryptSecret(code).encrypted
      );

      // Update in database
      const { error } = await supabase
        .from('user_mfa_settings')
        .update({
          backup_codes: encryptedBackupCodes,
          updated_at: new Date().toISOString()
        })
        .eq('user_id', userId);

      if (error) {
        console.error('Error regenerating backup codes:', error);
        throw new Error('Failed to regenerate backup codes');
      }

      // Log backup code regeneration
      await this.logMFAEvent(userId, 'mfa_backup_codes_regenerated', {
        new_codes_count: newBackupCodes.length
      });

      return {
        success: true,
        backupCodes: newBackupCodes
      };

    } catch (error) {
      console.error('Error regenerating backup codes:', error);
      throw error;
    }
  }

  /**
   * Disable MFA for a user (admin function)
   */
  async disableMFA(userId, adminUserId = null) {
    if (!this.isMFAEnabled()) {
      throw new Error('MFA is not enabled');
    }

    try {
      const { error } = await supabase
        .from('user_mfa_settings')
        .update({
          enabled: false,
          updated_at: new Date().toISOString()
        })
        .eq('user_id', userId);

      if (error) {
        console.error('Error disabling MFA:', error);
        throw new Error('Failed to disable MFA');
      }

      // Log MFA disabling
      await this.logMFAEvent(userId, 'mfa_disabled', {
        disabled_by: adminUserId || userId,
        admin_action: !!adminUserId
      });

      return { success: true };

    } catch (error) {
      console.error('Error disabling MFA:', error);
      throw error;
    }
  }
}

// Create singleton instance
const mfaService = new MFAService();

module.exports = mfaService;
