/**
 * Audit Service
 * Provides comprehensive audit logging and tracking functionality
 */

const { supabase } = require('../supabase');
const { ErrorHandler } = require('../errorHandler');

/**
 * Audit event types
 */
const AUDIT_EVENTS = {
  // Authentication events
  LOGIN_SUCCESS: 'login_success',
  LOGIN_FAILURE: 'login_failure',
  LOGOUT: 'logout',
  PASSWORD_CHANGE: 'password_change',
  
  // Data events
  DATA_CREATE: 'data_create',
  DATA_READ: 'data_read',
  DATA_UPDATE: 'data_update',
  DATA_DELETE: 'data_delete',
  DATA_EXPORT: 'data_export',
  
  // System events
  SYSTEM_ACCESS: 'system_access',
  SYSTEM_ERROR: 'system_error',
  SYSTEM_CONFIG_CHANGE: 'system_config_change',
  
  // Security events
  SECURITY_VIOLATION: 'security_violation',
  RATE_LIMIT_EXCEEDED: 'rate_limit_exceeded',
  SUSPICIOUS_ACTIVITY: 'suspicious_activity',
  
  // Admin events
  ADMIN_ACTION: 'admin_action',
  USER_ROLE_CHANGE: 'user_role_change',
  PERMISSION_CHANGE: 'permission_change'
};

/**
 * Audit severity levels
 */
const AUDIT_SEVERITY = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical'
};

/**
 * Audit Service Class
 */
class AuditService {
  constructor() {
    this.tableName = 'audit_log';
  }

  /**
   * Log an audit event
   */
  async logEvent(eventType, details = {}) {
    try {
      const auditEntry = {
        event_type: eventType,
        user_id: details.userId || null,
        user_email: details.userEmail || null,
        user_role: details.userRole || null,
        ip_address: details.ipAddress || null,
        user_agent: details.userAgent || null,
        request_id: details.requestId || null,
        endpoint: details.endpoint || null,
        method: details.method || null,
        resource_type: details.resourceType || null,
        resource_id: details.resourceId || null,
        action: details.action || null,
        severity: details.severity || AUDIT_SEVERITY.LOW,
        success: details.success !== false, // Default to true unless explicitly false
        error_message: details.errorMessage || null,
        metadata: details.metadata || {},
        created_at: new Date().toISOString()
      };

      const { data, error } = await supabase
        .from(this.tableName)
        .insert([auditEntry])
        .select()
        .single();

      if (error) {
        console.error('Failed to log audit event:', error);
        return { success: false, error };
      }

      return { success: true, data };
    } catch (error) {
      console.error('Audit logging error:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Log authentication events
   */
  async logAuth(eventType, details = {}) {
    return this.logEvent(eventType, {
      ...details,
      resourceType: 'authentication',
      severity: eventType === AUDIT_EVENTS.LOGIN_FAILURE ? AUDIT_SEVERITY.MEDIUM : AUDIT_SEVERITY.LOW
    });
  }

  /**
   * Log data access events
   */
  async logDataAccess(action, resourceType, resourceId, details = {}) {
    return this.logEvent(AUDIT_EVENTS.DATA_READ, {
      ...details,
      action,
      resourceType,
      resourceId,
      severity: AUDIT_SEVERITY.LOW
    });
  }

  /**
   * Log security events
   */
  async logSecurity(eventType, details = {}) {
    return this.logEvent(eventType, {
      ...details,
      resourceType: 'security',
      severity: details.severity || AUDIT_SEVERITY.HIGH
    });
  }

  /**
   * Log admin actions
   */
  async logAdmin(action, details = {}) {
    return this.logEvent(AUDIT_EVENTS.ADMIN_ACTION, {
      ...details,
      action,
      resourceType: 'admin',
      severity: AUDIT_SEVERITY.MEDIUM
    });
  }

  /**
   * Get audit logs with filtering
   */
  async getLogs(filters = {}) {
    try {
      let query = supabase
        .from(this.tableName)
        .select('*');

      // Apply filters
      if (filters.userId) {
        query = query.eq('user_id', filters.userId);
      }
      if (filters.eventType) {
        query = query.eq('event_type', filters.eventType);
      }
      if (filters.severity) {
        query = query.eq('severity', filters.severity);
      }
      if (filters.resourceType) {
        query = query.eq('resource_type', filters.resourceType);
      }
      if (filters.startDate) {
        query = query.gte('created_at', filters.startDate);
      }
      if (filters.endDate) {
        query = query.lte('created_at', filters.endDate);
      }
      if (filters.success !== undefined) {
        query = query.eq('success', filters.success);
      }

      // Apply ordering and limiting
      query = query.order('created_at', { ascending: false });
      
      if (filters.limit) {
        query = query.limit(filters.limit);
      }

      const { data, error } = await query;

      if (error) {
        throw error;
      }

      return { success: true, data };
    } catch (error) {
      console.error('Failed to retrieve audit logs:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Get audit statistics
   */
  async getStatistics(timeframe = '24h') {
    try {
      const startDate = this._getStartDate(timeframe);
      
      const { data, error } = await supabase
        .from(this.tableName)
        .select('event_type, severity, success')
        .gte('created_at', startDate);

      if (error) {
        throw error;
      }

      const stats = {
        total: data.length,
        byEventType: {},
        bySeverity: {},
        successRate: 0,
        failureCount: 0
      };

      let successCount = 0;

      data.forEach(log => {
        // Count by event type
        stats.byEventType[log.event_type] = (stats.byEventType[log.event_type] || 0) + 1;
        
        // Count by severity
        stats.bySeverity[log.severity] = (stats.bySeverity[log.severity] || 0) + 1;
        
        // Count success/failure
        if (log.success) {
          successCount++;
        } else {
          stats.failureCount++;
        }
      });

      stats.successRate = stats.total > 0 ? (successCount / stats.total) * 100 : 0;

      return { success: true, data: stats };
    } catch (error) {
      console.error('Failed to get audit statistics:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Clean up old audit logs
   */
  async cleanup(retentionDays = 90) {
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

      const { data, error } = await supabase
        .from(this.tableName)
        .delete()
        .lt('created_at', cutoffDate.toISOString());

      if (error) {
        throw error;
      }

      return { success: true, deletedCount: data?.length || 0 };
    } catch (error) {
      console.error('Failed to cleanup audit logs:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Helper method to get start date for timeframe
   */
  _getStartDate(timeframe) {
    const now = new Date();
    
    switch (timeframe) {
      case '1h':
        return new Date(now.getTime() - 60 * 60 * 1000).toISOString();
      case '24h':
        return new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
      case '7d':
        return new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();
      case '30d':
        return new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();
      default:
        return new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
    }
  }
}

// Create singleton instance
const auditService = new AuditService();

module.exports = {
  auditService,
  AuditService,
  AUDIT_EVENTS,
  AUDIT_SEVERITY
};