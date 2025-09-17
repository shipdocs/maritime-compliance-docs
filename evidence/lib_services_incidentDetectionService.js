/**
 * Incident Detection Service
 * Detects incidents from audit logs, errors, and performance metrics
 * Classifies incidents and prepares them for external integration
 */

const { supabase } = require('../supabase');
const { v4: uuidv4 } = require('uuid');

// Incident severity levels
const SEVERITY_LEVELS = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low'
};

// Incident types
const INCIDENT_TYPES = {
  SECURITY: {
    AUTHENTICATION_FAILURE: 'security.authentication_failure',
    BRUTE_FORCE: 'security.brute_force',
    SUSPICIOUS_ACCESS: 'security.suspicious_access',
    DATA_BREACH: 'security.data_breach',
    UNAUTHORIZED_ACCESS: 'security.unauthorized_access'
  },
  OPERATIONAL: {
    APPLICATION_ERROR: 'operational.application_error',
    PERFORMANCE_DEGRADATION: 'operational.performance',
    DATABASE_FAILURE: 'operational.database',
    SERVICE_OUTAGE: 'operational.service_outage',
    CAPACITY_ISSUE: 'operational.capacity'
  },
  MARITIME: {
    TRAINING_DISRUPTION: 'maritime.training_disruption',
    COMPLIANCE_VIOLATION: 'maritime.compliance_violation',
    CERTIFICATE_FAILURE: 'maritime.certificate_failure',
    COMMUNICATION_LOSS: 'maritime.communication_loss'
  }
};

// Detection rules configuration
const DETECTION_RULES = {
  // Security incident rules
  authentication_failure: {
    trigger: 'audit_log.action = "login_failed"',
    threshold: 5,
    window: 300000, // 5 minutes
    severity: SEVERITY_LEVELS.HIGH,
    type: INCIDENT_TYPES.SECURITY.AUTHENTICATION_FAILURE
  },

  brute_force_attack: {
    trigger: 'audit_log.action = "login_failed"',
    threshold: 10,
    window: 600000, // 10 minutes
    groupBy: 'ip_address',
    severity: SEVERITY_LEVELS.CRITICAL,
    type: INCIDENT_TYPES.SECURITY.BRUTE_FORCE
  },

  // Operational incident rules
  application_error: {
    trigger: 'error_level = "error"',
    threshold: 10,
    window: 300000, // 5 minutes
    severity: SEVERITY_LEVELS.HIGH,
    type: INCIDENT_TYPES.OPERATIONAL.APPLICATION_ERROR
  },

  performance_degradation: {
    trigger: 'response_time > 5000',
    threshold: 5,
    window: 120000, // 2 minutes
    severity: SEVERITY_LEVELS.MEDIUM,
    type: INCIDENT_TYPES.OPERATIONAL.PERFORMANCE_DEGRADATION
  }
};

class IncidentDetectionService {
  constructor() {
    this.isEnabled = process.env.INCIDENT_DETECTION_ENABLED !== 'false';
    this.recentIncidents = new Map(); // Cache for deduplication
  }

  /**
   * Detect incident from audit log event
   */
  async detectFromAuditLog(auditEvent) {
    if (!this.isEnabled) return null;

    try {
      // Check for authentication failures
      if (auditEvent.action === 'login_failed') {
        return await this.checkAuthenticationFailures(auditEvent);
      }

      // Check for suspicious access patterns
      if (auditEvent.action.includes('access') && auditEvent.severity_level === 'high') {
        return await this.checkSuspiciousAccess(auditEvent);
      }

      return null;
    } catch (error) {
      console.error('Error detecting incident from audit log:', error);
      return null;
    }
  }

  /**
   * Detect incident from error event
   */
  async detectFromError(errorEvent) {
    if (!this.isEnabled) return null;

    try {
      // Check for application errors
      if (errorEvent.level === 'error') {
        return await this.checkApplicationErrors(errorEvent);
      }

      // Check for database connection failures
      if (errorEvent.message && errorEvent.message.toLowerCase().includes('database')) {
        return await this.createIncident({
          type: INCIDENT_TYPES.OPERATIONAL.DATABASE_FAILURE,
          severity: SEVERITY_LEVELS.CRITICAL,
          title: 'Database Connection Failure',
          description: `Database error detected: ${errorEvent.message}`,
          sourceSystem: 'error_handler',
          sourceEventId: errorEvent.id,
          metadata: errorEvent
        });
      }

      return null;
    } catch (error) {
      console.error('Error detecting incident from error:', error);
      return null;
    }
  }

  /**
   * Detect incident from performance metrics
   */
  async detectFromPerformance(perfMetric) {
    if (!this.isEnabled) return null;

    try {
      // Check for performance degradation
      if (perfMetric.name === 'api_response_time' && perfMetric.value > 5000) {
        return await this.checkPerformanceDegradation(perfMetric);
      }

      // Check for high error rates
      if (perfMetric.name === 'error_rate' && perfMetric.value > 10) {
        return await this.createIncident({
          type: INCIDENT_TYPES.OPERATIONAL.APPLICATION_ERROR,
          severity: SEVERITY_LEVELS.HIGH,
          title: 'High Error Rate Detected',
          description: `Error rate exceeded threshold: ${perfMetric.value}%`,
          sourceSystem: 'performance_monitor',
          sourceEventId: perfMetric.id,
          metadata: perfMetric
        });
      }

      return null;
    } catch (error) {
      console.error('Error detecting incident from performance metric:', error);
      return null;
    }
  }

  /**
   * Check for authentication failure patterns
   */
  async checkAuthenticationFailures(auditEvent) {
    const rule = DETECTION_RULES.authentication_failure;
    const windowStart = new Date(Date.now() - rule.window);

    // Count recent failed login attempts from same IP
    const { data: recentFailures, error } = await supabase
      .from('audit_log')
      .select('id')
      .eq('action', 'login_failed')
      .eq('ip_address', auditEvent.ip_address)
      .gte('created_at', windowStart.toISOString());

    if (error) {
      console.error('Error checking authentication failures:', error);
      return null;
    }

    if (recentFailures.length >= rule.threshold) {
      // Check for brute force pattern
      if (recentFailures.length >= DETECTION_RULES.brute_force_attack.threshold) {
        return await this.createIncident({
          type: INCIDENT_TYPES.SECURITY.BRUTE_FORCE,
          severity: SEVERITY_LEVELS.CRITICAL,
          title: 'Brute Force Attack Detected',
          description: `${recentFailures.length} failed login attempts from IP ${auditEvent.ip_address} in ${rule.window / 60000} minutes`,
          sourceSystem: 'audit_log',
          sourceEventId: auditEvent.id,
          affectedSystems: ['authentication'],
          metadata: {
            ip_address: auditEvent.ip_address,
            attempt_count: recentFailures.length,
            time_window: rule.window
          }
        });
      }

      // Regular authentication failure incident
      return await this.createIncident({
        type: INCIDENT_TYPES.SECURITY.AUTHENTICATION_FAILURE,
        severity: SEVERITY_LEVELS.HIGH,
        title: 'Multiple Authentication Failures',
        description: `${recentFailures.length} failed login attempts from IP ${auditEvent.ip_address}`,
        sourceSystem: 'audit_log',
        sourceEventId: auditEvent.id,
        affectedSystems: ['authentication'],
        metadata: {
          ip_address: auditEvent.ip_address,
          attempt_count: recentFailures.length
        }
      });
    }

    return null;
  }

  /**
   * Check for suspicious access patterns
   */
  async checkSuspiciousAccess(auditEvent) {
    return await this.createIncident({
      type: INCIDENT_TYPES.SECURITY.SUSPICIOUS_ACCESS,
      severity: SEVERITY_LEVELS.MEDIUM,
      title: 'Suspicious Access Pattern Detected',
      description: `Unusual access pattern detected for user ${auditEvent.user_email}`,
      sourceSystem: 'audit_log',
      sourceEventId: auditEvent.id,
      affectedUsers: [auditEvent.user_email],
      metadata: auditEvent
    });
  }

  /**
   * Check for application error patterns
   */
  async checkApplicationErrors(errorEvent) {
    const rule = DETECTION_RULES.application_error;
    const windowStart = new Date(Date.now() - rule.window);

    // Count recent errors
    const { data: recentErrors, error } = await supabase
      .from('audit_log')
      .select('id')
      .ilike('action', '%error%')
      .gte('created_at', windowStart.toISOString());

    if (error) {
      console.error('Error checking application errors:', error);
      return null;
    }

    if (recentErrors.length >= rule.threshold) {
      return await this.createIncident({
        type: INCIDENT_TYPES.OPERATIONAL.APPLICATION_ERROR,
        severity: SEVERITY_LEVELS.HIGH,
        title: 'High Application Error Rate',
        description: `${recentErrors.length} application errors in ${rule.window / 60000} minutes`,
        sourceSystem: 'error_handler',
        sourceEventId: errorEvent.id,
        affectedSystems: ['application'],
        metadata: {
          error_count: recentErrors.length,
          time_window: rule.window,
          latest_error: errorEvent
        }
      });
    }

    return null;
  }

  /**
   * Check for performance degradation patterns
   */
  async checkPerformanceDegradation(perfMetric) {
    const rule = DETECTION_RULES.performance_degradation;

    return await this.createIncident({
      type: INCIDENT_TYPES.OPERATIONAL.PERFORMANCE_DEGRADATION,
      severity: SEVERITY_LEVELS.MEDIUM,
      title: 'Performance Degradation Detected',
      description: `API response time exceeded threshold: ${perfMetric.value}ms`,
      sourceSystem: 'performance_monitor',
      sourceEventId: perfMetric.id,
      affectedSystems: ['api'],
      metadata: perfMetric
    });
  }

  /**
   * Create a new incident
   */
  async createIncident({
    type,
    severity,
    title,
    description,
    sourceSystem,
    sourceEventId,
    affectedUsers = [],
    affectedSystems = [],
    metadata = {}
  }) {
    try {
      const incidentId = this.generateIncidentId();

      // Check for duplicate incidents (deduplication)
      const deduplicationKey = `${type}-${sourceSystem}-${JSON.stringify(metadata)}`;
      if (this.recentIncidents.has(deduplicationKey)) {
        return null; // Skip duplicate
      }

      const incidentData = {
        incident_id: incidentId,
        type,
        severity,
        title,
        description,
        source_system: sourceSystem,
        source_event_id: sourceEventId,
        affected_users: affectedUsers,
        affected_systems: affectedSystems,
        metadata,
        status: 'detected'
      };

      const { data: incident, error } = await supabase
        .from('incidents')
        .insert([incidentData])
        .select()
        .single();

      if (error) {
        console.error('Error creating incident:', error);
        return null;
      }

      // Cache for deduplication (expire after 5 minutes)
      this.recentIncidents.set(deduplicationKey, Date.now());
      setTimeout(() => {
        this.recentIncidents.delete(deduplicationKey);
      }, 300000);

      console.log(`Incident detected: ${incidentId} - ${title}`);
      return incident;

    } catch (error) {
      console.error('Error creating incident:', error);
      return null;
    }
  }

  /**
   * Generate unique incident ID
   */
  generateIncidentId() {
    const date = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    const random = Math.random().toString(36).substring(2, 8).toUpperCase();
    return `INC-${date}-${random}`;
  }

  /**
   * Get incident statistics
   */
  async getIncidentStats(timeRange = '24h') {
    try {
      const hours = timeRange === '24h' ? 24 : timeRange === '7d' ? 168 : 1;
      const since = new Date(Date.now() - hours * 60 * 60 * 1000);

      const { data: incidents, error } = await supabase
        .from('incidents')
        .select('severity, type, status')
        .gte('detection_time', since.toISOString());

      if (error) throw error;

      const stats = {
        total: incidents.length,
        by_severity: {},
        by_type: {},
        by_status: {}
      };

      incidents.forEach(incident => {
        stats.by_severity[incident.severity] = (stats.by_severity[incident.severity] || 0) + 1;
        stats.by_type[incident.type] = (stats.by_type[incident.type] || 0) + 1;
        stats.by_status[incident.status] = (stats.by_status[incident.status] || 0) + 1;
      });

      return stats;
    } catch (error) {
      console.error('Error getting incident stats:', error);
      return null;
    }
  }
}

// Export singleton instance
const incidentDetectionService = new IncidentDetectionService();

module.exports = {
  incidentDetectionService,
  SEVERITY_LEVELS,
  INCIDENT_TYPES
};
