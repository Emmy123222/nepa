import { EventEmitter } from 'events';
import { logger } from './logger';
import { webhookMonitor } from './WebhookMonitor';
import { webhookRateLimitService } from './WebhookRateLimitService';
import prisma from '../src/config/prismaClient';

export interface AlertRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  conditions: {
    metric: string;
    operator: 'gt' | 'lt' | 'eq' | 'gte' | 'lte';
    threshold: number;
    timeWindow?: number; // in minutes
  }[];
  actions: {
    type: 'email' | 'webhook' | 'slack' | 'webhook_internal';
    config: any;
  }[];
  cooldown: number; // in minutes
  severity: 'low' | 'medium' | 'high' | 'critical';
  webhookId?: string;
  createdBy: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface Alert {
  id: string;
  ruleId: string;
  ruleName: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  details: any;
  status: 'active' | 'resolved' | 'acknowledged';
  triggeredAt: Date;
  resolvedAt?: Date;
  acknowledgedAt?: Date;
  acknowledgedBy?: string;
  webhookId?: string;
}

export interface AlertNotification {
  alertId: string;
  type: 'email' | 'webhook' | 'slack' | 'webhook_internal';
  recipient: string;
  status: 'pending' | 'sent' | 'failed';
  sentAt?: Date;
  error?: string;
  retryCount: number;
}

class WebhookAlertingService extends EventEmitter {
  private alertRules: Map<string, AlertRule> = new Map();
  private activeAlerts: Map<string, Alert> = new Map();
  private alertHistory: Alert[] = [];
  private notificationQueue: AlertNotification[] = [];
  private isProcessing = false;

  constructor() {
    super();
    this.startMonitoring();
    this.startNotificationProcessor();
  }

  /**
   * Start monitoring for alerts
   */
  private startMonitoring(): void {
    // Check metrics every minute
    setInterval(async () => {
      await this.checkAlertConditions();
    }, 60 * 1000);

    logger.info('Webhook alerting service started');
  }

  /**
   * Start notification processor
   */
  private startNotificationProcessor(): void {
    setInterval(async () => {
      if (!this.isProcessing && this.notificationQueue.length > 0) {
        await this.processNotifications();
      }
    }, 5000);
  }

  /**
   * Create alert rule
   */
  async createAlertRule(rule: Omit<AlertRule, 'id' | 'createdAt' | 'updatedAt'>): Promise<AlertRule> {
    try {
      const newRule: AlertRule = {
        ...rule,
        id: Math.random().toString(36).substr(2, 9),
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      this.alertRules.set(newRule.id, newRule);

      // Save to database
      await prisma.alertRule.create({
        data: {
          id: newRule.id,
          name: newRule.name,
          description: newRule.description,
          enabled: newRule.enabled,
          conditions: newRule.conditions as any,
          actions: newRule.actions as any,
          cooldown: newRule.cooldown,
          severity: newRule.severity,
          webhookId: newRule.webhookId,
          createdBy: newRule.createdBy,
        },
      });

      logger.info(`Alert rule created: ${newRule.name} (${newRule.id})`);
      this.emit('ruleCreated', newRule);

      return newRule;
    } catch (error) {
      logger.error(`Failed to create alert rule: ${error}`);
      throw error;
    }
  }

  /**
   * Update alert rule
   */
  async updateAlertRule(ruleId: string, updates: Partial<AlertRule>): Promise<AlertRule> {
    try {
      const existingRule = this.alertRules.get(ruleId);
      if (!existingRule) {
        throw new Error('Alert rule not found');
      }

      const updatedRule = {
        ...existingRule,
        ...updates,
        updatedAt: new Date(),
      };

      this.alertRules.set(ruleId, updatedRule);

      // Update in database
      await prisma.alertRule.update({
        where: { id: ruleId },
        data: {
          name: updatedRule.name,
          description: updatedRule.description,
          enabled: updatedRule.enabled,
          conditions: updatedRule.conditions as any,
          actions: updatedRule.actions as any,
          cooldown: updatedRule.cooldown,
          severity: updatedRule.severity,
        },
      });

      logger.info(`Alert rule updated: ${updatedRule.name} (${ruleId})`);
      this.emit('ruleUpdated', updatedRule);

      return updatedRule;
    } catch (error) {
      logger.error(`Failed to update alert rule: ${error}`);
      throw error;
    }
  }

  /**
   * Delete alert rule
   */
  async deleteAlertRule(ruleId: string): Promise<void> {
    try {
      this.alertRules.delete(ruleId);

      // Delete from database
      await prisma.alertRule.delete({
        where: { id: ruleId },
      });

      logger.info(`Alert rule deleted: ${ruleId}`);
      this.emit('ruleDeleted', ruleId);
    } catch (error) {
      logger.error(`Failed to delete alert rule: ${error}`);
      throw error;
    }
  }

  /**
   * Check alert conditions
   */
  private async checkAlertConditions(): Promise<void> {
    try {
      const rules: AlertRule[] = [];
      this.alertRules.forEach((rule) => {
        rules.push(rule);
      });
      
      for (const rule of rules) {
        if (!rule.enabled) continue;

        // Check cooldown
        const lastAlert = this.alertHistory
          .filter(alert => alert.ruleId === rule.id)
          .sort((a, b) => b.triggeredAt.getTime() - a.triggeredAt.getTime())[0];

        if (lastAlert && 
            Date.now() - lastAlert.triggeredAt.getTime() < rule.cooldown * 60 * 1000) {
          continue; // Still in cooldown period
        }

        // Evaluate conditions
        const shouldTrigger = await this.evaluateConditions(rule);
        if (shouldTrigger) {
          await this.triggerAlert(rule);
        }
      }
    } catch (error) {
      logger.error(`Error checking alert conditions: ${error}`);
    }
  }

  /**
   * Evaluate alert conditions
   */
  private async evaluateConditions(rule: AlertRule): Promise<boolean> {
    try {
      for (const condition of rule.conditions) {
        const value = await this.getMetricValue(condition.metric, rule.webhookId);
        if (value === null) continue;

        let conditionMet = false;
        switch (condition.operator) {
          case 'gt':
            conditionMet = value > condition.threshold;
            break;
          case 'gte':
            conditionMet = value >= condition.threshold;
            break;
          case 'lt':
            conditionMet = value < condition.threshold;
            break;
          case 'lte':
            conditionMet = value <= condition.threshold;
            break;
          case 'eq':
            conditionMet = value === condition.threshold;
            break;
        }

        if (!conditionMet) {
          return false; // All conditions must be met
        }
      }

      return true;
    } catch (error) {
      logger.error(`Error evaluating conditions for rule ${rule.name}: ${error}`);
      return false;
    }
  }

  /**
   * Get metric value
   */
  private async getMetricValue(metric: string, webhookId?: string): Promise<number | null> {
    try {
      switch (metric) {
        case 'failure_rate':
          const metrics = webhookId 
            ? await webhookMonitor.getWebhookStats(webhookId)
            : await webhookMonitor.getGlobalMetrics();
          return metrics.successRate > 0 ? 100 - metrics.successRate : 0;

        case 'success_rate':
          const successMetrics = webhookId 
            ? await webhookMonitor.getWebhookStats(webhookId)
            : await webhookMonitor.getGlobalMetrics();
          return successMetrics.successRate;

        case 'average_response_time':
          const responseMetrics = webhookId 
            ? await webhookMonitor.getWebhookStats(webhookId)
            : await webhookMonitor.getGlobalMetrics();
          return responseMetrics.averageResponseTime;

        case 'pending_deliveries':
          const pendingMetrics = webhookId 
            ? await webhookMonitor.getWebhookStats(webhookId)
            : await webhookMonitor.getGlobalMetrics();
          return pendingMetrics.pendingDeliveries;

        case 'queue_length':
          const queueStatus = webhookId 
            ? webhookRateLimitService.getThrottleStatus(webhookId)
            : webhookRateLimitService.getGlobalMetrics();
          return webhookId ? (queueStatus as any).queued : (queueStatus as any).totalQueuedItems;

        case 'concurrent_processing':
          const concurrentStatus = webhookId 
            ? webhookRateLimitService.getThrottleStatus(webhookId)
            : webhookRateLimitService.getGlobalMetrics();
          return webhookId ? (concurrentStatus as any).concurrent : 0;

        default:
          logger.warn(`Unknown metric: ${metric}`);
          return null;
      }
    } catch (error) {
      logger.error(`Error getting metric value for ${metric}: ${error}`);
      return null;
    }
  }

  /**
   * Trigger alert
   */
  private async triggerAlert(rule: AlertRule): Promise<void> {
    try {
      const alert: Alert = {
        id: Math.random().toString(36).substr(2, 9),
        ruleId: rule.id,
        ruleName: rule.name,
        severity: rule.severity,
        message: `Alert triggered: ${rule.name}`,
        details: {
          conditions: rule.conditions,
          webhookId: rule.webhookId,
        },
        status: 'active',
        triggeredAt: new Date(),
        webhookId: rule.webhookId,
      };

      this.activeAlerts.set(alert.id, alert);
      this.alertHistory.push(alert);

      // Keep only last 1000 alerts in memory
      if (this.alertHistory.length > 1000) {
        this.alertHistory = this.alertHistory.slice(-1000);
      }

      // Save to database
      await prisma.alert.create({
        data: {
          id: alert.id,
          ruleId: rule.id,
          ruleName: rule.name,
          severity: rule.severity,
          message: alert.message,
          details: alert.details as any,
          status: alert.status,
          triggeredAt: alert.triggeredAt,
          webhookId: rule.webhookId,
        },
      });

      logger.warn(`Alert triggered: ${rule.name} (${alert.id})`);
      this.emit('alertTriggered', alert);

      // Queue notifications
      for (const action of rule.actions) {
        this.notificationQueue.push({
          alertId: alert.id,
          type: action.type,
          recipient: action.config.recipient || action.config.url,
          status: 'pending',
          retryCount: 0,
        });
      }
    } catch (error) {
      logger.error(`Failed to trigger alert: ${error}`);
    }
  }

  /**
   * Process notifications
   */
  private async processNotifications(): Promise<void> {
    if (this.isProcessing) return;
    
    this.isProcessing = true;
    const notifications = this.notificationQueue.splice(0, 10); // Process in batches

    try {
      for (const notification of notifications) {
        try {
          await this.sendNotification(notification);
        } catch (error) {
          logger.error(`Failed to send notification: ${error}`);
          
          // Retry logic
          if (notification.retryCount < 3) {
            notification.retryCount++;
            this.notificationQueue.unshift(notification);
          } else {
            notification.status = 'failed';
            notification.error = error instanceof Error ? error.message : 'Unknown error';
          }
        }
      }
    } finally {
      this.isProcessing = false;
    }
  }

  /**
   * Send notification
   */
  private async sendNotification(notification: AlertNotification): Promise<void> {
    const alert = this.activeAlerts.get(notification.alertId);
    if (!alert) {
      throw new Error('Alert not found');
    }

    switch (notification.type) {
      case 'email':
        await this.sendEmailNotification(notification, alert);
        break;
      case 'webhook':
        await this.sendWebhookNotification(notification, alert);
        break;
      case 'slack':
        await this.sendSlackNotification(notification, alert);
        break;
      case 'webhook_internal':
        await this.sendInternalWebhookNotification(notification, alert);
        break;
      default:
        throw new Error(`Unknown notification type: ${notification.type}`);
    }

    notification.status = 'sent';
    notification.sentAt = new Date();
  }

  /**
   * Send email notification
   */
  private async sendEmailNotification(notification: AlertNotification, alert: Alert): Promise<void> {
    // Implementation would depend on your email service
    logger.info(`Email notification sent to ${notification.recipient} for alert ${alert.id}`);
  }

  /**
   * Send webhook notification
   */
  private async sendWebhookNotification(notification: AlertNotification, alert: Alert): Promise<void> {
    const payload = {
      alert: {
        id: alert.id,
        ruleName: alert.ruleName,
        severity: alert.severity,
        message: alert.message,
        details: alert.details,
        triggeredAt: alert.triggeredAt,
      },
    };

    const response = await fetch(notification.recipient, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Alert-ID': alert.id,
        'X-Alert-Severity': alert.severity,
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      throw new Error(`Webhook notification failed: ${response.status} ${response.statusText}`);
    }

    logger.info(`Webhook notification sent to ${notification.recipient} for alert ${alert.id}`);
  }

  /**
   * Send Slack notification
   */
  private async sendSlackNotification(notification: AlertNotification, alert: Alert): Promise<void> {
    const color = {
      low: 'good',
      medium: 'warning',
      high: 'danger',
      critical: 'danger',
    }[alert.severity];

    const payload = {
      attachments: [{
        color,
        title: `Webhook Alert: ${alert.ruleName}`,
        text: alert.message,
        fields: [
          { title: 'Severity', value: alert.severity, short: true },
          { title: 'Triggered At', value: alert.triggeredAt.toISOString(), short: true },
        ],
        footer: 'Webhook Alerting System',
        ts: Math.floor(alert.triggeredAt.getTime() / 1000),
      }],
    };

    const response = await fetch(notification.recipient, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      throw new Error(`Slack notification failed: ${response.status} ${response.statusText}`);
    }

    logger.info(`Slack notification sent for alert ${alert.id}`);
  }

  /**
   * Send internal webhook notification
   */
  private async sendInternalWebhookNotification(notification: AlertNotification, alert: Alert): Promise<void> {
    // Trigger internal webhook event
    this.emit('internalAlert', {
      alert,
      notification,
    });

    logger.info(`Internal webhook notification sent for alert ${alert.id}`);
  }

  /**
   * Acknowledge alert
   */
  async acknowledgeAlert(alertId: string, userId: string): Promise<void> {
    try {
      const alert = this.activeAlerts.get(alertId);
      if (!alert) {
        throw new Error('Alert not found');
      }

      alert.status = 'acknowledged';
      alert.acknowledgedAt = new Date();
      alert.acknowledgedBy = userId;

      // Update in database
      await prisma.alert.update({
        where: { id: alertId },
        data: {
          status: 'acknowledged',
          acknowledgedAt: alert.acknowledgedAt,
          acknowledgedBy: userId,
        },
      });

      logger.info(`Alert acknowledged: ${alertId} by ${userId}`);
      this.emit('alertAcknowledged', alert);
    } catch (error) {
      logger.error(`Failed to acknowledge alert: ${error}`);
      throw error;
    }
  }

  /**
   * Resolve alert
   */
  async resolveAlert(alertId: string): Promise<void> {
    try {
      const alert = this.activeAlerts.get(alertId);
      if (!alert) {
        throw new Error('Alert not found');
      }

      alert.status = 'resolved';
      alert.resolvedAt = new Date();

      // Update in database
      await prisma.alert.update({
        where: { id: alertId },
        data: {
          status: 'resolved',
          resolvedAt: alert.resolvedAt,
        },
      });

      this.activeAlerts.delete(alertId);
      logger.info(`Alert resolved: ${alertId}`);
      this.emit('alertResolved', alert);
    } catch (error) {
      logger.error(`Failed to resolve alert: ${error}`);
      throw error;
    }
  }

  /**
   * Get active alerts
   */
  getActiveAlerts(webhookId?: string): Alert[] {
    const alerts = Array.from(this.activeAlerts.values());
    
    if (webhookId) {
      return alerts.filter(alert => alert.webhookId === webhookId);
    }
    
    return alerts;
  }

  /**
   * Get alert history
   */
  getAlertHistory(limit: number = 100, webhookId?: string): Alert[] {
    let history = [...this.alertHistory]
      .sort((a, b) => b.triggeredAt.getTime() - a.triggeredAt.getTime())
      .slice(0, limit);

    if (webhookId) {
      history = history.filter(alert => alert.webhookId === webhookId);
    }

    return history;
  }

  /**
   * Get alert rules
   */
  getAlertRules(webhookId?: string): AlertRule[] {
    const rules = Array.from(this.alertRules.values());
    
    if (webhookId) {
      return rules.filter(rule => rule.webhookId === webhookId);
    }
    
    return rules;
  }

  /**
   * Get alerting metrics
   */
  getAlertingMetrics(): {
    totalRules: number;
    activeRules: number;
    activeAlerts: number;
    alertsBySeverity: Record<string, number>;
    recentAlerts: number;
    notificationQueueSize: number;
  } {
    const rules = Array.from(this.alertRules.values());
    const alerts = Array.from(this.activeAlerts.values());
    const recentAlerts = this.alertHistory.filter(
      alert => Date.now() - alert.triggeredAt.getTime() < 24 * 60 * 60 * 1000
    ).length;

    const alertsBySeverity = alerts.reduce((acc, alert) => {
      acc[alert.severity] = (acc[alert.severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return {
      totalRules: rules.length,
      activeRules: rules.filter(rule => rule.enabled).length,
      activeAlerts: alerts.length,
      alertsBySeverity,
      recentAlerts,
      notificationQueueSize: this.notificationQueue.length,
    };
  }
}

export const webhookAlertingService = new WebhookAlertingService();
