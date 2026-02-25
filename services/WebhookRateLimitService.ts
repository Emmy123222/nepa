import { logger } from './logger';
import prisma from '../src/config/prismaClient';

export interface RateLimitConfig {
  requestsPerMinute?: number;
  requestsPerHour?: number;
  requestsPerDay?: number;
  burstCapacity?: number;
  webhookSpecificLimits?: Record<string, {
    requestsPerMinute?: number;
    requestsPerHour?: number;
    requestsPerDay?: number;
  }>;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetTime: Date;
  retryAfter?: number;
  limitType?: 'minute' | 'hour' | 'day';
}

export interface ThrottleConfig {
  maxConcurrent?: number;
  queueSize?: number;
  processingDelay?: number;
  priorityQueue?: boolean;
}

class WebhookRateLimitService {
  private rateLimitStore: Map<string, {
    minute: { count: number; resetTime: number };
    hour: { count: number; resetTime: number };
    day: { count: number; resetTime: number };
  }> = new Map();

  private concurrentProcessing: Map<string, number> = new Map();
  private throttleQueues: Map<string, Array<{
    id: string;
    webhookId: string;
    priority: number;
    timestamp: number;
    resolve: () => void;
    reject: (error: Error) => void;
  }>> = new Map();

  private defaultConfig: RateLimitConfig = {
    requestsPerMinute: 60,
    requestsPerHour: 1000,
    requestsPerDay: 10000,
    burstCapacity: 10,
  };

  private defaultThrottleConfig: ThrottleConfig = {
    maxConcurrent: 5,
    queueSize: 100,
    processingDelay: 100,
    priorityQueue: true,
  };

  /**
   * Check rate limit for a webhook
   */
  checkRateLimit(webhookId: string, config?: RateLimitConfig): RateLimitResult {
    const finalConfig = { ...this.defaultConfig, ...config };
    const now = Date.now();
    
    // Get or create rate limit entry
    let entry = this.rateLimitStore.get(webhookId);
    if (!entry) {
      entry = {
        minute: { count: 0, resetTime: now + 60 * 1000 },
        hour: { count: 0, resetTime: now + 60 * 60 * 1000 },
        day: { count: 0, resetTime: now + 24 * 60 * 60 * 1000 },
      };
      this.rateLimitStore.set(webhookId, entry);
    }

    // Reset expired counters
    if (now >= entry.minute.resetTime) {
      entry.minute = { count: 0, resetTime: now + 60 * 1000 };
    }
    if (now >= entry.hour.resetTime) {
      entry.hour = { count: 0, resetTime: now + 60 * 60 * 1000 };
    }
    if (now >= entry.day.resetTime) {
      entry.day = { count: 0, resetTime: now + 24 * 60 * 60 * 1000 };
    }

    // Check webhook-specific limits
    const webhookLimits = finalConfig.webhookSpecificLimits?.[webhookId];
    if (webhookLimits) {
      if (webhookLimits.requestsPerMinute && entry.minute.count >= webhookLimits.requestsPerMinute) {
        return {
          allowed: false,
          remaining: 0,
          resetTime: new Date(entry.minute.resetTime),
          retryAfter: Math.ceil((entry.minute.resetTime - now) / 1000),
          limitType: 'minute',
        };
      }
      if (webhookLimits.requestsPerHour && entry.hour.count >= webhookLimits.requestsPerHour) {
        return {
          allowed: false,
          remaining: 0,
          resetTime: new Date(entry.hour.resetTime),
          retryAfter: Math.ceil((entry.hour.resetTime - now) / 1000),
          limitType: 'hour',
        };
      }
      if (webhookLimits.requestsPerDay && entry.day.count >= webhookLimits.requestsPerDay) {
        return {
          allowed: false,
          remaining: 0,
          resetTime: new Date(entry.day.resetTime),
          retryAfter: Math.ceil((entry.day.resetTime - now) / 1000),
          limitType: 'day',
        };
      }
    }

    // Check global limits
    if (finalConfig.requestsPerMinute && entry.minute.count >= finalConfig.requestsPerMinute) {
      return {
        allowed: false,
        remaining: 0,
        resetTime: new Date(entry.minute.resetTime),
        retryAfter: Math.ceil((entry.minute.resetTime - now) / 1000),
        limitType: 'minute',
      };
    }

    if (finalConfig.requestsPerHour && entry.hour.count >= finalConfig.requestsPerHour) {
      return {
        allowed: false,
        remaining: 0,
        resetTime: new Date(entry.hour.resetTime),
        retryAfter: Math.ceil((entry.hour.resetTime - now) / 1000),
        limitType: 'hour',
      };
    }

    if (finalConfig.requestsPerDay && entry.day.count >= finalConfig.requestsPerDay) {
      return {
        allowed: false,
        remaining: 0,
        resetTime: new Date(entry.day.resetTime),
        retryAfter: Math.ceil((entry.day.resetTime - now) / 1000),
        limitType: 'day',
      };
    }

    // Increment counters
    entry.minute.count++;
    entry.hour.count++;
    entry.day.count++;

    // Calculate remaining requests
    const minuteRemaining = (finalConfig.requestsPerMinute || 60) - entry.minute.count;
    const hourRemaining = (finalConfig.requestsPerHour || 1000) - entry.hour.count;
    const dayRemaining = (finalConfig.requestsPerDay || 10000) - entry.day.count;

    return {
      allowed: true,
      remaining: Math.min(minuteRemaining, hourRemaining, dayRemaining),
      resetTime: new Date(entry.minute.resetTime),
    };
  }

  /**
   * Acquire processing slot (throttling)
   */
  async acquireProcessingSlot(
    webhookId: string,
    priority: number = 0,
    config?: ThrottleConfig
  ): Promise<void> {
    const finalConfig = { ...this.defaultThrottleConfig, ...config };
    const maxConcurrent = finalConfig.maxConcurrent || 5;

    // Get current concurrent count
    const current = this.concurrentProcessing.get(webhookId) || 0;

    if (current < maxConcurrent) {
      // Slot available, increment counter
      this.concurrentProcessing.set(webhookId, current + 1);
      return;
    }

    // No slot available, add to queue
    return new Promise((resolve, reject) => {
      const queue = this.throttleQueues.get(webhookId) || [];
      
      // Check queue size limit
      if (queue.length >= (finalConfig.queueSize || 100)) {
        reject(new Error('Throttle queue is full'));
        return;
      }

      const queueItem = {
        id: Math.random().toString(36).substr(2, 9),
        webhookId,
        priority,
        timestamp: Date.now(),
        resolve,
        reject,
      };

      queue.push(queueItem);

      // Sort by priority (higher priority first)
      if (finalConfig.priorityQueue) {
        queue.sort((a, b) => b.priority - a.priority);
      }

      this.throttleQueues.set(webhookId, queue);
    });
  }

  /**
   * Release processing slot
   */
  releaseProcessingSlot(webhookId: string): void {
    const current = this.concurrentProcessing.get(webhookId) || 0;
    this.concurrentProcessing.set(webhookId, Math.max(0, current - 1));

    // Process next item in queue
    this.processQueue(webhookId);
  }

  /**
   * Process throttle queue
   */
  private processQueue(webhookId: string): void {
    const queue = this.throttleQueues.get(webhookId);
    if (!queue || queue.length === 0) {
      return;
    }

    const current = this.concurrentProcessing.get(webhookId) || 0;
    const maxConcurrent = this.defaultThrottleConfig.maxConcurrent || 5;

    if (current >= maxConcurrent) {
      return; // Still at capacity
    }

    // Get next item from queue
    const nextItem = queue.shift();
    if (nextItem) {
      this.throttleQueues.set(webhookId, queue);
      this.concurrentProcessing.set(webhookId, current + 1);

      // Resolve the promise
      nextItem.resolve();
    }
  }

  /**
   * Get rate limit status for webhook
   */
  getRateLimitStatus(webhookId: string): {
    minute: { used: number; limit: number; remaining: number; resetTime: Date };
    hour: { used: number; limit: number; remaining: number; resetTime: Date };
    day: { used: number; limit: number; remaining: number; resetTime: Date };
  } | null {
    const entry = this.rateLimitStore.get(webhookId);
    if (!entry) {
      return null;
    }

    const now = Date.now();
    const config = this.defaultConfig;

    return {
      minute: {
        used: entry.minute.count,
        limit: config.requestsPerMinute || 60,
        remaining: Math.max(0, (config.requestsPerMinute || 60) - entry.minute.count),
        resetTime: new Date(entry.minute.resetTime),
      },
      hour: {
        used: entry.hour.count,
        limit: config.requestsPerHour || 1000,
        remaining: Math.max(0, (config.requestsPerHour || 1000) - entry.hour.count),
        resetTime: new Date(entry.hour.resetTime),
      },
      day: {
        used: entry.day.count,
        limit: config.requestsPerDay || 10000,
        remaining: Math.max(0, (config.requestsPerDay || 10000) - entry.day.count),
        resetTime: new Date(entry.day.resetTime),
      },
    };
  }

  /**
   * Get throttle status for webhook
   */
  getThrottleStatus(webhookId: string): {
    concurrent: number;
    maxConcurrent: number;
    queued: number;
    maxQueueSize: number;
  } {
    const concurrent = this.concurrentProcessing.get(webhookId) || 0;
    const queue = this.throttleQueues.get(webhookId) || [];

    return {
      concurrent,
      maxConcurrent: this.defaultThrottleConfig.maxConcurrent || 5,
      queued: queue.length,
      maxQueueSize: this.defaultThrottleConfig.queueSize || 100,
    };
  }

  /**
   * Reset rate limits for webhook (admin function)
   */
  resetRateLimits(webhookId: string): void {
    this.rateLimitStore.delete(webhookId);
    logger.info(`Rate limits reset for webhook: ${webhookId}`);
  }

  /**
   * Clear throttle queue for webhook (admin function)
   */
  clearThrottleQueue(webhookId: string): void {
    const queue = this.throttleQueues.get(webhookId);
    if (queue) {
      // Reject all pending items
      queue.forEach(item => {
        item.reject(new Error('Throttle queue cleared'));
      });
      this.throttleQueues.delete(webhookId);
      logger.info(`Throttle queue cleared for webhook: ${webhookId}`);
    }
  }

  /**
   * Get global rate limit metrics
   */
  getGlobalMetrics(): {
    totalWebhooks: number;
    activeWebhooks: number;
    totalRequestsPerMinute: number;
    totalRequestsPerHour: number;
    totalRequestsPerDay: number;
    averageQueueLength: number;
    totalQueuedItems: number;
  } {
    let totalMinute = 0;
    let totalHour = 0;
    let totalDay = 0;
    let totalQueued = 0;
    let activeCount = 0;

    this.rateLimitStore.forEach((entry, webhookId) => {
      totalMinute += entry.minute.count;
      totalHour += entry.hour.count;
      totalDay += entry.day.count;
      activeCount++;
    });

    this.throttleQueues.forEach(queue => {
      totalQueued += queue.length;
    });

    return {
      totalWebhooks: activeCount,
      activeWebhooks: activeCount,
      totalRequestsPerMinute: totalMinute,
      totalRequestsPerHour: totalHour,
      totalRequestsPerDay: totalDay,
      averageQueueLength: activeCount > 0 ? totalQueued / activeCount : 0,
      totalQueuedItems: totalQueued,
    };
  }

  /**
   * Cleanup expired entries
   */
  cleanup(): void {
    const now = Date.now();
    const toDelete: string[] = [];

    this.rateLimitStore.forEach((entry, webhookId) => {
      if (now >= entry.day.resetTime) {
        toDelete.push(webhookId);
      }
    });

    toDelete.forEach(webhookId => {
      this.rateLimitStore.delete(webhookId);
      this.throttleQueues.delete(webhookId);
      this.concurrentProcessing.delete(webhookId);
    });

    if (toDelete.length > 0) {
      logger.info(`Cleaned up ${toDelete.length} expired webhook rate limit entries`);
    }
  }

  /**
   * Configure rate limits for webhook
   */
  async configureWebhookRateLimits(
    webhookId: string,
    config: RateLimitConfig
  ): Promise<void> {
    try {
      await prisma.webhook.update({
        where: { id: webhookId },
        data: {
          rateLimitConfig: config as any,
        },
      });

      logger.info(`Rate limits configured for webhook: ${webhookId}`);
    } catch (error) {
      logger.error(`Failed to configure webhook rate limits: ${error}`);
      throw error;
    }
  }

  /**
   * Get webhook rate limit configuration
   */
  async getWebhookRateLimitConfig(webhookId: string): Promise<RateLimitConfig | null> {
    try {
      const webhook = await prisma.webhook.findUnique({
        where: { id: webhookId },
        select: { rateLimitConfig: true },
      });

      return webhook?.rateLimitConfig as RateLimitConfig || null;
    } catch (error) {
      logger.error(`Failed to get webhook rate limit config: ${error}`);
      return null;
    }
  }
}

// Start cleanup interval
const webhookRateLimitService = new WebhookRateLimitService();
setInterval(() => {
  webhookRateLimitService.cleanup();
}, 60 * 60 * 1000); // Cleanup every hour

export { webhookRateLimitService };
