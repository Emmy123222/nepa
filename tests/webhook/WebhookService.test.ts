import { WebhookService } from '../../services/WebhookService';
import { webhookSecurityService } from '../../services/WebhookSecurityService';
import { webhookQueueService } from '../../services/WebhookQueueService';
import prisma from '../../src/config/prismaClient';

// Mock dependencies
jest.mock('../../src/config/prismaClient');
jest.mock('../../services/logger');

const mockPrisma = prisma as jest.Mocked<typeof prisma>;

describe('WebhookService', () => {
  let webhookService: WebhookService;
  const testUserId = 'test-user-id';
  const testWebhookUrl = 'https://example.com/webhook';
  const testEvents = ['payment.success', 'bill.created'];

  beforeEach(() => {
    jest.clearAllMocks();
    webhookService = new WebhookService();
  });

  describe('registerWebhook', () => {
    it('should register a webhook successfully', async () => {
      const mockWebhook = {
        id: 'webhook-id',
        userId: testUserId,
        url: testWebhookUrl,
        events: testEvents,
        secret: 'test-secret',
        isActive: true,
        retryPolicy: 'EXPONENTIAL',
        maxRetries: 3,
        retryDelaySeconds: 60,
        timeoutSeconds: 30,
        headers: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      mockPrisma.webhook.create.mockResolvedValue(mockWebhook);
      mockPrisma.webhookLog.create.mockResolvedValue({} as any);

      const result = await webhookService.registerWebhook(testUserId, testWebhookUrl, testEvents);

      expect(result).toEqual(mockWebhook);
      expect(mockPrisma.webhook.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          userId: testUserId,
          url: testWebhookUrl,
          events: testEvents,
          secret: expect.any(String),
          retryPolicy: 'EXPONENTIAL',
          maxRetries: 3,
          retryDelaySeconds: 60,
          timeoutSeconds: 30,
        }),
      });
    });

    it('should reject invalid URLs', async () => {
      await expect(
        webhookService.registerWebhook(testUserId, 'invalid-url', testEvents)
      ).rejects.toThrow('Invalid webhook URL');
    });

    it('should reject invalid event types', async () => {
      await expect(
        webhookService.registerWebhook(testUserId, testWebhookUrl, ['invalid.event'])
      ).rejects.toThrow('Invalid event type: invalid.event');
    });
  });

  describe('updateWebhook', () => {
    const webhookId = 'test-webhook-id';

    it('should update webhook successfully', async () => {
      const mockWebhook = {
        id: webhookId,
        url: 'https://updated-url.com',
        events: testEvents,
        isActive: false,
        updatedAt: new Date(),
      };

      mockPrisma.webhook.update.mockResolvedValue(mockWebhook);
      mockPrisma.webhookLog.create.mockResolvedValue({} as any);

      const result = await webhookService.updateWebhook(webhookId, {
        url: 'https://updated-url.com',
        isActive: false,
      });

      expect(result).toEqual(mockWebhook);
      expect(mockPrisma.webhook.update).toHaveBeenCalledWith({
        where: { id: webhookId },
        data: {
          url: 'https://updated-url.com',
          isActive: false,
        },
      });
    });

    it('should reject invalid URLs in update', async () => {
      await expect(
        webhookService.updateWebhook(webhookId, { url: 'invalid-url' })
      ).rejects.toThrow('Invalid webhook URL');
    });
  });

  describe('deleteWebhook', () => {
    it('should delete webhook successfully', async () => {
      const webhookId = 'test-webhook-id';
      mockPrisma.webhook.delete.mockResolvedValue({} as any);
      mockPrisma.webhookLog.create.mockResolvedValue({} as any);

      await webhookService.deleteWebhook(webhookId);

      expect(mockPrisma.webhook.delete).toHaveBeenCalledWith({
        where: { id: webhookId },
      });
    });
  });

  describe('getUserWebhooks', () => {
    it('should return user webhooks', async () => {
      const mockWebhooks = [
        {
          id: 'webhook-1',
          url: testWebhookUrl,
          events: testEvents,
          isActive: true,
          createdAt: new Date(),
        },
        {
          id: 'webhook-2',
          url: 'https://another-url.com',
          events: ['user.created'],
          isActive: false,
          createdAt: new Date(),
        },
      ];

      mockPrisma.webhook.findMany.mockResolvedValue(mockWebhooks as any);

      const result = await webhookService.getUserWebhooks(testUserId);

      expect(result).toEqual(mockWebhooks);
      expect(mockPrisma.webhook.findMany).toHaveBeenCalledWith({
        where: { userId: testUserId },
        orderBy: { createdAt: 'desc' },
      });
    });
  });

  describe('triggerWebhook', () => {
    it('should trigger webhook for matching events', async () => {
      const eventType = 'payment.success';
      const payload = { amount: 100, currency: 'USD' };

      const mockWebhooks = [
        {
          id: 'webhook-1',
          url: testWebhookUrl,
          events: [eventType],
          secret: 'test-secret',
          isActive: true,
          retryPolicy: 'EXPONENTIAL',
          maxRetries: 3,
          retryDelaySeconds: 60,
          timeoutSeconds: 30,
          headers: null,
        },
      ];

      mockPrisma.webhook.findMany.mockResolvedValue(mockWebhooks as any);
      mockPrisma.webhookEvent.create.mockResolvedValue({} as any);
      mockPrisma.webhookAttempt.create.mockResolvedValue({} as any);
      mockPrisma.webhookEvent.update.mockResolvedValue({} as any);

      await webhookService.triggerWebhook(eventType, payload);

      expect(mockPrisma.webhook.findMany).toHaveBeenCalledWith({
        where: {
          isActive: true,
          events: {
            has: eventType,
          },
        },
      });
    });

    it('should not trigger webhooks for non-matching events', async () => {
      const eventType = 'payment.success';
      const payload = { amount: 100 };

      mockPrisma.webhook.findMany.mockResolvedValue([]);

      await webhookService.triggerWebhook(eventType, payload);

      expect(mockPrisma.webhookEvent.create).not.toHaveBeenCalled();
    });
  });

  describe('testWebhook', () => {
    const webhookId = 'test-webhook-id';

    it('should test webhook successfully', async () => {
      const mockWebhook = {
        id: webhookId,
        url: testWebhookUrl,
        secret: 'test-secret',
        timeoutSeconds: 30,
        headers: null,
      };

      mockPrisma.webhook.findUnique.mockResolvedValue(mockWebhook as any);
      mockPrisma.webhookLog.create.mockResolvedValue({} as any);

      // Mock successful fetch
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        status: 200,
        text: jest.fn().mockResolvedValue('Success'),
      });

      const result = await webhookService.testWebhook(webhookId);

      expect(result.success).toBe(true);
      expect(result.statusCode).toBe(200);
      expect(result.responseTime).toBeGreaterThan(0);
    });

    it('should handle webhook test failure', async () => {
      const mockWebhook = {
        id: webhookId,
        url: testWebhookUrl,
        secret: 'test-secret',
        timeoutSeconds: 30,
        headers: null,
      };

      mockPrisma.webhook.findUnique.mockResolvedValue(mockWebhook as any);
      mockPrisma.webhookLog.create.mockResolvedValue({} as any);

      // Mock failed fetch
      global.fetch = jest.fn().mockRejectedValue(new Error('Network error'));

      const result = await webhookService.testWebhook(webhookId);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Network error');
    });

    it('should throw error for non-existent webhook', async () => {
      mockPrisma.webhook.findUnique.mockResolvedValue(null);

      await expect(webhookService.testWebhook('non-existent')).rejects.toThrow('Webhook not found');
    });
  });

  describe('retryWebhookEvent', () => {
    const eventId = 'test-event-id';
    const webhookId = 'test-webhook-id';

    it('should retry failed webhook event', async () => {
      const mockEvent = {
        id: eventId,
        webhookId,
        payload: { test: true },
      };

      const mockWebhook = {
        id: webhookId,
        secret: 'test-secret',
      };

      mockPrisma.webhookEvent.findUnique.mockResolvedValue(mockEvent as any);
      mockPrisma.webhook.findUnique.mockResolvedValue(mockWebhook as any);
      mockPrisma.webhookEvent.update.mockResolvedValue({} as any);
      mockPrisma.webhookAttempt.create.mockResolvedValue({} as any);
      mockPrisma.webhookEvent.update.mockResolvedValue({} as any);

      await webhookService.retryWebhookEvent(eventId);

      expect(mockPrisma.webhookEvent.update).toHaveBeenCalledWith({
        where: { id: eventId },
        data: {
          status: 'PENDING',
          attempts: 0,
        },
      });
    });

    it('should throw error for non-existent event', async () => {
      mockPrisma.webhookEvent.findUnique.mockResolvedValue(null);

      await expect(webhookService.retryWebhookEvent('non-existent')).rejects.toThrow('Event not found');
    });
  });

  describe('getWebhookStats', () => {
    const webhookId = 'test-webhook-id';

    it('should return webhook statistics', async () => {
      const mockEvents = [
        {
          status: 'DELIVERED',
          deliveryAttempts: [{ duration: 100 }, { duration: 200 }],
        },
        {
          status: 'FAILED',
          deliveryAttempts: [{ duration: 150 }],
        },
        {
          status: 'PENDING',
          deliveryAttempts: [],
        },
      ];

      mockPrisma.webhookEvent.findMany.mockResolvedValue(mockEvents as any);

      const stats = await webhookService.getWebhookStats(webhookId);

      expect(stats).toEqual({
        totalEvents: 3,
        successfulDeliveries: 1,
        failedDeliveries: 1,
        pendingDeliveries: 1,
        successRate: 33.333333333333336,
        averageResponseTime: 150,
      });
    });

    it('should handle empty events', async () => {
      mockPrisma.webhookEvent.findMany.mockResolvedValue([]);

      const stats = await webhookService.getWebhookStats(webhookId);

      expect(stats).toEqual({
        totalEvents: 0,
        successfulDeliveries: 0,
        failedDeliveries: 0,
        pendingDeliveries: 0,
        successRate: 0,
        averageResponseTime: 0,
      });
    });
  });
});

describe('WebhookSecurityService', () => {
  describe('validateSignature', () => {
    it('should validate correct signature', () => {
      const payload = 'test payload';
      const secret = 'test-secret';
      const signature = webhookSecurityService.generateSignature(payload, secret);

      const result = webhookSecurityService.validateSignature(payload, signature, secret);

      expect(result).toBe(true);
    });

    it('should reject incorrect signature', () => {
      const payload = 'test payload';
      const secret = 'test-secret';
      const wrongSignature = 'wrong-signature';

      const result = webhookSecurityService.validateSignature(payload, wrongSignature, secret);

      expect(result).toBe(false);
    });
  });

  describe('validateWebhookURL', () => {
    it('should validate HTTPS URLs', () => {
      const config = { requireHTTPS: true };
      const result = webhookSecurityService.validateWebhookURL('https://example.com/webhook', config);

      expect(result.isValid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject HTTP URLs when HTTPS required', () => {
      const config = { requireHTTPS: true };
      const result = webhookSecurityService.validateWebhookURL('http://example.com/webhook', config);

      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('HTTPS is required for webhook URLs');
    });

    it('should reject localhost URLs', () => {
      const config = { requireHTTPS: true };
      const result = webhookSecurityService.validateWebhookURL('https://localhost/webhook', config);

      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Localhost URLs are not allowed in production');
    });

    it('should validate allowed domains', () => {
      const config = { allowedDomains: ['example.com', 'trusted.com'] };
      const result = webhookSecurityService.validateWebhookURL('https://api.example.com/webhook', config);

      expect(result.isValid).toBe(true);
    });

    it('should reject non-allowed domains', () => {
      const config = { allowedDomains: ['trusted.com'] };
      const result = webhookSecurityService.validateWebhookURL('https://evil.com/webhook', config);

      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Domain evil.com is not in the allowed list');
    });
  });

  describe('hashCredential and verifyCredential', () => {
    it('should hash and verify credentials correctly', async () => {
      const credential = 'test-credential';
      const hash = await webhookSecurityService.hashCredential(credential);

      expect(hash).not.toBe(credential);
      expect(hash).toMatch(/^[a-f0-9]{64}$/); // SHA-256 hash

      const isValid = await webhookSecurityService.verifyCredential(credential, hash);
      expect(isValid).toBe(true);
    });

    it('should reject incorrect credentials', async () => {
      const credential = 'test-credential';
      const wrongCredential = 'wrong-credential';
      const hash = await webhookSecurityService.hashCredential(credential);

      const isValid = await webhookSecurityService.verifyCredential(wrongCredential, hash);
      expect(isValid).toBe(false);
    });
  });
});

describe('WebhookQueueService', () => {
  let queueService: typeof webhookQueueService;

  beforeEach(() => {
    jest.clearAllMocks();
    queueService = webhookQueueService;
  });

  describe('addToQueue', () => {
    it('should add event to queue with priority', async () => {
      const webhookId = 'test-webhook-id';
      const eventType = 'payment.success';
      const payload = { amount: 100 };

      const mockWebhook = {
        id: webhookId,
        maxRetries: 3,
        retryDelaySeconds: 60,
        timeoutSeconds: 30,
        headers: null,
      };

      mockPrisma.webhook.findUnique.mockResolvedValue(mockWebhook as any);
      mockPrisma.webhookQueue.create.mockResolvedValue({
        id: 'queue-id',
        priority: 'HIGH',
      } as any);

      const eventId = await queueService.addToQueue(webhookId, eventType, payload, {
        priority: 'HIGH',
      });

      expect(eventId).toBe('queue-id');
      expect(mockPrisma.webhookQueue.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          webhookId,
          eventType,
          payload,
          priority: 'HIGH',
          status: 'QUEUED',
        }),
      });
    });

    it('should throw error for non-existent webhook', async () => {
      mockPrisma.webhook.findUnique.mockResolvedValue(null);

      await expect(
        queueService.addToQueue('non-existent', 'test.event', {})
      ).rejects.toThrow('Webhook not found: non-existent');
    });
  });

  describe('getQueueMetrics', () => {
    it('should return queue metrics', async () => {
      const mockQueuedEvents = [
        { status: 'QUEUED', priority: 'HIGH' },
        { status: 'QUEUED', priority: 'NORMAL' },
        { status: 'PROCESSING' },
        { status: 'FAILED' },
      ];

      mockPrisma.webhookQueue.groupBy.mockResolvedValue([
        { status: 'QUEUED', priority: 'HIGH', _count: 1 },
        { status: 'QUEUED', priority: 'NORMAL', _count: 1 },
        { status: 'PROCESSING', _count: 1 },
        { status: 'FAILED', _count: 1 },
      ]);

      mockPrisma.webhookQueue.findMany.mockResolvedValue(mockQueuedEvents as any);

      const metrics = await queueService.getQueueMetrics();

      expect(metrics).toEqual({
        totalQueued: 2,
        pendingByPriority: {
          HIGH: 1,
          NORMAL: 1,
        },
        processingCount: 1,
        failedCount: 1,
        averageProcessingTime: 0,
        throughputPerMinute: 0,
      });
    });
  });

  describe('retryEvent', () => {
    it('should retry failed event', async () => {
      const eventId = 'test-event-id';
      const mockEvent = {
        id: eventId,
        status: 'FAILED',
      };

      mockPrisma.webhookQueue.findUnique.mockResolvedValue(mockEvent as any);
      mockPrisma.webhookQueue.update.mockResolvedValue({} as any);

      await queueService.retryEvent(eventId);

      expect(mockPrisma.webhookQueue.update).toHaveBeenCalledWith({
        where: { id: eventId },
        data: {
          status: 'QUEUED',
          attempts: 0,
          lastError: null,
          scheduledFor: expect.any(Date),
        },
      });
    });

    it('should throw error for non-existent event', async () => {
      mockPrisma.webhookQueue.findUnique.mockResolvedValue(null);

      await expect(queueService.retryEvent('non-existent')).rejects.toThrow('Event not found');
    });
  });

  describe('cancelEvent', () => {
    it('should cancel queued event', async () => {
      const eventId = 'test-event-id';

      mockPrisma.webhookQueue.update.mockResolvedValue({} as any);

      await queueService.cancelEvent(eventId);

      expect(mockPrisma.webhookQueue.update).toHaveBeenCalledWith({
        where: { id: eventId },
        data: {
          status: 'CANCELLED',
          completedAt: expect.any(Date),
        },
      });
    });
  });
});
