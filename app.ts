import express from 'express';
import swaggerUi from 'swagger-ui-express';
import { apiLimiter, ddosDetector, checkBlockedIP, ipRestriction, progressiveLimiter } from './middleware/rateLimiter';
import { configureSecurity } from './middleware/security';
import { apiKeyAuth } from './middleware/auth';
import { loggingMiddleware, setupGlobalErrorHandling, errorTracker } from './middleware/logger';
import { errorTracker as abuseDetector } from './middleware/abuseDetection';
import { swaggerSpec } from './swagger';
import { upload } from './middleware/upload';
import { uploadDocument } from './controllers/DocumentController';
import { getDashboardData, generateReport, exportData } from './controllers/AnalyticsController';
import { applyPaymentSecurity, processPayment, getPaymentHistory, validatePayment } from './controllers/PaymentController';
import { setupRateLimitRoutes } from './routes/rateLimitRoutes';
import { initializeCacheSystem } from './services/cache/CacheInitializer';
import { cacheHealthMiddleware, apiCacheMiddleware, cacheInvalidationMiddleware } from './middleware/cacheMiddleware';
import cacheRoutes from './routes/cacheRoutes';
import { logger } from './services/logger';

// Mock services for now - replace with actual implementations
const performanceMonitor = {
  getHealthStatus: () => ({ status: 'healthy' }),
  getMemoryUsage: () => ({ heapUsed: 0, heapTotal: 0, external: 0 }),
  getRequestMetrics: (limit: number) => [],
  getCustomMetrics: (limit: number) => []
};

const analyticsService = {
  getAnalyticsData: () => ({ userEvents: [], activeUsers: 0 })
};

const app = express();

// Initialize cache system on startup
initializeCacheSystem().then(result => {
  if (result.success) {
    logger.info('Cache system initialized successfully', {
      initializationTime: result.metrics.initializationTime,
      services: result.services
    });
  } else {
    logger.error('Cache system initialization failed', {
      errors: result.errors,
      warnings: result.warnings
    });
  }
}).catch(error => {
  logger.error('Cache system initialization error:', error);
});

// Initialize logging and monitoring
logger.info('Application starting up', { 
  nodeEnv: process.env.NODE_ENV,
  version: process.env.npm_package_version 
});

// Initialize error tracking if DSN is provided
if (process.env.SENTRY_DSN) {
  errorTracker.initialize({
    dsn: process.env.SENTRY_DSN,
    environment: process.env.NODE_ENV || 'development',
    tracesSampleRate: parseFloat(process.env.SENTRY_TRACES_SAMPLE_RATE || '0.1'),
    release: process.env.npm_package_version
  });
}

// 1. Comprehensive logging middleware (should be first)
app.use(...loggingMiddleware);

// 2. DDoS Protection and IP Blocking
app.use(ddosDetector);
app.use(checkBlockedIP);
app.use(ipRestriction);

// 3. Security Headers & CORS
configureSecurity(app);

// 4. Body Parsing
app.use(express.json({ limit: '10kb' })); // Limit body size for security

// 5. Progressive Rate Limiting
app.use('/api', progressiveLimiter);

// 6. Advanced Rate Limiting (replaces basic rate limiting)
app.use('/api', advancedRateLimiter);

// 7. Error tracking for abuse detection
app.use(abuseDetector);

// 8. Setup rate limiting routes
setupRateLimitRoutes(app);

// 9. Cache health check middleware
app.use(cacheHealthMiddleware());

// 10. API Documentation
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
app.use('/api-docs/v1', swaggerUi.serve, swaggerUi.setup(getVersionedSwaggerSpec('v1')));
app.use('/api-docs/v2', swaggerUi.serve, swaggerUi.setup(getVersionedSwaggerSpec('v2')));

// 11. Enhanced Health Check
app.get('/health', (req, res) => {
  const healthStatus = performanceMonitor.getHealthStatus();
  const memoryUsage = performanceMonitor.getMemoryUsage();
  
  res.status(200).json({
    status: 'UP',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    performance: healthStatus,
    memory: {
      used: memoryUsage.heapUsed,
      total: memoryUsage.heapTotal,
      external: memoryUsage.external
    },
    analytics: {
      totalEvents: analyticsService.getAnalyticsData().userEvents.length,
      activeUsers: analyticsService.getAnalyticsData().activeUsers
    }
  });
});

// 10. Monitoring endpoints (unversioned)
app.get('/api/monitoring/metrics', apiKeyAuth, (req, res) => {
  const analytics = analyticsService.getAnalyticsData();
  const performance = performanceMonitor.getHealthStatus();

  res.json({
    analytics,
    performance,
    requestMetrics: performanceMonitor.getRequestMetrics(100),
    customMetrics: performanceMonitor.getCustomMetrics(100)
  });
});

// 11. API version discovery (no auth required for discovery)
app.get('/api/versions', (_req, res) => {
  res.json({
    defaultVersion: apiVersioningConfig.defaultVersion,
    latestVersion: apiVersioningConfig.latestVersion,
    supportedVersions: apiVersioningConfig.supportedVersions,
    lifecycle: apiVersioningConfig.lifecycle,
  });
});

// 12. Versioned API routes (version from path or header X-API-Version / Accept / query)
app.use('/api', apiVersionMiddleware, versionUsageAnalyticsMiddleware);
app.use('/api/v1', setApiVersion('v1'), createV1Router());
app.use('/api/v2', setApiVersion('v2'), createV2Router());
app.use('/api', setApiVersion('v2'), createV2Router()); // default unversioned /api/* -> v2

export default app;
// Cache Management Routes (Admin only)
app.use('/api/cache', cacheRoutes);

// Add cache middleware to existing routes for better performance
// Note: These would be added to existing route definitions in a real implementation

export default app;