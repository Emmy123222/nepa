import express from 'express';
import swaggerUi from 'swagger-ui-express';
import { apiLimiter, ddosDetector, checkBlockedIP, ipRestriction, progressiveLimiter, authLimiter } from './middleware/rateLimiter';
import { configureSecurity } from './middleware/security';
import { apiKeyAuth } from './middleware/auth';
import { requestLogger } from './middleware/logger';
import { errorTracker } from './middleware/abuseDetection';
import { swaggerSpec } from './swagger';
import { upload } from './middleware/upload';
import { uploadDocument } from './controllers/DocumentController';
import { getDashboardData, generateReport, exportData } from './controllers/AnalyticsController';
import { applyPaymentSecurity, processPayment, getPaymentHistory, validatePayment } from './controllers/PaymentController';

const app = express();

// 1. Logging (should be first to capture all requests)
app.use(requestLogger);

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

// 6. General API Rate Limiting
app.use('/api', apiLimiter);

// 7. Error tracking for abuse detection
app.use(errorTracker);

// 8. API Documentation
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// 9. Public Routes
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'UP' });
});

// 10. Protected API Routes
app.use('/api', apiKeyAuth);

// Authentication endpoints with stricter rate limiting
app.post('/api/auth/login', authLimiter, (req, res) => {
  // Login logic here
  res.json({ message: 'Login endpoint' });
});

app.post('/api/auth/register', authLimiter, (req, res) => {
  // Registration logic here
  res.json({ message: 'Register endpoint' });
});

// Payment endpoints with enhanced security
app.post('/api/payment/process', ...applyPaymentSecurity, processPayment);
app.get('/api/payment/history', apiKeyAuth, getPaymentHistory);
app.post('/api/payment/validate', ...applyPaymentSecurity, validatePayment);

// Example protected route
/**
 * @openapi
 * /api/test:
 *   get:
 *     summary: Test protected route
 *     security:
 *       - ApiKeyAuth: []
 *     responses:
 *       200:
 *         description: Success
 */
app.get('/api/test', (req, res) => {
  res.json({ message: 'Authenticated access successful' });
});

// Document Upload Route
/**
 * @openapi
 * /api/documents/upload:
 *   post:
 *     summary: Upload a document
 *     security:
 *       - ApiKeyAuth: []
 *     requestBody:
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               file:
 *                 type: string
 *                 format: binary
 *               userId:
 *                 type: string
 *     responses:
 *       201:
 *         description: Document uploaded successfully
 */
app.post('/api/documents/upload', apiKeyAuth, upload.single('file'), uploadDocument);

// Analytics Routes
/**
 * @openapi
 * /api/analytics/dashboard:
 *   get:
 *     summary: Get analytics dashboard data
 *     security:
 *       - ApiKeyAuth: []
 *     responses:
 *       200:
 *         description: Dashboard data retrieved
 */
app.get('/api/analytics/dashboard', apiKeyAuth, getDashboardData);

/**
 * @openapi
 * /api/analytics/reports:
 *   post:
 *     summary: Generate and save a custom report
 *     security:
 *       - ApiKeyAuth: []
 *     responses:
 *       201:
 *         description: Report created
 */
app.post('/api/analytics/reports', apiKeyAuth, generateReport);

// Export Route
app.get('/api/analytics/export', apiKeyAuth, exportData);

export default app;