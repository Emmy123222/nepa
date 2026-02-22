# Rate Limiting and DDoS Protection Implementation

## Overview

This implementation provides comprehensive protection against rate limiting abuse, DDoS attacks, and other security vulnerabilities for the NEPA application.

## Security Features Implemented

### 1. Multi-Layer Rate Limiting

#### General API Rate Limiting (`apiLimiter`)
- **Window**: 15 minutes
- **Limit**: 100 requests per IP
- **Storage**: Redis-based for distributed environments
- **Features**: Standard headers, skip health checks

#### Payment-Specific Rate Limiting (`paymentLimiter`)
- **Window**: 5 minutes
- **Limit**: 5 payment requests per IP
- **Key Generation**: IP + User ID for granular control
- **Purpose**: Protect payment endpoints from abuse

#### Transaction Frequency Limiting (`transactionLimiter`)
- **Window**: 1 hour
- **Limit**: 20 transactions per IP/user
- **Purpose**: Prevent transaction spam and financial abuse

#### Authentication Rate Limiting (`authLimiter`)
- **Window**: 15 minutes
- **Limit**: 10 auth attempts per IP
- **Features**: Skip successful requests to reduce false positives

#### Progressive Rate Limiting (`progressiveLimiter`)
- **Dynamic Limits**: Adjusts based on suspicious activity
- **Normal Requests**: 30 requests per minute
- **Suspicious Requests**: 5 requests per minute

### 2. DDoS Detection and Prevention

#### Real-time Monitoring (`ddosDetector`)
- **Threshold**: 100+ requests per minute triggers blocking
- **Automatic Blocking**: 5-minute temporary IP blocks
- **Logging**: Comprehensive logging of potential attacks

#### IP-Based Restrictions (`ipRestriction`)
- **Blocked IP List**: Configurable blocked IPs
- **User Agent Analysis**: Flags suspicious/missing user agents
- **Pattern Recognition**: Identifies bot-like behavior

#### IP Blocking System (`checkBlockedIP`)
- **Temporary Blocks**: 5-minute blocks for suspicious activity
- **Redis Storage**: Fast lookup and distributed blocking
- **Automatic Cleanup**: Expired blocks automatically removed

### 3. CAPTCHA Protection

#### Conditional CAPTCHA (`conditionalCaptcha`)
- **Triggers**: Suspicious activity, payment endpoints, invalid user agents
- **Integration**: Google reCAPTCHA v2/v3 support
- **Score-Based**: v3 uses risk scoring (0.5 threshold)

#### Mandatory CAPTCHA (`verifyRecaptcha`)
- **Payment Endpoints**: Always required for payment processing
- **High-Risk Operations**: Applied to sensitive operations
- **Error Handling**: Graceful degradation when service unavailable

### 4. Abuse Detection and Monitoring

#### Pattern Analysis (`abuseDetector`)
- **Request Frequency**: High-frequency request detection
- **User Agent Analysis**: Bot and crawler detection
- **Time-Based Patterns**: Unusual activity hours detection
- **Endpoint Targeting**: Monitoring sensitive endpoint access

#### Error Tracking (`errorTracker`)
- **Authentication Errors**: Failed login attempt tracking
- **Validation Errors**: Invalid request pattern detection
- **Error Frequency**: High error rate indicators

#### Alert System (`abuseAlerter`)
- **Threshold Alerts**: 100+ suspicious activities trigger alerts
- **Alert Storage**: Last 100 alerts maintained
- **Monitoring Integration**: Ready for external monitoring services

### 5. Enhanced Payment Security

#### Payment Controller (`PaymentController.ts`)
- **Multi-Layer Security**: All rate limiters applied
- **Input Validation**: Comprehensive payment data validation
- **User Authentication**: Required for all payment operations
- **Error Handling**: Secure error responses

#### Payment Endpoints
- `POST /api/payment/process` - Process payments with full security
- `GET /api/payment/history` - Retrieve payment history
- `POST /api/payment/validate` - Validate payment data before processing

## Configuration

### Environment Variables

```bash
# Redis Configuration
REDIS_URL=redis://localhost:6379

# reCAPTCHA Configuration
RECAPTCHA_SECRET_KEY=your_secret_key
RECAPTCHA_SITE_KEY=your_site_key

# Security Configuration
BLOCKED_IPS=192.168.1.100,10.0.0.50
CORS_ORIGIN=http://localhost:3000

# Rate Limiting Configuration
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
PAYMENT_RATE_LIMIT_MAX=5
TRANSACTION_RATE_LIMIT_MAX=20
```

### Rate Limiting Tiers

| Tier | Window | Limit | Use Case |
|------|--------|-------|----------|
| General API | 15 min | 100/IP | Normal API usage |
| Payment | 5 min | 5/IP | Payment processing |
| Transaction | 1 hour | 20/IP | Transaction frequency |
| Auth | 15 min | 10/IP | Authentication attempts |
| Progressive | 1 min | 5-30/IP | Dynamic based on suspicion |

## Installation and Setup

### 1. Install Dependencies
```bash
npm install express-rate-limit rate-limit-redis ioredis helmet cors
```

### 2. Configure Redis
```bash
# Start Redis server
redis-server

# Or use Docker
docker run -d -p 6379:6379 redis:alpine
```

### 3. Set Up reCAPTCHA
1. Register at Google reCAPTCHA console
2. Get site key and secret key
3. Add to environment variables

### 4. Update Environment
```bash
cp .env.example .env
# Edit .env with your configuration
```

## Monitoring and Maintenance

### Metrics Available
- Request counts per IP/user
- Error rates and types
- Suspicious activity patterns
- CAPTCHA verification results
- IP blocking statistics

### Alert Configuration
- High suspicious activity thresholds
- Custom webhook integration
- Email alert support
- Monitoring service integration

### Log Analysis
- Structured logging for security events
- IP-based request patterns
- Time-based activity analysis
- Error correlation and trending

## Testing

### Load Testing
```bash
# Install artillery
npm install -g artillery

# Run load test
artillery run load-test-config.yml
```

### Security Testing
- Test rate limiting boundaries
- Verify CAPTCHA functionality
- Test IP blocking behavior
- Validate abuse detection patterns

## Performance Considerations

### Redis Optimization
- Use Redis Cluster for high availability
- Configure appropriate memory limits
- Monitor Redis performance metrics
- Implement connection pooling

### Rate Limiting Optimization
- Adjust windows and limits based on traffic
- Monitor false positive rates
- Implement progressive limiting
- Use sliding windows for accuracy

## Future Enhancements

### Advanced Features
- Machine learning-based abuse detection
- Geographic IP blocking
- Device fingerprinting
- Behavioral analysis
- Real-time threat intelligence integration

### Monitoring Integration
- Prometheus metrics
- Grafana dashboards
- ELK stack integration
- Custom alerting rules

## Security Best Practices

### Regular Maintenance
- Review and update rate limits
- Monitor blocked IP patterns
- Update CAPTCHA configuration
- Review abuse detection rules

### Incident Response
- Document security incidents
- Analyze attack patterns
- Update protection mechanisms
- Communicate with stakeholders

## Conclusion

This implementation provides comprehensive protection against rate limiting abuse and DDoS attacks while maintaining good user experience for legitimate users. The multi-layered approach ensures that different types of attacks are detected and mitigated at various levels of the application stack.

The system is designed to be:
- **Scalable**: Redis-based distributed rate limiting
- **Configurable**: Environment-based configuration
- **Monitorable**: Comprehensive logging and metrics
- **Maintainable**: Modular architecture with clear separation of concerns
- **Extensible**: Easy to add new security measures and monitoring capabilities
