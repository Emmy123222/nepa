import { Request, Response } from 'express';
import { BillingService } from '../BillingService';
import { paymentLimiter, transactionLimiter } from '../middleware/rateLimiter';
import { conditionalCaptcha } from '../middleware/captcha';
import { abuseDetector } from '../middleware/abuseDetection';

const billingService = new BillingService();

// Apply rate limiting and security to all payment routes
export const applyPaymentSecurity = [
  abuseDetector,
  paymentLimiter,
  transactionLimiter,
  conditionalCaptcha
];

/**
 * @openapi
 * /api/payment/process:
 *   post:
 *     summary: Process a payment
 *     security:
 *       - ApiKeyAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               billId:
 *                 type: string
 *               amount:
 *                 type: number
 *               paymentMethod:
 *                 type: string
 *                 enum: [BANK_TRANSFER, CREDIT_CARD, CRYPTO]
 *               recaptchaToken:
 *                 type: string
 *     responses:
 *       200:
 *         description: Payment processed successfully
 *       429:
 *         description: Rate limit exceeded
 *       400:
 *         description: Invalid payment data
 */
export const processPayment = async (req: Request, res: Response) => {
  try {
    const { billId, amount, paymentMethod } = req.body;
    const userId = (req as any).user?.id;
    
    if (!userId) {
      return res.status(401).json({
        status: 401,
        error: 'User authentication required'
      });
    }
    
    // Validate payment data
    if (!billId || !amount || !paymentMethod) {
      return res.status(400).json({
        status: 400,
        error: 'Missing required payment fields'
      });
    }
    
    if (amount <= 0) {
      return res.status(400).json({
        status: 400,
        error: 'Payment amount must be greater than 0'
      });
    }
    
    // Process payment (integrate with actual payment processor)
    const paymentResult = await billingService.processPayment({
      billId,
      userId,
      amount,
      paymentMethod,
      timestamp: new Date()
    });
    
    res.status(200).json({
      status: 200,
      message: 'Payment processed successfully',
      data: paymentResult
    });
    
  } catch (error) {
    console.error('Payment processing error:', error);
    res.status(500).json({
      status: 500,
      error: 'Payment processing failed'
    });
  }
};

/**
 * @openapi
 * /api/payment/history:
 *   get:
 *     summary: Get payment history for a user
 *     security:
 *       - ApiKeyAuth: []
 *     parameters:
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 10
 *       - in: query
 *         name: offset
 *         schema:
 *           type: integer
 *           default: 0
 *     responses:
 *       200:
 *         description: Payment history retrieved successfully
 */
export const getPaymentHistory = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.id;
    const limit = parseInt(req.query.limit as string) || 10;
    const offset = parseInt(req.query.offset as string) || 0;
    
    if (!userId) {
      return res.status(401).json({
        status: 401,
        error: 'User authentication required'
      });
    }
    
    const paymentHistory = await billingService.getPaymentHistory(userId, limit, offset);
    
    res.status(200).json({
      status: 200,
      data: paymentHistory
    });
    
  } catch (error) {
    console.error('Payment history error:', error);
    res.status(500).json({
      status: 500,
      error: 'Failed to retrieve payment history'
    });
  }
};

/**
 * @openapi
 * /api/payment/validate:
 *   post:
 *     summary: Validate payment data before processing
 *     security:
 *       - ApiKeyAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               billId:
 *                 type: string
 *               amount:
 *                 type: number
 *     responses:
 *       200:
 *         description: Payment data is valid
 */
export const validatePayment = async (req: Request, res: Response) => {
  try {
    const { billId, amount } = req.body;
    const userId = (req as any).user?.id;
    
    if (!userId) {
      return res.status(401).json({
        status: 401,
        error: 'User authentication required'
      });
    }
    
    // Validate bill exists and belongs to user
    const bill = await billingService.getBill(billId);
    if (!bill || bill.userId !== userId) {
      return res.status(404).json({
        status: 404,
        error: 'Bill not found or access denied'
      });
    }
    
    // Validate amount
    if (amount <= 0 || amount > Number(bill.amount) + Number(bill.lateFee || 0)) {
      return res.status(400).json({
        status: 400,
        error: 'Invalid payment amount'
      });
    }
    
    res.status(200).json({
      status: 200,
      message: 'Payment data is valid',
      data: {
        billAmount: bill.amount,
        lateFee: bill.lateFee,
        totalDue: Number(bill.amount) + Number(bill.lateFee || 0)
      }
    });
    
  } catch (error) {
    console.error('Payment validation error:', error);
    res.status(500).json({
      status: 500,
      error: 'Payment validation failed'
    });
  }
};
