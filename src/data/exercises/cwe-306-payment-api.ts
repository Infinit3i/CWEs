import type { Exercise } from '@/data/exercises'

/**
 * CWE-306: Missing Authentication for Payment Processing API
 * Enterprise scenario: Financial transaction endpoint without proper authentication
 */
export const cwe306PaymentApi: Exercise = {
  cweId: 'CWE-306',
  name: 'Missing Authentication - Payment Processing',

  vulnerableFunction: `class PaymentController {
  async processPayment(req: Request, res: Response) {
    const { fromAccount, toAccount, amount, description } = req.body;

    // Validate request parameters
    if (!fromAccount || !toAccount || !amount) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    if (amount <= 0 || amount > 10000) {
      return res.status(400).json({ error: 'Invalid amount' });
    }

    // Execute the transfer
    const transaction = await PaymentService.transfer({
      fromAccount,
      toAccount,
      amount,
      description: description || 'API Transfer',
      processedAt: new Date()
    });

    await NotificationService.sendTransferConfirmation(transaction);

    res.status(200).json({
      transactionId: transaction.id,
      status: 'completed',
      amount,
      message: 'Payment processed successfully'
    });
  }
}`,

  vulnerableLine: `async processPayment(req: Request, res: Response) {`,

  options: [
    {
      code: `async processPayment(req: Request, res: Response) { const user = await this.authenticateUser(req); if (!user || !this.canInitiateTransfer(user, req.body.fromAccount)) { return res.status(403).json({ error: 'Unauthorized transfer' }); }`,
      correct: true,
      explanation: `Correct! Payment processing requires strong authentication to verify user identity and authorization to verify the user owns the source account. Financial transactions without authentication enable unauthorized money transfers.`
    },
    {
      code: `async processPayment(req: Request, res: Response) {`,
      correct: false,
      explanation: 'From MITRE: Missing authentication in financial operations allows anyone to initiate transfers. This is similar to the bank account creation example where sensitive operations lack authority verification.'
    },
    {
      code: `async processPayment(req: Request, res: Response) { if (!req.body.accountPin) { return res.status(400).json({ error: 'Account PIN required' }); }`,
      correct: false,
      explanation: 'Requiring a PIN without validation provides no authentication. Any value in the accountPin field would satisfy this check while providing no security.'
    },
    {
      code: `async processPayment(req: Request, res: Response) { const sessionId = req.headers['x-session-id']; if (!sessionId) { return res.status(401).json({ error: 'Session ID required' }); }`,
      correct: false,
      explanation: 'Checking for session ID presence without validation is meaningless. Any string value would satisfy this requirement without verifying user authentication.'
    },
    {
      code: `async processPayment(req: Request, res: Response) { if (req.body.amount > 1000 && !req.headers.authorization) { return res.status(401).json({ error: 'Authorization required for large amounts' }); }`,
      correct: false,
      explanation: 'Conditional authentication based on amount is insufficient. Even small unauthorized transfers are harmful, and header presence without validation provides no security.'
    },
    {
      code: `async processPayment(req: Request, res: Response) { const userAgent = req.headers['user-agent']; if (!userAgent || !userAgent.includes('MobileBank')) { return res.status(403).json({ error: 'Invalid client application' }); }`,
      correct: false,
      explanation: 'User-Agent filtering is not authentication. Headers can be easily spoofed, and this provides no verification of user identity or account ownership.'
    },
    {
      code: `async processPayment(req: Request, res: Response) { const timestamp = req.body.timestamp; if (!timestamp || Math.abs(Date.now() - timestamp) > 300000) { return res.status(400).json({ error: 'Request expired' }); }`,
      correct: false,
      explanation: 'Timestamp validation prevents replay attacks but provides no authentication. Anyone can include a current timestamp and still process unauthorized transfers.'
    },
    {
      code: `async processPayment(req: Request, res: Response) { if (req.ip !== '10.0.0.100') { return res.status(403).json({ error: 'Access denied from this IP' }); }`,
      correct: false,
      explanation: 'IP-based access control is not user authentication. This only restricts location but provides no verification of user identity or authorization for specific accounts.'
    }
  ]
}