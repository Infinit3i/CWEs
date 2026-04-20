import type { Exercise } from '@/data/exercises'

/**
 * CWE-209: Information Exposure Through API Validation Errors
 * Scenario: REST API exposing business logic and validation details
 * Based on MITRE demonstrative examples showing validation error leakage
 */
export const cwe209ApiValidation: Exercise = {
  cweId: 'CWE-209',
  name: 'Information Exposure - API Validation Errors',

  vulnerableFunction: `app.post('/api/transfer-funds', authenticateUser, async (req, res) => {
  try {
    const { fromAccount, toAccount, amount, description } = req.body;
    
    // Validate source account
    const sourceAccount = await db.query(
      'SELECT id, user_id, balance, account_type, status FROM accounts WHERE id = ?',
      [fromAccount]
    );
    
    if (sourceAccount.length === 0) {
      return res.status(400).json({
        error: 'Source account validation failed',
        details: {
          providedAccountId: fromAccount,
          validAccountIds: await db.query('SELECT id FROM accounts WHERE user_id = ?', [req.user.id]),
          message: 'Account ID does not exist in accounts table',
          query: 'SELECT id, user_id, balance FROM accounts WHERE id = ?',
          suggestion: 'Use GET /api/accounts to list available accounts'
        }
      });
    }
    
    // Check account ownership
    if (sourceAccount[0].user_id !== req.user.id) {
      return res.status(403).json({
        error: 'Account ownership verification failed',
        details: {
          requestedAccount: fromAccount,
          actualOwner: sourceAccount[0].user_id,
          requestingUser: req.user.id,
          ownerEmail: await getUserEmail(sourceAccount[0].user_id),
          userRole: req.user.role,
          accountType: sourceAccount[0].account_type,
          message: 'User ID mismatch in accounts.user_id foreign key constraint'
        }
      });
    }
    
    // Validate destination account
    const destAccount = await db.query(
      'SELECT id, user_id, account_type, status FROM accounts WHERE id = ?',
      [toAccount]
    );
    
    if (destAccount.length === 0) {
      return res.status(400).json({
        error: 'Destination account validation failed',
        details: {
          providedAccountId: toAccount,
          searchQuery: 'SELECT * FROM accounts WHERE id = ?',
          totalAccounts: await db.query('SELECT COUNT(*) as count FROM accounts'),
          recentAccounts: await db.query('SELECT id, account_type FROM accounts ORDER BY created_at DESC LIMIT 10'),
          message: 'Destination account not found in database'
        }
      });
    }
    
    // Validate transfer amount
    const balance = sourceAccount[0].balance;
    if (amount > balance) {
      return res.status(400).json({
        error: 'Insufficient funds validation failed',
        details: {
          requestedAmount: amount,
          availableBalance: balance,
          accountId: fromAccount,
          shortfall: amount - balance,
          balanceQuery: 'SELECT balance FROM accounts WHERE id = ?',
          lastTransactions: await db.query(
            'SELECT amount, type, created_at FROM transactions WHERE account_id = ? ORDER BY created_at DESC LIMIT 5',
            [fromAccount]
          ),
          message: \`Balance check failed: \${amount} > \${balance}\`
        }
      });
    }
    
    // Business rule validation
    if (amount > 10000 && req.user.verification_level !== 'premium') {
      return res.status(403).json({
        error: 'Transfer limit validation failed',
        details: {
          requestedAmount: amount,
          userVerificationLevel: req.user.verification_level,
          requiredLevel: 'premium',
          currentLimits: {
            basic: 1000,
            standard: 5000,
            premium: 50000
          },
          upgradeProcess: 'Submit identity verification documents',
          businessRule: 'Large transfers require premium verification (see business_rules table)',
          message: 'Amount exceeds user tier limit in user_verification_levels configuration'
        }
      });
    }
    
    // Execute transfer
    const result = await executeTransfer(fromAccount, toAccount, amount, description);
    
    res.json({
      message: 'Transfer completed successfully',
      transactionId: result.id
    });
    
  } catch (error) {
    console.error('Transfer error:', error);
    res.status(500).json({
      error: 'Transfer processing failed',
      details: {
        message: error.message,
        stack: error.stack,
        code: error.code,
        sqlState: error.sqlState,
        query: error.sql,
        constraint: error.constraint
      },
      debugInfo: {
        timestamp: Date.now(),
        userId: req.user.id,
        requestBody: req.body,
        databaseHost: process.env.DB_HOST,
        environment: process.env.NODE_ENV
      }
    });
  }
});`,

  vulnerableLine: `return res.status(400).json({`,

  options: [
    {
      code: `// Log detailed validation errors securely, return generic messages
const errorId = crypto.randomUUID();

if (sourceAccount.length === 0) {
  console.error('Transfer validation error:', {
    errorId,
    type: 'INVALID_SOURCE_ACCOUNT',
    userId: req.user.id,
    providedAccountId: fromAccount,
    timestamp: new Date().toISOString()
  });
  
  return res.status(400).json({
    error: 'Invalid transfer request',
    errorId: errorId,
    message: 'Please verify your account details and try again'
  });
}`,
      correct: true,
      explanation: `Correct! This prevents information exposure by logging detailed validation errors securely on the server while returning only generic error messages to the client. The error ID allows developers to correlate user reports with server logs without exposing sensitive business logic, database schema, account ownership details, or system configuration that attackers could use to understand the application's internal workings and plan targeted attacks.`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `return res.status(400).json({
  error: 'Source account validation failed',
  details: {
    providedAccountId: fromAccount,
    validAccountIds: await db.query('SELECT id FROM accounts WHERE user_id = ?', [req.user.id]),
    message: 'Account ID does not exist in accounts table',
    query: 'SELECT id, user_id, balance FROM accounts WHERE id = ?'
  }
});`,
      correct: false,
      explanation: 'Direct from MITRE CWE-209: Detailed validation errors expose database schema, table structures, query patterns, and valid account IDs. Attackers can use this information to understand the data model and enumerate valid accounts for targeted attacks.'
    },
    {
      code: `return res.status(403).json({
  error: 'Account ownership verification failed',
  details: {
    actualOwner: sourceAccount[0].user_id,
    requestingUser: req.user.id,
    ownerEmail: await getUserEmail(sourceAccount[0].user_id),
    accountType: sourceAccount[0].account_type,
    message: 'User ID mismatch in foreign key constraint'
  }
});`,
      correct: false,
      explanation: 'Account ownership errors from MITRE examples expose sensitive user information including other users\' IDs, email addresses, and account relationships. This enables account enumeration and privacy violations.'
    },
    {
      code: `return res.status(400).json({
  error: 'Insufficient funds',
  details: {
    requestedAmount: amount,
    availableBalance: balance,
    shortfall: amount - balance,
    lastTransactions: await db.query('SELECT amount, type FROM transactions WHERE account_id = ? LIMIT 5', [fromAccount])
  }
});`,
      correct: false,
      explanation: 'Balance and transaction details expose sensitive financial information including account balances and transaction history that should be protected from unauthorized disclosure, even during validation errors.'
    },
    {
      code: `return res.status(403).json({
  error: 'Transfer limit exceeded',
  userLevel: req.user.verification_level,
  limits: { basic: 1000, standard: 5000, premium: 50000 },
  businessRule: 'Large transfers require premium verification'
});`,
      correct: false,
      explanation: 'Business rule exposure reveals internal application logic including verification levels, transfer limits, and business processes that can help attackers understand system capabilities and potential attack vectors.'
    },
    {
      code: `const errorType = sourceAccount.length === 0 ? 'ACCOUNT_NOT_FOUND' : 'VALIDATION_FAILED';
return res.status(400).json({
  error: 'Transfer failed',
  code: errorType,
  timestamp: Date.now()
});`,
      correct: false,
      explanation: 'Specific error codes still provide information about internal validation logic. Even without detailed messages, different error codes can help attackers distinguish between various failure scenarios.'
    },
    {
      code: `return res.status(400).json({
  error: 'Invalid request',
  field: 'fromAccount',
  constraint: 'foreign_key_accounts_user_id',
  suggestion: 'Use valid account ID'
});`,
      correct: false,
      explanation: 'Database constraint information exposes schema details including foreign key relationships and constraint names that provide valuable reconnaissance information for database-focused attacks.'
    },
    {
      code: `const maskedAccount = fromAccount.toString().replace(/\\d/g, '*');
return res.status(400).json({
  error: 'Account validation failed',
  accountPattern: maskedAccount,
  validationRule: 'Account must exist and belong to user'
});`,
      correct: false,
      explanation: 'Masked data and validation rules still expose business logic and data patterns. Even with obfuscation, the validation rule information helps attackers understand authorization mechanisms.'
    },
    {
      code: `if (process.env.NODE_ENV === 'development') {
  return res.status(400).json({ 
    error: 'Validation failed', 
    details: { providedAccountId: fromAccount, actualOwner: sourceAccount[0]?.user_id }
  });
} else {
  return res.status(400).json({ error: 'Invalid request' });
}`,
      correct: false,
      explanation: 'Environment-conditional error exposure can leak information if the environment is misconfigured, or if attackers can determine the deployment environment through other means.'
    },
    {
      code: `const validationHash = crypto.createHash('md5').update(\`\${fromAccount}_\${req.user.id}\`).digest('hex');
return res.status(400).json({
  error: 'Validation failed',
  checksum: validationHash
});`,
      correct: false,
      explanation: 'Validation checksums do not prevent information leakage and may actually provide attackers with additional data points for understanding validation logic or conducting timing attacks.'
    }
  ]
}
