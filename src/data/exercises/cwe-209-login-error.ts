import type { Exercise } from '@/data/exercises'

/**
 * CWE-209: Information Exposure Through Error Messages - Login System
 * Scenario: Authentication endpoint revealing account enumeration data
 * Based on MITRE demonstrative examples showing differential login errors
 */
export const cwe209LoginError: Exercise = {
  cweId: 'CWE-209',
  name: 'Information Exposure - Login Error Messages',

  vulnerableFunction: `app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Validate input format
    if (!email || !password) {
      return res.status(400).json({ 
        error: 'Email and password are required',
        timestamp: Date.now()
      });
    }
    
    // Look up user by email
    const userQuery = 'SELECT id, email, password_hash, account_status, failed_attempts, locked_until FROM users WHERE email = ?';
    const userResult = await db.query(userQuery, [email]);
    
    if (userResult.length === 0) {
      return res.status(401).json({
        error: 'No account found with that email address',
        suggestion: 'Please check your email or create a new account',
        availableEmails: await db.query('SELECT email FROM users WHERE email LIKE ? LIMIT 5', [\`\${email.split('@')[0]}%\`]),
        timestamp: Date.now()
      });
    }
    
    const user = userResult[0];
    
    // Check if account is locked
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      return res.status(423).json({
        error: 'Account temporarily locked due to multiple failed login attempts',
        lockedUntil: user.locked_until,
        failedAttempts: user.failed_attempts,
        unlockTime: new Date(user.locked_until).toLocaleString(),
        contactSupport: 'support@company.com'
      });
    }
    
    // Verify password
    const passwordValid = await bcrypt.compare(password, user.password_hash);
    
    if (!passwordValid) {
      await incrementFailedAttempts(user.id);
      
      return res.status(401).json({
        error: 'Incorrect password for this account',
        email: email,
        lastSuccessfulLogin: user.last_login,
        failedAttempts: user.failed_attempts + 1,
        accountCreated: user.created_at,
        passwordHint: user.password_hint,
        suggestedActions: ['Try password reset', 'Contact support'],
        timestamp: Date.now()
      });
    }
    
    // Check account status
    if (user.account_status === 'suspended') {
      return res.status(403).json({
        error: 'Account suspended',
        reason: user.suspension_reason,
        suspendedSince: user.suspended_at,
        contactInfo: 'support@company.com'
      });
    }
    
    // Generate session token
    const token = jwt.sign({ userId: user.id, email: user.email }, process.env.JWT_SECRET);
    
    res.json({
      message: 'Login successful',
      token: token,
      user: { id: user.id, email: user.email }
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      error: 'Login system error',
      details: error.message,
      stack: error.stack,
      query: error.sql
    });
  }
});`,

  vulnerableLine: `return res.status(401).json({`,

  options: [
    {
      code: `// Use consistent response for all authentication failures
const loginAttempt = {
  email,
  ip: req.ip,
  timestamp: Date.now(),
  success: false
};

if (userResult.length === 0) {
  await logLoginAttempt(loginAttempt);
  // Same delay as password verification
  await new Promise(resolve => setTimeout(resolve, 100));
}

if (userResult.length === 0 || !passwordValid || user.account_status !== 'active') {
  await logFailedLogin(email, req.ip);
  
  return res.status(401).json({
    error: 'Invalid credentials',
    timestamp: Date.now()
  });
}`,
      correct: true,
      explanation: `Correct! This prevents information exposure by providing identical responses for all authentication failures, regardless of whether the account exists, password is wrong, or account is disabled. Attackers cannot distinguish between these scenarios, preventing user enumeration. The consistent timing and generic error message eliminate information leakage while still providing appropriate security logging.`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `return res.status(401).json({
  error: 'No account found with that email address',
  suggestion: 'Please check your email or create a new account',
  availableEmails: await db.query('SELECT email FROM users WHERE email LIKE ? LIMIT 5', [\`\${email.split('@')[0]}%\`]),
  timestamp: Date.now()
});`,
      correct: false,
      explanation: 'Direct from MITRE CWE-209: Specific error messages enable user enumeration attacks. Attackers can systematically test email addresses to discover registered accounts. The suggested similar emails provide additional reconnaissance data for targeted attacks.'
    },
    {
      code: `return res.status(401).json({
  error: 'Incorrect password for this account',
  email: email,
  lastSuccessfulLogin: user.last_login,
  failedAttempts: user.failed_attempts + 1,
  accountCreated: user.created_at,
  passwordHint: user.password_hint,
  timestamp: Date.now()
});`,
      correct: false,
      explanation: 'Password-specific error from MITRE examples confirms account existence and exposes additional sensitive information including login history, creation date, and password hints that can be used for social engineering or targeted attacks.'
    },
    {
      code: `if (userResult.length === 0) {
  return res.status(404).json({ error: 'User not found' });
} else {
  return res.status(401).json({ error: 'Authentication failed' });
}`,
      correct: false,
      explanation: 'Different status codes from MITRE examples enable user enumeration. Attackers can distinguish between non-existent accounts (404) and existing accounts with wrong passwords (401) to build user lists for targeted attacks.'
    },
    {
      code: `return res.status(423).json({
  error: 'Account temporarily locked due to multiple failed login attempts',
  lockedUntil: user.locked_until,
  failedAttempts: user.failed_attempts,
  unlockTime: new Date(user.locked_until).toLocaleString()
});`,
      correct: false,
      explanation: 'Account lock messages expose detailed account information including exact lock times and failure counts. This confirms account existence and provides timing information that attackers can use to plan future attacks.'
    },
    {
      code: `const errorCode = userResult.length === 0 ? 'USER_NOT_FOUND' : 'INVALID_PASSWORD';
return res.status(401).json({ 
  error: 'Login failed', 
  code: errorCode 
});`,
      correct: false,
      explanation: 'Different error codes still enable user enumeration. Even with generic error messages, specific codes like USER_NOT_FOUND clearly indicate to attackers whether an email address is registered.'
    },
    {
      code: `if (userResult.length === 0) {
  await new Promise(resolve => setTimeout(resolve, 500));
} else {
  await new Promise(resolve => setTimeout(resolve, 100));
}
return res.status(401).json({ error: 'Authentication failed' });`,
      correct: false,
      explanation: 'Different timing delays can still enable user enumeration through timing analysis. Attackers can distinguish between existing and non-existing accounts by measuring response times despite generic error messages.'
    },
    {
      code: `const hashedEmail = crypto.createHash('md5').update(email).digest('hex');
return res.status(401).json({ 
  error: 'Login failed for user', 
  identifier: hashedEmail 
});`,
      correct: false,
      explanation: 'Email hashing does not prevent enumeration when combined with differential responses. Attackers can still distinguish account existence through different response patterns or timing differences.'
    },
    {
      code: `console.log(\`Failed login attempt for: \${email}\`);
return res.status(401).json({ error: 'Invalid login credentials' });`,
      correct: false,
      explanation: 'While consistent error messages help, server-side logging alone is insufficient if there are still timing differences or other side-channel information leakage methods that attackers can exploit.'
    },
    {
      code: `const randomResponse = Math.random() > 0.5 ? 'Invalid credentials' : 'Authentication failed';
return res.status(401).json({ error: randomResponse });`,
      correct: false,
      explanation: 'Random error messages do not address the core issue. If there are still differences in response timing, status codes, or other patterns between existing and non-existing accounts, enumeration is still possible.'
    }
  ]
}
