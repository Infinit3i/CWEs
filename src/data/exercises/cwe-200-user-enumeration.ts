import type { Exercise } from '@/data/exercises'

/**
 * CWE-200: Information Exposure Through User Enumeration
 * Scenario: User registration endpoint revealing account existence
 * Based on MITRE patterns for differential response information leakage
 */
export const cwe200UserEnumeration: Exercise = {
  cweId: 'CWE-200',
  name: 'Information Exposure - User Enumeration',
  language: 'Java',

  vulnerableFunction: `app.post('/api/register', async (req, res) => {
  try {
    const { email, password, firstName, lastName } = req.body;
    
    // Validate email format
    if (!email || !/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email)) {
      return res.status(400).json({ 
        error: 'Invalid email format',
        timestamp: Date.now()
      });
    }
    
    // Validate password strength
    if (!password || password.length < 8) {
      return res.status(400).json({ 
        error: 'Password must be at least 8 characters',
        timestamp: Date.now()
      });
    }
    
    // Check if user already exists
    const existingUser = await db.query('SELECT id, email FROM users WHERE email = ?', [email]);
    
    if (existingUser.length > 0) {
      return res.status(409).json({ 
        error: 'Account already exists for this email address',
        email: email,
        existingSince: existingUser[0].created_at,
        lastLogin: existingUser[0].last_login,
        accountType: existingUser[0].account_type,
        timestamp: Date.now()
      });
    }
    
    // Create new user account
    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = await db.query(
      'INSERT INTO users (email, password_hash, first_name, last_name) VALUES (?, ?, ?, ?)',
      [email, hashedPassword, firstName, lastName]
    );
    
    res.status(201).json({
      message: 'Account created successfully',
      userId: newUser.insertId,
      email: email,
      timestamp: Date.now()
    });
    
  } catch (error) {
    res.status(500).json({
      error: 'Registration failed',
      details: error.message,
      timestamp: Date.now()
    });
  }
});`,

  vulnerableLine: `return res.status(409).json({`,

  options: [
    {
      code: `// Use consistent response to prevent user enumeration
if (existingUser.length > 0) {
  // Log attempt for monitoring
  console.log('Registration attempt for existing email:', email);
  
  // Return same response as successful registration
  res.status(201).json({
    message: 'Registration initiated. Please check your email for verification.',
    timestamp: Date.now()
  });
  
  // Send different email to existing user
  await sendExistingUserNotification(email);
  return;
}`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `return res.status(409).json({ 
  error: 'Account already exists for this email address',
  email: email,
  existingSince: existingUser[0].created_at,
  lastLogin: existingUser[0].last_login,
  accountType: existingUser[0].account_type,
  timestamp: Date.now()
});`,
      correct: false,
      explanation: 'Direct from MITRE CWE-200: Differential responses enable user enumeration attacks. Attackers can systematically test email addresses to discover which users have accounts, plus gather additional information like registration dates and account types for targeted attacks.'
    },
    {
      code: `if (existingUser.length > 0) {
  return res.status(409).json({ 
    error: 'Registration failed',
    reason: 'Email already in use',
    timestamp: Date.now()
  });
}`,
      correct: false,
      explanation: 'Different error messages from MITRE examples still enable user enumeration. Even without additional details, the specific "Email already in use" message allows attackers to distinguish existing accounts from other registration failures.'
    },
    {
      code: `if (existingUser.length > 0) {
  // Add random delay to obscure timing differences
  await new Promise(resolve => setTimeout(resolve, Math.random() * 1000));
  return res.status(409).json({ error: 'Account already exists' });
}`,
      correct: false,
      explanation: 'Random delays do not prevent user enumeration when different status codes and messages are returned. Attackers can still distinguish existing accounts through response content despite timing variations.'
    },
    {
      code: `if (existingUser.length > 0) {
  const hashedEmail = crypto.createHash('md5').update(email).digest('hex');
  return res.status(409).json({ 
    error: 'Duplicate found',
    identifier: hashedEmail 
  });
}`,
      correct: false,
      explanation: 'Hashing email addresses does not prevent enumeration when different responses are provided. The 409 status code and "Duplicate found" message still clearly indicate that the email address is already registered.'
    },
    {
      code: `if (existingUser.length > 0) {
  return res.status(400).json({ 
    error: 'Registration validation failed',
    code: 'DUPLICATE_EMAIL'
  });
}`,
      correct: false,
      explanation: 'Using different status codes or error codes still enables user enumeration. The specific error code "DUPLICATE_EMAIL" clearly indicates to attackers that the email address is already registered in the system.'
    },
    {
      code: `if (existingUser.length > 0) {
  console.log('Existing user registration attempt:', email);
  return res.status(409).json({ error: 'Unable to complete registration' });
}`,
      correct: false,
      explanation: 'Generic error messages with different status codes still reveal information. The 409 Conflict status specifically indicates a duplicate resource, allowing attackers to distinguish existing accounts.'
    },
    {
      code: `if (existingUser.length > 0) {
  const errorId = generateRandomId();
  return res.status(409).json({ 
    error: 'Registration failed',
    errorId: errorId 
  });
}`,
      correct: false,
      explanation: 'Adding error IDs does not prevent enumeration when distinctive status codes are used. The 409 status code still clearly indicates that the email address already exists in the system.'
    },
    {
      code: `if (existingUser.length > 0) {
  return res.status(500).json({ error: 'Internal server error' });
}`,
      correct: false,
      explanation: 'Using a 500 error code for existing users can prevent enumeration but incorrectly suggests a server problem. This approach may confuse legitimate users and does not provide proper user experience.'
    },
    {
      code: `if (existingUser.length > 0) {
  const obfuscated = Buffer.from('Account exists').toString('base64');
  return res.status(409).json({ message: obfuscated });
}`,
      correct: false,
      explanation: 'Obfuscating the response message does not prevent enumeration when distinctive status codes are used. The 409 status code still indicates a conflict, and the base64 can be easily decoded.'
    }
  ]
}
