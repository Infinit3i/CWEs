import type { Exercise } from '@/data/exercises'

/**
 * CWE-200: Information Exposure Through API Error Messages
 * Scenario: REST API exposing sensitive system information in errors
 * Based on MITRE examples showing uncontrolled information disclosure
 */
export const cwe200ApiError: Exercise = {
  cweId: 'CWE-200',
  name: 'Information Exposure - API Error Messages',
  language: 'Java',

  vulnerableFunction: `app.get('/api/user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Query user from database
    const query = 'SELECT * FROM users WHERE id = ?';
    const result = await db.query(query, [userId]);
    
    if (result.length === 0) {
      return res.status(404).json({ 
        error: 'User not found',
        query: query,
        searchedUserId: userId,
        availableUsers: await db.query('SELECT id, email FROM users LIMIT 10')
      });
    }
    
    res.json({ user: result[0] });
    
  } catch (error) {
    res.status(500).json({
      error: 'Database connection failed',
      details: {
        message: error.message,
        stack: error.stack,
        query: error.sql,
        host: process.env.DB_HOST,
        database: process.env.DB_NAME,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD
      }
    });
  }
});`,

  vulnerableLine: `res.status(500).json({`,

  options: [
    {
      code: `// Log detailed error for debugging but return generic message
console.error('Database error:', {
  userId,
  error: error.message,
  stack: error.stack,
  timestamp: new Date().toISOString()
});

res.status(500).json({
  error: 'Internal server error',
  errorId: generateErrorId()
});`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `res.status(500).json({
  error: 'Database connection failed',
  details: {
    message: error.message,
    stack: error.stack,
    query: error.sql,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD
  }
});`,
      correct: false,
      explanation: 'Direct from MITRE CWE-200: Exposing detailed error information reveals sensitive system details including database credentials, connection strings, and query structure. Attackers can use this information to plan targeted attacks.'
    },
    {
      code: `res.status(500).json({
  error: 'Database error',
  sqlError: error.message,
  failedQuery: error.sql
});`,
      correct: false,
      explanation: 'Exposing SQL error messages and queries from MITRE examples reveals database schema, table names, and column structures that attackers can use for SQL injection and reconnaissance.'
    },
    {
      code: `res.status(500).json({
  error: 'Internal error',
  timestamp: Date.now(),
  server: os.hostname(),
  process: process.pid
});`,
      correct: false,
      explanation: 'System information exposure reveals server hostnames and process details that can aid attackers in fingerprinting the infrastructure and planning advanced persistent threats.'
    },
    {
      code: `res.status(500).json({
  error: 'Service unavailable',
  config: {
    environment: process.env.NODE_ENV,
    version: process.env.APP_VERSION,
    dbHost: process.env.DB_HOST?.substring(0, 3) + '***'
  }
});`,
      correct: false,
      explanation: 'Partial masking of sensitive data still leaks valuable information. Environment details and version information can help attackers identify specific vulnerabilities and attack vectors.'
    },
    {
      code: `const errorCode = error.code || 'UNKNOWN';
res.status(500).json({
  error: 'Database error occurred',
  errorCode: errorCode,
  suggestion: 'Check database connection'
});`,
      correct: false,
      explanation: 'Database error codes can reveal specific system information and vulnerabilities. Even without full details, error codes can guide attackers toward specific attack strategies.'
    },
    {
      code: `res.status(500).json({
  error: 'Request failed',
  debug: process.env.NODE_ENV === 'development' ? error.stack : 'Contact support',
  requestId: req.headers['x-request-id']
});`,
      correct: false,
      explanation: 'Environment-conditional error exposure can still leak information if attackers can determine or manipulate the environment. Request IDs may also reveal internal system patterns.'
    },
    {
      code: `const sanitizedError = error.message.replace(/password/gi, '[REDACTED]');
res.status(500).json({
  error: 'Operation failed',
  details: sanitizedError,
  stack: error.stack?.split('\\n')[0]
});`,
      correct: false,
      explanation: 'Simple keyword redaction is insufficient. Error messages can contain many types of sensitive information beyond passwords, and partial stack traces still reveal internal code structure.'
    },
    {
      code: `res.status(500).json({
  error: 'Service error',
  code: 'ERR_DB_CONNECTION',
  retry: true,
  contact: 'support@company.com'
});`,
      correct: false,
      explanation: 'Specific error codes can provide attackers with information about internal system architecture and potential attack vectors, even when other details are omitted.'
    },
    {
      code: `const logEntry = \`Error at \${new Date()}: \${error.message}\`;
fs.appendFileSync('/var/log/app.log', logEntry);
res.status(500).json({ error: 'Request could not be processed' });`,
      correct: false,
      explanation: 'While logging is good practice, synchronous file operations can cause performance issues and the generic error message lacks an error ID for correlation between client reports and server logs.'
    }
  ]
}
