import type { Exercise } from '@/data/exercises'

/**
 * CWE-209: Information Exposure Through Database Error Messages
 * Scenario: API endpoint exposing SQL errors with schema information
 * Based on MITRE demonstrative examples showing database error leakage
 */
export const cwe209DatabaseError: Exercise = {
  cweId: 'CWE-209',
  name: 'Information Exposure - Database Error Messages',

  vulnerableFunction: `app.get('/api/products/search', async (req, res) => {
  try {
    const { category, price_min, price_max, sort_by, order } = req.query;
    
    // Build dynamic query
    let query = 'SELECT * FROM products WHERE 1=1';
    const params = [];
    
    if (category) {
      query += ' AND category = ?';
      params.push(category);
    }
    
    if (price_min) {
      query += ' AND price >= ?';
      params.push(parseFloat(price_min));
    }
    
    if (price_max) {
      query += ' AND price <= ?';
      params.push(parseFloat(price_max));
    }
    
    // Add sorting (vulnerable to column name exposure)
    if (sort_by) {
      const allowedSorts = ['name', 'price', 'category', 'created_at'];
      if (allowedSorts.includes(sort_by)) {
        query += \` ORDER BY \${sort_by}\`;
        
        if (order && ['ASC', 'DESC'].includes(order.toUpperCase())) {
          query += \` \${order.toUpperCase()}\`;
        }
      }
    }
    
    console.log('Executing query:', query);
    console.log('With parameters:', params);
    
    const results = await db.query(query, params);
    
    res.json({
      products: results,
      total: results.length,
      query_time: Date.now()
    });
    
  } catch (error) {
    console.error('Database query failed:', error);
    
    // Return detailed database error information
    res.status(500).json({
      error: 'Database query failed',
      details: {
        message: error.message,
        code: error.code,
        errno: error.errno,
        sqlState: error.sqlState,
        sql: error.sql,
        sqlMessage: error.sqlMessage,
        table: error.table,
        column: error.column,
        constraint: error.constraint,
        schema: error.schema
      },
      executedQuery: {
        statement: query,
        parameters: params,
        database: process.env.DB_NAME,
        host: process.env.DB_HOST,
        user: process.env.DB_USER
      },
      systemInfo: {
        timestamp: new Date().toISOString(),
        nodeVersion: process.version,
        platform: process.platform
      },
      suggestion: 'Check table structure: DESCRIBE products; SHOW TABLES; SHOW COLUMNS FROM products;'
    });
  }
});`,

  vulnerableLine: `res.status(500).json({`,

  options: [
    {
      code: `// Log detailed error securely and return generic message
const errorId = generateErrorId();

console.error('Database error:', {
  errorId,
  message: error.message,
  code: error.code,
  sql: error.sql,
  params,
  timestamp: new Date().toISOString(),
  userId: req.user?.id,
  ip: req.ip
});

// Return generic error without exposing database details
res.status(500).json({
  error: 'Search temporarily unavailable',
  errorId: errorId,
  message: 'Please try again later or contact support if the problem persists'
});`,
      correct: true,
      explanation: `Correct! This prevents information exposure by logging detailed database errors securely on the server while returning only a generic error message to the client. The error ID allows developers to correlate user reports with server logs without exposing sensitive database schema, query structure, or system information that attackers could use to plan targeted SQL injection or other database attacks.`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `res.status(500).json({
  error: 'Database query failed',
  details: {
    message: error.message,
    code: error.code,
    sql: error.sql,
    table: error.table,
    column: error.column,
    schema: error.schema
  },
  executedQuery: {
    statement: query,
    parameters: params,
    database: process.env.DB_NAME
  }
});`,
      correct: false,
      explanation: 'Direct from MITRE CWE-209: Exposing detailed database errors reveals critical schema information including table names, column names, database structure, and query patterns. Attackers can use this information to craft targeted SQL injection attacks and understand the database architecture.'
    },
    {
      code: `res.status(500).json({
  error: 'Database error occurred',
  sqlError: error.message,
  failedQuery: query,
  suggestion: 'Check table structure: DESCRIBE products; SHOW TABLES;'
});`,
      correct: false,
      explanation: 'SQL error messages from MITRE examples expose database schema details and query structure. The debugging suggestions provide attackers with specific SQL commands to gather more information about the database structure.'
    },
    {
      code: `const sanitizedError = error.message.replace(/password/gi, '[REDACTED]');
res.status(500).json({
  error: 'Query execution failed',
  details: sanitizedError,
  query: query,
  database: process.env.DB_NAME
});`,
      correct: false,
      explanation: 'Simple keyword redaction is insufficient. Database errors contain many types of sensitive information beyond passwords, including table names, column names, and schema details that aid SQL injection attacks.'
    },
    {
      code: `if (error.code) {
  res.status(500).json({
    error: 'Database operation failed',
    errorCode: error.code,
    table: error.table
  });
} else {
  res.status(500).json({ error: 'Unknown database error' });
}`,
      correct: false,
      explanation: 'Database error codes and table names provide valuable reconnaissance information. Even without full error messages, specific error codes can reveal database type, version, and vulnerability patterns to attackers.'
    },
    {
      code: `res.status(500).json({
  error: 'Search failed',
  debug: process.env.NODE_ENV === 'development' ? {
    message: error.message,
    sql: query
  } : undefined,
  timestamp: Date.now()
});`,
      correct: false,
      explanation: 'Environment-conditional debugging can still expose sensitive information if attackers can determine or manipulate the environment setting, or if the application is accidentally deployed with development settings.'
    },
    {
      code: `const errorHash = crypto.createHash('md5').update(error.message).digest('hex');
res.status(500).json({
  error: 'Database operation unsuccessful',
  errorFingerprint: errorHash,
  query: query
});`,
      correct: false,
      explanation: 'Hashing error messages does not prevent information exposure when the original query is still included. The query structure reveals database schema and table information that attackers can exploit.'
    },
    {
      code: `res.status(500).json({
  error: 'Service error',
  type: 'DatabaseError',
  affected: error.table || 'unknown',
  code: 'DB_QUERY_FAILED'
});`,
      correct: false,
      explanation: 'Specific error types and affected table information still provide valuable reconnaissance data. Even abstracted error information can help attackers understand database structure and plan targeted attacks.'
    },
    {
      code: `console.log('Database error details:', error);
res.status(500).json({
  error: 'Unable to complete search',
  suggestion: 'Please refine your search criteria'
});`,
      correct: false,
      explanation: 'While the response is generic, logging detailed errors to console in production can expose sensitive information through log files, especially if logs are accessible or if there are log injection vulnerabilities.'
    },
    {
      code: `const truncatedError = error.message.substring(0, 50) + '...';
res.status(500).json({
  error: 'Database query issue',
  hint: truncatedError
});`,
      correct: false,
      explanation: 'Truncating error messages still exposes partial database information. Even shortened error messages can reveal table names, column names, or constraint information that aids in reconnaissance and attack planning.'
    }
  ]
}
