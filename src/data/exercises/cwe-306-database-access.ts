import type { Exercise } from '@/data/exercises'

/**
 * CWE-306: Missing Authentication for Database Management Interface
 * Infrastructure scenario: Database administration endpoint without access control
 */
export const cwe306DatabaseAccess: Exercise = {
  cweId: 'CWE-306',
  name: 'Missing Authentication - Database Management',
  language: 'C',

  vulnerableFunction: `class DatabaseAdminController {
  async executeQuery(req: Request, res: Response) {
    const { query, database } = req.body;

    // Basic query validation
    if (!query || !database) {
      return res.status(400).json({ error: 'Query and database parameters required' });
    }

    // Prevent obviously dangerous operations
    const dangerousOperations = ['DROP', 'DELETE', 'TRUNCATE', 'ALTER'];
    const upperQuery = query.toUpperCase();

    for (const op of dangerousOperations) {
      if (upperQuery.includes(op)) {
        return res.status(400).json({ error: \`Operation \${op} not allowed\` });
      }
    }

    try {
      const result = await DatabaseConnection.query(query, { database });

      res.status(200).json({
        success: true,
        rowCount: result.rowCount || 0,
        data: result.rows || [],
        executedAt: new Date()
      });
    } catch (error) {
      res.status(500).json({
        error: 'Query execution failed',
        message: error.message
      });
    }
  }
}`,

  vulnerableLine: `async executeQuery(req: Request, res: Response) {`,

  options: [
    {
      code: `async executeQuery(req: Request, res: Response) { const user = await this.authenticateUser(req); if (!user || user.role !== 'database_admin') { return res.status(403).json({ error: 'Database administrator access required' }); }`,
      correct: true,
      explanation: `Require authentication before access`
    },
    {
      code: `async executeQuery(req: Request, res: Response) {`,
      correct: false,
      explanation: 'Missing authentication for database operations allows unauthorized data access and manipulation. This is similar to cloud storage examples where unauthenticated access exposed sensitive data.'
    },
    {
      code: `async executeQuery(req: Request, res: Response) { if (!req.body.adminPassword) { return res.status(401).json({ error: 'Admin password required' }); }`,
      correct: false,
      explanation: 'Checking for password field presence without validation provides no authentication. Any value in the adminPassword field would satisfy this check.'
    },
    {
      code: `async executeQuery(req: Request, res: Response) { const dbToken = req.headers['x-db-token']; if (!dbToken) { return res.status(401).json({ error: 'Database token required' }); }`,
      correct: false,
      explanation: 'Requiring a token header without validation is meaningless. Any string value would satisfy this requirement while providing no authentication verification.'
    },
    {
      code: `async executeQuery(req: Request, res: Response) { if (req.query.readonly !== 'false' && req.body.query.toUpperCase().includes('SELECT')) { /* Allow read-only queries without auth */ } else { return res.status(403).json({ error: 'Write operations require authentication' }); }`,
      correct: false,
      explanation: 'Conditional authentication based on query type is insufficient. Even read-only database access should be authenticated, and query classification can be bypassed.'
    },
    {
      code: `async executeQuery(req: Request, res: Response) { const clientCert = req.headers['x-client-cert']; if (!clientCert) { return res.status(401).json({ error: 'Client certificate required' }); }`,
      correct: false,
      explanation: 'Checking for certificate header presence without validation provides no security. Certificate verification requires proper cryptographic validation, not just header presence.'
    },
    {
      code: `async executeQuery(req: Request, res: Response) { if (req.ip !== '192.168.1.100') { return res.status(403).json({ error: 'Database access restricted to admin workstation' }); }`,
      correct: false,
      explanation: 'IP-based restrictions are not user authentication. Source IP does not verify individual user identity, and IP addresses can be spoofed or proxied.'
    },
    {
      code: `async executeQuery(req: Request, res: Response) { const sessionCookie = req.headers.cookie; if (!sessionCookie || !sessionCookie.includes('db_session=')) { return res.status(401).json({ error: 'Database session required' }); }`,
      correct: false,
      explanation: 'Checking for cookie presence without session validation provides no authentication. Any value in the db_session cookie would satisfy this check.'
    }
  ]
}