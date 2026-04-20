import type { Exercise } from '@/data/exercises'

/**
 * CWE-306: Missing Authentication for Admin API Endpoints
 * Enterprise scenario: Administrative API without proper authentication checks
 */
export const cwe306AdminApi: Exercise = {
  cweId: 'CWE-306',
  name: 'Missing Authentication - Administrative API',

  vulnerableFunction: `class AdminController {
  async createUserAccount(req: Request, res: Response) {
    const { username, email, role, permissions } = req.body;

    const newUser = await User.create({
      username,
      email,
      role: role || 'admin',
      permissions: permissions || ['read', 'write', 'delete'],
      accountStatus: 'active',
      createdBy: 'admin-api'
    });

    await this.auditLogger.log('USER_CREATED', {
      userId: newUser.id,
      username: newUser.username,
      role: newUser.role
    });

    res.status(201).json({
      message: 'User account created successfully',
      userId: newUser.id,
      username: newUser.username
    });
  }
}`,

  vulnerableLine: `async createUserAccount(req: Request, res: Response) {`,

  options: [
    {
      code: `async createUserAccount(req: Request, res: Response) { const user = await this.authenticateAdmin(req); if (!user || user.role !== 'admin') { return res.status(403).json({ error: 'Admin access required' }); }`,
      correct: true,
      explanation: `Correct! Administrative functions must verify both authentication (who is the user) and authorization (does the user have admin privileges) before allowing sensitive operations like user creation.`
    },
    {
      code: `async createUserAccount(req: Request, res: Response) {`,
      correct: false,
      explanation: 'From MITRE: "There is no authentication mechanism to ensure that the user creating this bank account object has the authority to create new bank accounts." Same applies to user accounts - anyone can create admin users.'
    },
    {
      code: `async createUserAccount(req: Request, res: Response) { if (!req.headers.authorization) { return res.status(401).json({ error: 'Authorization header required' }); }`,
      correct: false,
      explanation: 'Checking for presence of Authorization header without validating the token provides no security. Any value in the header would bypass this check.'
    },
    {
      code: `async createUserAccount(req: Request, res: Response) { const apiKey = req.headers['x-api-key']; if (!apiKey) { return res.status(401).json({ error: 'API key required' }); }`,
      correct: false,
      explanation: 'Requiring an API key without validation is meaningless. Any string value would satisfy this check, providing no authentication.'
    },
    {
      code: `async createUserAccount(req: Request, res: Response) { if (req.ip !== '127.0.0.1') { return res.status(403).json({ error: 'Access denied' }); }`,
      correct: false,
      explanation: 'IP-based access control is not authentication. IP addresses can be spoofed, and legitimate remote administration requires proper authentication mechanisms.'
    },
    {
      code: `async createUserAccount(req: Request, res: Response) { const timestamp = Date.now(); if (!req.body.timestamp || Math.abs(timestamp - req.body.timestamp) > 60000) { return res.status(400).json({ error: 'Invalid timestamp' }); }`,
      correct: false,
      explanation: 'Timestamp validation addresses replay attacks but provides no authentication. Anyone can include a current timestamp and still access the endpoint.'
    },
    {
      code: `async createUserAccount(req: Request, res: Response) { if (req.method !== 'POST') { return res.status(405).json({ error: 'Method not allowed' }); }`,
      correct: false,
      explanation: 'HTTP method validation is not authentication. This only restricts the request type but allows anyone using POST to access the administrative function.'
    },
    {
      code: `async createUserAccount(req: Request, res: Response) { const userAgent = req.headers['user-agent']; if (!userAgent || !userAgent.includes('AdminClient')) { return res.status(403).json({ error: 'Invalid client' }); }`,
      correct: false,
      explanation: 'User-Agent validation is not authentication. Headers can be easily spoofed, and this provides no verification of user identity or authority.'
    }
  ]
}