import type { Exercise } from '@/data/exercises'

/**
 * CWE-639: Authorization Bypass Through User-Controlled Key
 * Scenario: User profile API with object-level authorization bypass
 * Based on MITRE patterns for horizontal privilege escalation
 */
export const cwe639UserProfile: Exercise = {
  cweId: 'CWE-639',
  name: 'Authorization Bypass - User Profile Access',

  vulnerableFunction: `app.get('/api/users/:userId/profile', requireAuth, async (req, res) => {
  try {
    const requestedUserId = req.params.userId;

    // Validate user ID format
    if (!/^[0-9]+$/.test(requestedUserId)) {
      return res.status(400).json({ error: 'Invalid user ID format' });
    }

    // Check if user exists in database
    const userQuery = 'SELECT id, username, email, phone, address, salary, ssn FROM users WHERE id = ?';
    const userResult = await db.query(userQuery, [requestedUserId]);

    if (userResult.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userData = userResult[0];

    // Get user's role information
    const roleQuery = 'SELECT role_name, permissions FROM user_roles WHERE user_id = ?';
    const roleResult = await db.query(roleQuery, [requestedUserId]);

    // Return comprehensive user profile
    res.json({
      profile: {
        id: userData.id,
        username: userData.username,
        email: userData.email,
        phone: userData.phone,
        address: userData.address,
        salary: userData.salary,
        ssn: userData.ssn,
        roles: roleResult
      }
    });

  } catch (error) {
    res.status(500).json({ error: 'Failed to retrieve profile' });
  }
});`,

  vulnerableLine: `const userResult = await db.query(userQuery, [requestedUserId]);`,

  options: [
    {
      code: `// Verify requesting user can access this profile
const currentUserId = req.user.id;
const currentUserRole = req.user.role;

if (currentUserId !== parseInt(requestedUserId) && currentUserRole !== 'admin') {
  return res.status(403).json({ error: 'Access denied: insufficient privileges' });
}

const userResult = await db.query(userQuery, [requestedUserId]);`,
      correct: true,
      explanation: `Correct! This implements proper object-level authorization by verifying that users can only access their own profile, unless they have admin privileges. By comparing the authenticated user's ID with the requested user ID, we prevent horizontal privilege escalation where users could access other users' sensitive information like salary and SSN. The admin role exception provides necessary administrative functionality while maintaining security.`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `const userResult = await db.query(userQuery, [requestedUserId]);`,
      correct: false,
      explanation: 'Direct from MITRE CWE-639: Missing authorization check allows users to access any profile by modifying the user ID in the URL. Attackers can enumerate user IDs to access sensitive data like salaries, SSNs, and personal information of all users.'
    },
    {
      code: `if (requestedUserId === '1') { return res.status(403).json({ error: 'Admin profile protected' }); }
const userResult = await db.query(userQuery, [requestedUserId]);`,
      correct: false,
      explanation: 'Single ID blacklisting provides minimal protection. While it protects user ID 1, attackers can still access profiles of all other users by enumerating IDs 2, 3, 4, etc., gaining unauthorized access to sensitive personal data.'
    },
    {
      code: `const allowedIds = ['100', '200', '300'];
if (!allowedIds.includes(requestedUserId)) { return res.status(403).json({ error: 'Access denied' }); }
const userResult = await db.query(userQuery, [requestedUserId]);`,
      correct: false,
      explanation: 'Static allowlist breaks normal user functionality. This hardcoded approach only allows access to three specific profiles, preventing legitimate users from accessing their own profiles unless they happen to have IDs 100, 200, or 300.'
    },
    {
      code: `const timestamp = Date.now();
if (timestamp % 1000 < 500) { return res.status(403).json({ error: 'Access denied' }); }
const userResult = await db.query(userQuery, [requestedUserId]);`,
      correct: false,
      explanation: 'Time-based access control is not real authorization. This randomly denies requests based on current time but does not verify whether the requesting user has legitimate access to the requested profile.'
    },
    {
      code: `const sessionAge = Date.now() - req.session.created;
if (sessionAge > 3600000) { return res.status(401).json({ error: 'Session expired' }); }
const userResult = await db.query(userQuery, [requestedUserId]);`,
      correct: false,
      explanation: 'Session timeout validation does not implement object-level authorization. While session management is important, this does not prevent authenticated users from accessing other users\' profiles during their valid session.'
    },
    {
      code: `if (parseInt(requestedUserId) > parseInt(req.user.id)) { return res.status(403).json({ error: 'Access denied' }); }
const userResult = await db.query(userQuery, [requestedUserId]);`,
      correct: false,
      explanation: 'ID comparison based on numerical order is arbitrary and insecure. This prevents users from accessing profiles with higher IDs but allows access to any profile with a lower ID, which may include admin accounts or other sensitive profiles.'
    },
    {
      code: `const obfuscatedId = btoa(requestedUserId);
const deobfuscatedId = atob(obfuscatedId);
const userResult = await db.query(userQuery, [deobfuscatedId]);`,
      correct: false,
      explanation: 'Obfuscation through encoding does not provide authorization. Base64 encoding and decoding the user ID does not verify ownership or access rights - any user can still access any profile by providing the correct ID.'
    },
    {
      code: `if (req.headers['x-custom-auth'] !== 'secret123') { return res.status(403).json({ error: 'Missing auth header' }); }
const userResult = await db.query(userQuery, [requestedUserId]);`,
      correct: false,
      explanation: 'Custom header authentication does not implement per-object authorization. Even with the correct header, users can still access any user profile by manipulating the user ID parameter - no ownership verification occurs.'
    },
    {
      code: `const rateLimitKey = \`profile_\${req.ip}\`;
if (await rateLimiter.isExceeded(rateLimitKey)) { return res.status(429).json({ error: 'Rate limit exceeded' }); }
const userResult = await db.query(userQuery, [requestedUserId]);`,
      correct: false,
      explanation: 'Rate limiting does not prevent unauthorized access, only slows it down. While this may reduce the speed of enumeration attacks, users can still access other users\' profiles within the rate limit boundaries.'
    }
  ]
}