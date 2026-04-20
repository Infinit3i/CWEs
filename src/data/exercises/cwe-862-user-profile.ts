import type { Exercise } from '@/data/exercises'

/**
 * CWE-862 exercise - User Profile Access
 * Based on MITRE demonstrative examples for missing authorization checks
 */
export const cwe862UserProfile: Exercise = {
  cweId: 'CWE-862',
  name: 'Missing Authorization - User Profile Access',

  vulnerableFunction: `app.get('/api/users/:userId/profile', authenticateUser, (req, res) => {
  const requestedUserId = req.params.userId;

  // Query user profile from database
  const query = 'SELECT email, full_name, phone, address FROM users WHERE id = ?';
  db.query(query, [requestedUserId], (err, results) => {
    if (err || results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(results[0]);
  });
});`,

  vulnerableLine: `app.get('/api/users/:userId/profile', authenticateUser, (req, res) => {`,

  options: [
    {
      code: `app.get('/api/users/:userId/profile', authenticateUser, (req, res) => { const requestedUserId = parseInt(req.params.userId); const currentUserId = req.user.id; if (requestedUserId !== currentUserId && !req.user.isAdmin) { return res.status(403).json({ error: 'Access denied' }); }`,
      correct: true,
      explanation: `Check user permissions before access`
    },
    {
      code: `if (!session_is_registered("username")) { echo "invalid session detected!"; exit; }`,
      correct: false,
      explanation: 'Authentication-only validation allows any authenticated user to access any profile. An "authenticated attacker could provide any arbitrary identifier and read private messages intended for other users."'
    },
    {
      code: `if (!req.user || !req.user.id) { return res.status(401).json({ error: 'Authentication required' }); } // Proceed with any user ID`,
      correct: false,
      explanation: 'MITRE vulnerability: This only verifies user identity but not permissions. Any authenticated user can access sensitive employee information by providing different user IDs in the request.'
    },
    {
      code: `if (req.headers.authorization && req.headers.authorization.includes('Bearer')) { // User is authenticated, allow access }`,
      correct: false,
      explanation: 'Token presence validation confirms authentication but provides no authorization control. Users can still access other users\' profiles by manipulating the userId parameter.'
    },
    {
      code: `if (req.user.accountStatus === 'active') { // User account is active, allow profile access for any userId }`,
      correct: false,
      explanation: 'Account status checking is part of authentication state but does not address authorization. Active users can still access profiles they should not have permission to view.'
    },
    {
      code: `if (req.ip && req.ip === req.user.lastLoginIP) { // IP matches, allow access to any profile }`,
      correct: false,
      explanation: 'IP validation may help detect session hijacking but does not provide authorization controls. Legitimate users from the correct IP can still access unauthorized profiles.'
    },
    {
      code: `if (Date.now() - req.user.loginTime < 3600000) { // Session is recent, allow access to any profile }`,
      correct: false,
      explanation: 'Session freshness checking is good for security but does not implement authorization controls. Recent sessions can still access profiles without permission validation.'
    },
    {
      code: `if (req.user.emailVerified === true) { // Email is verified, allow profile access for any user }`,
      correct: false,
      explanation: 'Email verification status is part of user authentication state but provides no authorization boundaries. Verified users can still access other users\' private data.'
    },
    {
      code: `if (req.user.role && ['user', 'admin', 'moderator'].includes(req.user.role)) { // Valid role exists, allow any profile access }`,
      correct: false,
      explanation: 'Role existence checking confirms user has a valid role but does not implement proper authorization logic to restrict access to appropriate resources per role.'
    },
    {
      code: `if (req.sessionID && req.session.userId) { // Valid session exists, allow access to any profile }`,
      correct: false,
      explanation: 'Session validation confirms the user is authenticated but implements no authorization logic to ensure users only access their own profile data or have appropriate permissions.'
    }
  ]
}