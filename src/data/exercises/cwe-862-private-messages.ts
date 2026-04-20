import type { Exercise } from '@/data/exercises'

/**
 * CWE-862 exercise - Private Messages
 * Based on MITRE horizontal authorization bypass in bulletin board systems
 */
export const cwe862PrivateMessages: Exercise = {
  cweId: 'CWE-862',
  name: 'Missing Authorization - Private Messages',
  language: 'JavaScript',

  vulnerableFunction: `app.get('/api/messages/:messageId', authenticateUser, (req, res) => {
  const messageId = req.params.messageId;

  // Fetch message from database
  const query = 'SELECT * FROM private_messages WHERE id = ?';
  db.query(query, [messageId], (err, results) => {
    if (err || results.length === 0) {
      return res.status(404).json({ error: 'Message not found' });
    }
    res.json(results[0]);
  });
});`,

  vulnerableLine: `const query = 'SELECT * FROM private_messages WHERE id = ?';`,

  options: [
    {
      code: `const query = 'SELECT * FROM private_messages WHERE id = ? AND (sender_id = ? OR recipient_id = ?)'; db.query(query, [messageId, req.user.id, req.user.id], (err, results) => {`,
      correct: true,
      explanation: `Check user permissions before access`
    },
    {
      code: `if (!session_is_registered("username")) { echo "invalid session detected!"; exit; } display_bulletin($messageId);`,
      correct: false,
      explanation: 'A bulletin board system that authenticates users but fails to verify message ownership allows "authenticated attackers to provide any arbitrary identifier and read private messages intended for other users."'
    },
    {
      code: `if (req.user && req.user.authenticated) { // User is logged in, show any message const query = \'SELECT * FROM private_messages WHERE id = ?\'; }`,
      correct: false,
      explanation: 'Authentication without authorization allows any logged-in user to access any private message by manipulating the messageId parameter.'
    },
    {
      code: `if (req.headers.authorization) { // Authorization header exists, allow access to any message }`,
      correct: false,
      explanation: 'Header presence validation confirms authentication but provides no access control. Users can still read private messages belonging to other users by changing the message ID.'
    },
    {
      code: `if (req.user.accountType === \'premium\') { // Premium users can access any private message }`,
      correct: false,
      explanation: 'Account type checking may determine feature access but should not override message ownership validation. Premium users should still only see their own private messages.'
    },
    {
      code: `if (parseInt(messageId) > 0) { // Valid message ID format, allow access const query = \'SELECT * FROM private_messages WHERE id = ?\'; }`,
      correct: false,
      explanation: 'Input validation ensures proper format but provides no authorization control. Any valid message ID can be accessed regardless of ownership or permissions.'
    },
    {
      code: `if (req.user.permissions.includes(\'read_messages\')) { // User has read permission, allow access to any message }`,
      correct: false,
      explanation: 'Generic permission checking without resource-specific authorization allows users to read all private messages rather than only their own messages.'
    },
    {
      code: `if (Date.now() - req.user.lastActivity < 300000) { // User recently active, allow access to any message }`,
      correct: false,
      explanation: 'Activity-based validation helps with session security but does not implement proper authorization to ensure users only access their own private messages.'
    },
    {
      code: `if (req.user.emailVerified && req.user.status === \'active\') { // Verified active user, allow access to any message }`,
      correct: false,
      explanation: 'Account verification and status checking are authentication-related but do not provide authorization controls for message ownership validation.'
    },
    {
      code: `if (req.sessionID && req.session.valid) { // Valid session, show any requested private message }`,
      correct: false,
      explanation: 'Session validity checking confirms authentication state but implements no authorization logic to restrict access to messages the user owns or has permission to read.'
    }
  ]
}