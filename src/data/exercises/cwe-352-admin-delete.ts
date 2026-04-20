import type { Exercise } from '@/data/exercises'

/**
 * CWE-352 exercise - Admin User Deletion
 * Based on MITRE CSRF examples targeting privileged operations
 */
export const cwe352AdminDelete: Exercise = {
  cweId: 'CWE-352',
  name: 'Cross-Site Request Forgery - Admin User Deletion',

  vulnerableFunction: `app.delete('/admin/users/:userId', requireAdmin, (req, res) => {
  const { userId } = req.params;
  const adminId = req.user.id;

  // Prevent self-deletion
  if (userId === adminId) {
    return res.status(400).json({ error: 'Cannot delete yourself' });
  }

  deleteUser(userId);
  res.json({ message: 'User deleted successfully' });
});`,

  vulnerableLine: `app.delete('/admin/users/:userId', requireAdmin, (req, res) => {`,

  options: [
    {
      code: `const csrf = require('csurf'); app.delete('/admin/users/:userId', requireAdmin, csrf({ cookie: { httpOnly: true, secure: true, sameSite: 'strict' } }), (req, res) => {`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `app.delete('/admin/users/:userId', (req, res) => { if (!req.session || !req.session.isAdmin) { return res.status(401).json({ error: 'Admin required' }); }`,
      correct: false,
      explanation: 'When a privileged user is compromised via CSRF, "consequences may include obtaining complete control over the web application—deleting or stealing data" because session validation alone is insufficient.'
    },
    {
      code: `app.delete('/admin/users/:userId', requireAdmin, (req, res) => { if (req.headers['user-agent'] && req.headers['user-agent'].includes('Mozilla')) { // Proceed with deletion }`,
      correct: false,
      explanation: 'User-Agent validation is ineffective as malicious requests from the victim\'s browser will include legitimate user-agent strings, allowing the CSRF attack to succeed.'
    },
    {
      code: `app.delete('/admin/users/:userId', requireAdmin, (req, res) => { if (!req.headers.referer || !req.headers.referer.startsWith('https://admin.example.com')) { return res.status(403).json({ error: 'Invalid referer' }); }`,
      correct: false,
      explanation: 'Referer checking can be bypassed and may block legitimate requests from users with privacy settings. Corporate firewalls often strip referer headers entirely.'
    },
    {
      code: `app.delete('/admin/users/:userId', requireAdmin, (req, res) => { const confirmHeader = req.headers['x-confirm-delete']; if (confirmHeader !== 'true') { return res.status(400).json({ error: 'Confirmation required' }); }`,
      correct: false,
      explanation: 'Custom headers provide limited protection but can be included in malicious XMLHttpRequest-based attacks, especially if the victim is tricked into visiting a compromised admin page.'
    },
    {
      code: `app.delete('/admin/users/:userId', requireAdmin, (req, res) => { const clientIP = req.ip; if (clientIP !== req.user.lastLoginIP) { return res.status(403).json({ error: 'IP mismatch' }); }`,
      correct: false,
      explanation: 'IP validation breaks mobile users and shared networks while not preventing CSRF, since the malicious request originates from the victim\'s IP address through their browser.'
    },
    {
      code: `app.delete('/admin/users/:userId', requireAdmin, (req, res) => { if (req.method !== 'DELETE') { return res.status(405).json({ error: 'Method not allowed' }); }`,
      correct: false,
      explanation: 'HTTP method validation is standard practice but provides no CSRF protection, as attackers can craft DELETE requests using JavaScript XMLHttpRequest or fetch API.'
    },
    {
      code: `app.delete('/admin/users/:userId', requireAdmin, (req, res) => { const timestamp = parseInt(req.headers['x-timestamp']); if (!timestamp || Math.abs(Date.now() - timestamp) > 60000) { return res.status(403).json({ error: 'Request expired' }); }`,
      correct: false,
      explanation: 'Timestamp validation does not prevent CSRF as malicious JavaScript can dynamically generate current timestamps when crafting the attack request.'
    },
    {
      code: `app.delete('/admin/users/:userId', requireAdmin, (req, res) => { if (Date.now() - req.user.lastActivity < 5000) { // Recently active, likely legitimate } else { return res.status(403).json({ error: 'Session timeout' }); }`,
      correct: false,
      explanation: 'Activity-based validation may help but does not prevent CSRF if the admin is actively using the application when the attack occurs, which is often the target scenario.'
    },
    {
      code: `app.delete('/admin/users/:userId', requireAdmin, (req, res) => { const origin = req.headers.origin; if (!origin || !['https://admin.example.com', 'https://secure-admin.example.com'].includes(origin)) { return res.status(403).json({ error: 'Invalid origin' }); }`,
      correct: false,
      explanation: 'Origin validation helps but provides weaker protection than CSRF tokens and may not be sent in all browsers or request types, especially for same-site navigation.'
    }
  ]
}