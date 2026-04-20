import type { Exercise } from '@/data/exercises'

/**
 * CWE-352 exercise - Profile Update Endpoint
 * Based on MITRE demonstrative examples for CSRF vulnerabilities
 */
export const cwe352ProfileUpdate: Exercise = {
  cweId: 'CWE-352',
  name: 'Cross-Site Request Forgery - Profile Update',

  vulnerableFunction: `app.post('/api/profile', authenticateUser, (req, res) => {
  const { email, firstName, lastName } = req.body;
  const userId = req.user.id;

  // Update user profile
  const query = 'UPDATE users SET email = ?, first_name = ?, last_name = ? WHERE id = ?';
  db.query(query, [email, firstName, lastName, userId], (err, result) => {
    if (err) return res.status(500).json({ error: 'Update failed' });
    res.json({ message: 'Profile updated successfully' });
  });
});`,

  vulnerableLine: `app.post('/api/profile', authenticateUser, (req, res) => {`,

  options: [
    {
      code: `const csrf = require('csurf'); const csrfProtection = csrf({ cookie: true }); app.post('/api/profile', authenticateUser, csrfProtection, (req, res) => {`,
      correct: true,
      explanation: `Correct! CSRF tokens ensure that requests originate from the legitimate application. The token is generated server-side and must be included in the request. Attackers cannot forge requests without access to the victim's valid token, preventing unauthorized profile changes.`
    },
    {
      code: `app.post('/api/profile', (req, res) => { if (!req.session.username) { return res.status(401).json({ error: 'Not authenticated' }); }`,
      correct: false,
      explanation: 'Direct from MITRE: Session validation alone cannot prevent CSRF since attackers forge requests through the user\'s browser within existing authenticated sessions. The browser automatically includes session cookies.'
    },
    {
      code: `app.post('/api/profile', authenticateUser, (req, res) => { if (req.headers.referer && !req.headers.referer.includes('trusted-domain.com')) { return res.status(403).json({ error: 'Invalid referer' }); }`,
      correct: false,
      explanation: 'Referer header validation is unreliable as it can be spoofed by attackers or blocked by privacy tools. Many legitimate users may have referer headers stripped by proxies or browser settings.'
    },
    {
      code: `app.post('/api/profile', authenticateUser, (req, res) => { const userAgent = req.headers['user-agent']; if (!userAgent || userAgent.includes('bot')) { return res.status(403).json({ error: 'Invalid request' }); }`,
      correct: false,
      explanation: 'User-Agent validation is ineffective against CSRF as attackers can easily forge this header and legitimate browsers will send requests with proper user-agent strings.'
    },
    {
      code: `app.post('/api/profile', authenticateUser, (req, res) => { if (req.ip !== req.user.lastLoginIP) { return res.status(403).json({ error: 'IP mismatch' }); }`,
      correct: false,
      explanation: 'IP address validation breaks legitimate usage (mobile users, shared networks) and does not prevent CSRF as the malicious request comes from the victim\'s IP address.'
    },
    {
      code: `app.post('/api/profile', authenticateUser, (req, res) => { const timestamp = req.headers['x-timestamp']; if (!timestamp || Math.abs(Date.now() - parseInt(timestamp)) > 300000) { return res.status(403).json({ error: 'Request expired' }); }`,
      correct: false,
      explanation: 'Timestamp validation does not prevent CSRF attacks as malicious sites can generate fresh timestamps. This approach may also break legitimate requests due to clock skew.'
    },
    {
      code: `app.post('/api/profile', authenticateUser, (req, res) => { if (!req.headers['x-requested-with'] || req.headers['x-requested-with'] !== 'XMLHttpRequest') { return res.status(403).json({ error: 'Invalid request type' }); }`,
      correct: false,
      explanation: 'X-Requested-With header checking provides some protection but can be bypassed and is not as robust as proper CSRF tokens. Modern browsers may not always include this header.'
    },
    {
      code: `app.post('/api/profile', authenticateUser, (req, res) => { const origin = req.headers.origin; if (!origin || !['https://app.example.com', 'https://mobile.example.com'].includes(origin)) { return res.status(403).json({ error: 'Invalid origin' }); }`,
      correct: false,
      explanation: 'Origin header validation helps but can be bypassed in some browsers and does not provide the same level of protection as cryptographic CSRF tokens that are unique per session.'
    },
    {
      code: `app.post('/api/profile', authenticateUser, (req, res) => { if (!req.body.confirmUpdate || req.body.confirmUpdate !== 'true') { return res.status(400).json({ error: 'Confirmation required' }); }`,
      correct: false,
      explanation: 'Simple confirmation flags can be easily included in malicious requests and do not provide cryptographic proof that the request originated from the legitimate application.'
    },
    {
      code: `app.post('/api/profile', authenticateUser, (req, res) => { if (req.method !== 'POST') { return res.status(405).json({ error: 'Method not allowed' }); }`,
      correct: false,
      explanation: 'HTTP method validation is standard practice but does not prevent CSRF attacks, as malicious sites can easily create POST requests using forms or JavaScript.'
    }
  ]
}