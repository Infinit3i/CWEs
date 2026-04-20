import type { Exercise } from '@/data/exercises'

/**
 * CWE-862 exercise - Admin Panel Access
 * Based on MITRE patterns for missing privilege escalation protection
 */
export const cwe862AdminPanel: Exercise = {
  cweId: 'CWE-862',
  name: 'Missing Authorization - Admin Panel Access',

  vulnerableFunction: `app.get('/admin/dashboard', authenticateUser, (req, res) => {
  // Render admin dashboard with sensitive data
  const systemStats = {
    totalUsers: getUserCount(),
    serverMetrics: getServerMetrics(),
    apiKeys: getAllAPIKeys(),
    configSettings: getSystemConfig()
  };

  res.render('admin/dashboard', { stats: systemStats });
});`,

  vulnerableLine: `app.get('/admin/dashboard', authenticateUser, (req, res) => {`,

  options: [
    {
      code: `app.get('/admin/dashboard', authenticateUser, authorizeAdmin, (req, res) => { // Additional middleware function: function authorizeAdmin(req, res, next) { if (!req.user.isAdmin && !req.user.roles.includes('administrator')) { return res.status(403).json({ error: 'Admin access required' }); } next(); }`,
      correct: true,
      explanation: `Check user permissions before access`
    },
    {
      code: `if (!session_is_registered("username")) { echo "invalid session detected!"; exit; } display_admin_panel();`,
      correct: false,
      explanation: 'Authentication-only protection allows any authenticated user to access admin functionality, exposing "API keys," "database files," and administrative controls to unauthorized users.'
    },
    {
      code: `if (req.user && req.user.id) { // User is authenticated, show admin dashboard const systemStats = getAllSystemData(); }`,
      correct: false,
      explanation: 'MITRE vulnerability: Basic authentication without role validation allows any logged-in user to access administrative interfaces by directly navigating to admin URLs.'
    },
    {
      code: `if (req.headers.authorization && req.headers.authorization.startsWith(\'Bearer \')) { // Valid token, allow admin access }`,
      correct: false,
      explanation: 'Token presence validation confirms authentication but provides no authorization control to determine if the user should have administrative privileges.'
    },
    {
      code: `if (req.user.accountStatus === \'verified\') { // Account is verified, allow admin panel access }`,
      correct: false,
      explanation: 'Account verification status is an authentication attribute but does not indicate administrative privileges. Verified regular users should not access admin functions.'
    },
    {
      code: `if (req.sessionID && req.session.userId) { // Valid session exists, show admin dashboard }`,
      correct: false,
      explanation: 'Session validation confirms user authentication but implements no authorization logic to ensure only users with admin privileges can access administrative functions.'
    },
    {
      code: `if (req.user.emailDomain === \'company.com\') { // Internal email domain, allow admin access }`,
      correct: false,
      explanation: 'Email domain checking is insufficient for authorization. Not all company employees should have admin access, and this can be easily spoofed or compromised.'
    },
    {
      code: `if (Date.now() - req.user.createdAt > 86400000) { // Account older than 24 hours, allow admin access }`,
      correct: false,
      explanation: 'Account age checking has no relationship to administrative privileges. Older accounts do not automatically deserve admin access to sensitive system functions.'
    },
    {
      code: `if (req.ip.startsWith(\'192.168.\') || req.ip.startsWith(\'10.\')) { // Internal IP, allow admin access }`,
      correct: false,
      explanation: 'IP-based validation is easily bypassed and does not provide proper authorization. Internal network access should not automatically grant administrative privileges.'
    },
    {
      code: `if (req.user.loginCount > 5) { // Frequent user, probably admin, allow access }`,
      correct: false,
      explanation: 'Login frequency has no correlation with administrative privileges. High usage does not indicate a user should have access to sensitive admin functions and API keys.'
    }
  ]
}