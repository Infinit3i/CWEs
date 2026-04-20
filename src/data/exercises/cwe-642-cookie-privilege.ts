import type { Exercise } from '@/data/exercises'

/**
 * CWE-642: External Control of Critical State Data - Cookie-Based Privilege Escalation
 * Based on MITRE pattern where authentication state is stored in client-controlled cookies
 */
export const cwe642CookiePrivilege: Exercise = {
  cweId: 'CWE-642',
  name: 'External Control of Critical State Data - Cookie Authentication',
  language: 'PHP',

  vulnerableFunction: `function checkAdminAccess(request) {
  const cookies = parseCookies(request.headers.cookie);

  if (cookies.authenticated === 'true') {
    // User is authenticated
    if (cookies.role === 'admin') {
      return {
        isAdmin: true,
        allowedActions: ['read', 'write', 'delete', 'manage_users']
      };
    }

    return {
      isAdmin: false,
      allowedActions: ['read']
    };
  }

  return {
    isAdmin: false,
    allowedActions: []
  };
}`,

  vulnerableLine: `if (cookies.role === 'admin') {`,

  options: [
    {
      code: `const serverRole = getUserRoleFromDatabase(cookies.sessionId); if (serverRole === 'admin') {`,
      correct: true,
      explanation: `Get role from database not cookies`
    },
    {
      code: `if (cookies.role === 'admin') { // Trust client cookie`,
      correct: false,
      explanation: 'Direct MITRE vulnerability pattern. Trusting client-provided role information allows attackers to set cookies.role=admin and immediately gain administrative privileges without authentication.'
    },
    {
      code: `if (cookies.role === 'admin' && cookies.authenticated === 'true') {`,
      correct: false,
      explanation: 'Adds authentication check but still trusts client-controlled role. Authenticated users can set their own role to admin, bypassing authorization controls through cookie manipulation.'
    },
    {
      code: `const encodedRole = btoa(cookies.role); if (encodedRole === btoa('admin')) {`,
      correct: false,
      explanation: 'Base64 encoding provides no security benefit for client data. Attackers can easily encode \'admin\' and set the cookie, as encoding is not encryption or validation.'
    },
    {
      code: `if (cookies.role && cookies.role.toLowerCase() === 'admin') {`,
      correct: false,
      explanation: 'Case normalization doesn\'t address the core trust issue. Attackers can still set role cookies to \'admin\', \'ADMIN\', or \'Admin\' to gain unauthorized privileges.'
    },
    {
      code: `const hashedRole = md5(cookies.role); if (hashedRole === md5('admin')) {`,
      correct: false,
      explanation: 'MD5 hashing of client data provides no protection. Attackers can hash \'admin\' and set the resulting hash value in their cookies to bypass this check.'
    },
    {
      code: `if (cookies.role === 'admin' && cookies.sessionStart && Date.now() - cookies.sessionStart < 3600000) {`,
      correct: false,
      explanation: 'Time validation but still trusts client role data. Attackers can set both role=admin and a valid timestamp to gain admin privileges within the time window.'
    },
    {
      code: `const roles = cookies.role.split(','); if (roles.includes('admin')) {`,
      correct: false,
      explanation: 'Multi-role parsing still trusts client data. Attackers can set role=user,admin or any comma-separated list containing admin to gain unauthorized privileges.'
    },
    {
      code: `if (cookies.role === 'admin' && validateCookieSignature(cookies)) {`,
      correct: false,
      explanation: 'Signature validation helps but the example doesn\'t show actual signature implementation. If signature validation is missing or weak, attackers can still manipulate role data.'
    },
    {
      code: `if (cookies.userType === 'premium' && cookies.role === 'admin') {`,
      correct: false,
      explanation: 'Multiple client-controlled conditions increase attack surface. Attackers can set both userType=premium and role=admin to meet both requirements from client-side manipulation.'
    }
  ]
}