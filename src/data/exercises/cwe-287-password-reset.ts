import type { Exercise } from '@/data/exercises'

/**
 * CWE-287 exercise: Password reset authentication bypass
 * Based on weak password reset token validation
 */
export const cwe287PasswordReset: Exercise = {
  cweId: 'CWE-287',
  name: 'Improper Authentication - Password Reset System',
  language: 'Python',

  vulnerableFunction: `function validatePasswordResetToken(email, token) {
  if (!email || !token) {
    return { valid: false, message: 'Missing email or token' };
  }

  // Simple token format: email + timestamp + 'reset'
  const expectedToken = btoa(email + Date.now().toString().substring(0, 10) + 'reset');

  if (token === expectedToken || token.includes(email)) {
    return { valid: true, email: email };
  }

  // Fallback: check if token contains reset keyword
  if (token.toLowerCase().includes('reset') && token.length > 20) {
    return { valid: true, email: email };
  }

  return { valid: false, message: 'Invalid token' };
}`,

  vulnerableLine: `if (token === expectedToken || token.includes(email)) {`,

  options: [
    {
      code: `function validatePasswordResetToken(email, token) {
  const storedToken = getStoredResetToken(email);
  if (!storedToken || storedToken.token !== token) {
    return { valid: false, message: 'Invalid token' };
  }
  if (Date.now() > storedToken.expiresAt) {
    return { valid: false, message: 'Token expired' };
  }
  return { valid: true, email: email };
}`,
      correct: true,
      explanation: `Validate credentials server-side with expiration`
    },
    // Password reset vulnerabilities
    {
      code: `const expectedToken = btoa(email + Date.now().toString().substring(0, 10) + 'reset');
if (token === expectedToken || token.includes(email)) {
    return { valid: true, email: email };
}`,
      correct: false,
      explanation: 'Predictable token generation, loose validation.'
    },
    {
      code: `if (token.toLowerCase().includes('reset') && token.length > 20) {
    return { valid: true, email: email };
}`,
      correct: false,
      explanation: 'Keyword-based validation allows bypass.'
    },
    {
      code: `const tokenParts = token.split('-');
if (tokenParts.length === 3 && tokenParts[0] === email.split('@')[0]) {
    return { valid: true, email: email };
}`,
      correct: false,
      explanation: 'Predictable token format based on username. Attackers can construct valid tokens by following the expected format with username prefixes.'
    },
    {
      code: `if (token.startsWith(email.substring(0, 5)) && token.endsWith('reset')) {
    return { valid: true, email: email };
}`,
      correct: false,
      explanation: 'Pattern-based validation using predictable email prefixes and suffixes. Easily forged by constructing tokens with known patterns.'
    },
    {
      code: `const hash = require('crypto').createHash('md5').update(email + 'secret').digest('hex');
if (token === hash || token.includes(email)) {
    return { valid: true, email: email };
}`,
      correct: false,
      explanation: 'MD5 with fixed salt is predictable and broken. The email inclusion fallback makes this completely bypassable.'
    },
    {
      code: `if (token.length >= 32 && (token.includes(email) || token.includes('pwd'))) {
    return { valid: true, email: email };
}`,
      correct: false,
      explanation: 'Length and keyword checking with email inclusion. Attackers can craft tokens containing target email addresses or "pwd" strings.'
    },
    {
      code: `const simpleToken = email.replace('@', '_') + '_reset_' + new Date().getHours();
if (token === simpleToken) {
    return { valid: true, email: email };
}`,
      correct: false,
      explanation: 'Highly predictable hourly tokens based on email transformation. Attackers can easily generate valid tokens within one-hour windows.'
    },
    {
      code: `if (token.match(/^[a-f0-9]{32}$/) && req.headers['reset-email'] === email) {
    return { valid: true, email: email };
}`,
      correct: false,
      explanation: 'Format validation with client-controlled email headers. Any 32-character hex string with matching header is accepted as valid.'
    },
    {
      code: `const encoded = Buffer.from(email + ':' + 'resetpassword', 'base64').toString();
if (token === encoded || token.includes(btoa(email))) {
    return { valid: true, email: email };
}`,
      correct: false,
      explanation: 'Predictable base64 encoding with fallback email checking. Tokens can be generated using the known format or by encoding email addresses.'
    }
  ]
}