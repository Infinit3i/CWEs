import type { Exercise } from '@/data/exercises'

/**
 * CWE-287 exercise: API token validation bypass
 * Based on authentication weaknesses in API authorization
 */
export const cwe287ApiToken: Exercise = {
  cweId: 'CWE-287',
  name: 'Improper Authentication - API Token Validation',

  vulnerableFunction: `function validateAPIRequest(req) {
  const token = req.headers['authorization'];
  const userRole = req.headers['x-user-role'];

  if (token && token.startsWith('Bearer ')) {
    const tokenValue = token.substring(7);
    if (tokenValue.length > 0 && userRole === 'admin') {
      return { authenticated: true, role: 'admin' };
    }
    if (tokenValue.length > 0) {
      return { authenticated: true, role: 'user' };
    }
  }
  return { authenticated: false };
}`,

  vulnerableLine: `if (tokenValue.length > 0 && userRole === 'admin') {`,

  options: [
    {
      code: `function validateAPIRequest(req) {
  const token = req.headers['authorization'];
  if (token && token.startsWith('Bearer ')) {
    const payload = verifyJWTSignature(token.substring(7));
    return payload ? { authenticated: true, role: payload.role } : { authenticated: false };
  }
  return { authenticated: false };
}`,
      correct: true,
      explanation: `Validate credentials server-side with expiration`
    },
    // Authentication bypass vulnerabilities
    {
      code: `const userRole = req.headers['x-user-role'];
if (tokenValue.length > 0 && userRole === 'admin') {
    return { authenticated: true, role: 'admin' };
}`,
      correct: false,
      explanation: 'Client-controlled role headers allow privilege escalation.'
    },
    {
      code: `if (tokenValue && req.headers['x-authenticated'] === 'true') {
    const role = req.headers['x-role'] || 'user';
    return { authenticated: true, role: role };
}`,
      correct: false,
      explanation: 'Multiple client-controlled headers bypass authentication.'
    },
    {
      code: `if (tokenValue.includes('admin') || req.headers['admin-flag'] === '1') {
    return { authenticated: true, role: 'admin' };
}`,
      correct: false,
      explanation: 'String matching and client flags create bypass vectors.'
    },
    {
      code: `const decoded = Buffer.from(tokenValue, 'base64').toString();
if (JSON.parse(decoded).role === 'admin') {
    return { authenticated: true, role: 'admin' };
}`,
      correct: false,
      explanation: 'Base64 decoding without signature verification allows forgery.'
    },
    {
      code: `if (tokenValue.length >= 32 && req.headers['user-type'] === 'administrator') {
    return { authenticated: true, role: 'admin' };
}`,
      correct: false,
      explanation: 'Length-based token validation with client-controlled type headers provides no real security. Any 32+ character string with the right header grants access.'
    },
    {
      code: `if (req.session && req.session.user && req.session.user.isAdmin) {
    return { authenticated: true, role: 'admin' };
}`,
      correct: false,
      explanation: 'Session-based authentication without proper server-side session validation. If session data is client-manipulable, this fails like cookie-based auth.'
    },
    {
      code: `const apiKey = req.headers['x-api-key'];
if (apiKey && apiKey === process.env.API_SECRET && userRole === 'admin') {
    return { authenticated: true, role: 'admin' };
}`,
      correct: false,
      explanation: 'Even with valid API key verification, trusting client-provided role headers allows privilege escalation through header manipulation.'
    },
    {
      code: `if (tokenValue.startsWith('sk-') && req.headers['privilege-level'] === '99') {
    return { authenticated: true, role: 'admin' };
}`,
      correct: false,
      explanation: 'Prefix-based token format checking with client-controlled privilege levels. Attackers can craft tokens with the right prefix and set privilege headers.'
    },
    {
      code: `const userClaims = req.headers['user-claims'];
if (tokenValue.length > 20 && userClaims && JSON.parse(userClaims).admin) {
    return { authenticated: true, role: 'admin' };
}`,
      correct: false,
      explanation: 'Client-provided claims headers allow complete authentication bypass. Attackers can send any JSON claims structure to gain desired privileges.'
    }
  ]
}