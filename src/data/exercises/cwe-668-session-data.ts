import type { Exercise } from '@/data/exercises'

export const cwe668SessionData: Exercise = {
  cweId: 'CWE-668',
  name: 'Exposure of Resource to Wrong Sphere - Session Management',
  language: 'PHP',

  vulnerableFunction: `function getSessionData(sessionId, requestedField) {
  const sessionStore = require('./sessionStore');

  const session = sessionStore.get(sessionId);

  if (!session) {
    throw new Error('Session not found');
  }

  // Return requested field from session
  return session[requestedField];
}`,

  vulnerableLine: `return session[requestedField];`,

  options: [
    {
      code: `const allowedFields = ['username', 'preferences', 'lastActivity']; if (!allowedFields.includes(requestedField)) throw new Error('Field not accessible'); return session[requestedField];`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `return session[requestedField];`,
      correct: false,
      explanation: 'Unrestricted field access exposes sensitive session data to wrong spheres. Clients could access internal authentication tokens or admin flags.'
    },
    {
      code: `if (requestedField !== 'password') return session[requestedField];`,
      correct: false,
      explanation: 'Blacklisting specific fields is insufficient. Session data may contain other sensitive information like CSRF tokens, internal flags, or encrypted data that should not be exposed.'
    },
    {
      code: `return requestedField.length > 3 ? session[requestedField] : null;`,
      correct: false,
      explanation: 'Field name length validation does not determine sensitivity. This arbitrary restriction fails to protect sensitive short field names like "key" or "jwt".'
    },
    {
      code: `if (typeof session[requestedField] === 'string') return session[requestedField];`,
      correct: false,
      explanation: 'Type-based filtering does not protect sensitive string data. Authentication tokens and secrets are often stored as strings and should not be exposed.'
    },
    {
      code: `return session[requestedField] ? session[requestedField].toString() : null;`,
      correct: false,
      explanation: 'Converting to string does not address the authorization issue. Sensitive data remains exposed regardless of its string representation.'
    },
    {
      code: `const sensitiveFields = ['password', 'token']; return sensitiveFields.includes(requestedField) ? '[REDACTED]' : session[requestedField];`,
      correct: false,
      explanation: 'Limited blacklisting misses many sensitive fields. Session objects may contain various internal data that should not cross sphere boundaries.'
    },
    {
      code: `if (session.hasOwnProperty(requestedField)) return session[requestedField];`,
      correct: false,
      explanation: 'Property existence check does not validate authorization. This still allows access to any existing session property regardless of its sensitivity.'
    }
  ]
}