import type { Exercise } from '@/data/exercises'

/**
 * CWE-642: External Control of Critical State Data - Session Timeout Control
 * Client-controlled session expiration allowing extended access
 */
export const cwe642SessionTimeout: Exercise = {
  cweId: 'CWE-642',
  name: 'External Control of Critical State Data - Session Management',

  vulnerableFunction: `function validateSessionAccess(request) {
  const sessionData = request.cookies.sessionData ?
    JSON.parse(request.cookies.sessionData) : null;

  if (!sessionData) {
    return { valid: false, reason: 'No session' };
  }

  const currentTime = Date.now();
  const sessionAge = currentTime - sessionData.startTime;

  // Check session timeout from client data
  if (sessionAge > sessionData.maxAge) {
    return { valid: false, reason: 'Session expired' };
  }

  // Check if session is still active
  if (sessionData.lastActivity &&
      (currentTime - sessionData.lastActivity) > sessionData.inactivityTimeout) {
    return { valid: false, reason: 'Session inactive' };
  }

  return { valid: true, userId: sessionData.userId };
}`,

  vulnerableLine: `if (sessionAge > sessionData.maxAge) {`,

  options: [
    {
      code: `const serverMaxAge = getServerSessionTimeout(); if (sessionAge > serverMaxAge) {`,
      correct: true,
      explanation: `Use server timeout not client setting`
    },
    {
      code: `if (sessionAge > sessionData.maxAge) { // Trust client timeout`,
      correct: false,
      explanation: 'Client sets timeout enabling permanent sessions'
    },
    {
      code: `const cappedMaxAge = Math.min(sessionData.maxAge, 86400000); if (sessionAge > cappedMaxAge) {`,
      correct: false,
      explanation: 'Caps at 24 hours but client controls value'
    },
    {
      code: `if (sessionAge > (sessionData.maxAge || 3600000)) {`,
      correct: false,
      explanation: 'Fallback exists but client value overrides'
    },
    {
      code: `const adjustedMaxAge = sessionData.maxAge * 0.8; if (sessionAge > adjustedMaxAge) {`,
      correct: false,
      explanation: 'Reduces timeout but client sets base value'
    },
    {
      code: `if (sessionData.maxAge < 1800000 && sessionAge > sessionData.maxAge) {`,
      correct: false,
      explanation: 'Short sessions timeout but long ones never expire'
    },
    {
      code: `const hashedMaxAge = crypto.createHash('sha256').update(sessionData.maxAge.toString()).digest('hex'); if (sessionAge > parseInt(hashedMaxAge.substring(0, 8), 16)) {`,
      correct: false,
      explanation: 'Hashing creates arbitrary timeouts'
    },
    {
      code: `if (sessionAge > sessionData.maxAge && sessionData.enforceTimeout !== false) {`,
      correct: false,
      explanation: 'Client can disable timeout enforcement'
    },
    {
      code: `const multiplier = sessionData.userType === 'premium' ? 2 : 1; if (sessionAge > sessionData.maxAge * multiplier) {`,
      correct: false,
      explanation: 'User type and timeout both client-controlled'
    },
    {
      code: `if (sessionAge > sessionData.maxAge) { console.warn('Session timeout from client data'); return { valid: false };`,
      correct: false,
      explanation: 'Warns but still uses client timeout data'
    }
  ]
}