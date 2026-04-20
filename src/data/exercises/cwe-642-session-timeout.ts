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
      explanation: `Correct! Uses server-defined session timeout rather than trusting client-provided values. This prevents attackers from setting arbitrary session durations in their cookies to maintain unauthorized access indefinitely.`
    },
    {
      code: `if (sessionAge > sessionData.maxAge) { // Trust client timeout`,
      correct: false,
      explanation: 'Direct MITRE vulnerability pattern. Trusting client-provided session timeout allows attackers to set maxAge to years or decades, maintaining persistent access beyond intended security policies.'
    },
    {
      code: `const cappedMaxAge = Math.min(sessionData.maxAge, 86400000); if (sessionAge > cappedMaxAge) {`,
      correct: false,
      explanation: 'Caps timeout at 24 hours but still trusts client data. Attackers can set maxAge to the maximum allowed value, extending sessions far beyond typical security requirements.'
    },
    {
      code: `if (sessionAge > (sessionData.maxAge || 3600000)) {`,
      correct: false,
      explanation: 'Provides fallback but primary value is client-controlled. Attackers who provide maxAge values bypass the fallback, allowing extended session durations through cookie manipulation.'
    },
    {
      code: `const adjustedMaxAge = sessionData.maxAge * 0.8; if (sessionAge > adjustedMaxAge) {`,
      correct: false,
      explanation: 'Arbitrary reduction still relies on client data. Attackers can set maxAge to large values where even 80% provides unauthorized extended access beyond security policies.'
    },
    {
      code: `if (sessionData.maxAge < 1800000 && sessionAge > sessionData.maxAge) {`,
      correct: false,
      explanation: 'Only enforces timeout for short sessions but allows unlimited access for longer client-set durations. Sessions with maxAge >= 30 minutes never expire, violating security policies.'
    },
    {
      code: `const hashedMaxAge = crypto.createHash('sha256').update(sessionData.maxAge.toString()).digest('hex'); if (sessionAge > parseInt(hashedMaxAge.substring(0, 8), 16)) {`,
      correct: false,
      explanation: 'Hashing client data creates unpredictable timeouts but doesn\'t solve the trust issue. The timeout becomes arbitrary rather than enforcing actual security policies.'
    },
    {
      code: `if (sessionAge > sessionData.maxAge && sessionData.enforceTimeout !== false) {`,
      correct: false,
      explanation: 'Allows client to disable timeout enforcement entirely through enforceTimeout flag. Attackers can set enforceTimeout=false to bypass any session expiration controls.'
    },
    {
      code: `const multiplier = sessionData.userType === 'premium' ? 2 : 1; if (sessionAge > sessionData.maxAge * multiplier) {`,
      correct: false,
      explanation: 'User type multiplier but both userType and maxAge are client-controlled. Attackers can set userType=premium and high maxAge values for extended unauthorized access.'
    },
    {
      code: `if (sessionAge > sessionData.maxAge) { console.warn('Session timeout from client data'); return { valid: false };`,
      correct: false,
      explanation: 'Logs warning about client control but still uses client data for critical security decision. The fundamental trust boundary violation remains unaddressed.'
    }
  ]
}