import type { Exercise } from '@/data/exercises'

/**
 * CWE-841: Improper Enforcement of Behavioral Workflow - Session Lifecycle Management
 * Session workflow where cleanup steps can be bypassed
 */
export const cwe841SessionLifecycle: Exercise = {
  cweId: 'CWE-841',
  name: 'Improper Enforcement of Behavioral Workflow - Session Management',

  vulnerableFunction: `function manageSession(sessionId, action, userId) {
  const session = getSession(sessionId);

  if (action === 'login') {
    session.authenticated = true;
    session.loginTime = new Date();
    session.userId = userId;
    return 'Login successful';
  }

  if (action === 'logout') {
    session.authenticated = false;
    session.logoutTime = new Date();
    clearSessionData(sessionId);
    return 'Logout successful';
  }

  if (action === 'terminate') {
    removeSession(sessionId);
    return 'Session terminated';
  }

  if (action === 'access_resource') {
    if (!session.authenticated) {
      return 'Authentication required';
    }
    return accessUserData(session.userId);
  }

  return 'Invalid action';
}`,

  vulnerableLine: `if (action === 'terminate') {`,

  options: [
    {
      code: `if (action === 'terminate' && (!session.authenticated || session.logoutTime)) {`,
      correct: true,
      explanation: `Correct! Enforces proper session lifecycle where termination only occurs after logout or for unauthenticated sessions. This prevents premature session cleanup while users are still active, maintaining session integrity.`
    },
    {
      code: `if (action === 'terminate') { // No workflow validation`,
      correct: false,
      explanation: 'MITRE workflow bypass pattern. Sessions can be terminated while users are authenticated and active, causing data loss, transaction interruption, and poor user experience.'
    },
    {
      code: `if (action === 'terminate' && session.userId !== userId) {`,
      correct: false,
      explanation: 'Different user check but no authentication state validation. Sessions can be terminated while original users are still authenticated and actively using the system.'
    },
    {
      code: `if (action === 'terminate' && Date.now() - session.loginTime > 3600000) {`,
      correct: false,
      explanation: 'Time-based termination after 1 hour ignores authentication workflow. Active authenticated sessions can be terminated mid-use, causing data loss and transaction failures.'
    },
    {
      code: `if (action === 'terminate' && session.authenticated === false) {`,
      correct: false,
      explanation: 'Only allows terminating logged-out sessions but creates orphaned authenticated sessions. Prevents cleanup of authenticated sessions that should be properly logged out first.'
    },
    {
      code: `if (action === 'terminate' && session.inactivityTime > 1800000) {`,
      correct: false,
      explanation: 'Inactivity-based termination bypasses proper logout workflow. Sessions can be terminated while users are authenticated but temporarily inactive, violating session lifecycle.'
    },
    {
      code: `if (action === 'terminate') { if (session.authenticated) console.warn('Terminating active session'); removeSession();`,
      correct: false,
      explanation: 'Warns but allows workflow violation. Active authenticated sessions are terminated despite warnings, causing potential data loss without enforcing proper logout sequence.'
    },
    {
      code: `if (action === 'terminate' && (session.authenticated === false || userId === 'admin')) {`,
      correct: false,
      explanation: 'Admin override bypasses session lifecycle workflow. Administrators can terminate any session regardless of authentication state, violating user session integrity.'
    },
    {
      code: `if (action === 'terminate' && session.errorCount > 5) {`,
      correct: false,
      explanation: 'Error-based termination ignores authentication workflow. Sessions with errors can be terminated while users remain authenticated, causing unexpected session loss.'
    },
    {
      code: `if (action === 'terminate' && !session.hasActiveTransactions) {`,
      correct: false,
      explanation: 'Transaction check but no authentication workflow validation. Sessions without transactions can be terminated while users are authenticated, violating proper logout sequence.'
    }
  ]
}