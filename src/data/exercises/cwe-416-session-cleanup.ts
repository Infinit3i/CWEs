import type { Exercise } from '@/data/exercises'

export const cwe416SessionCleanup: Exercise = {
  cweId: 'CWE-416',
  name: 'Use After Free - Session Resource Management',

  vulnerableFunction: `function handleUserSession(sessionId, action) {
  let sessionData = getSessionData(sessionId);

  switch (action) {
    case 'logout':
      cleanupUserSession(sessionData);
      deallocateSessionData(sessionData);
      break;

    case 'refresh':
      updateLastActivity(sessionData);
      break;

    case 'timeout':
      if (isSessionExpired(sessionData)) {
        deallocateSessionData(sessionData);
      }
      break;
  }

  // Log final session state for audit
  auditLog('Session operation completed', sessionData);

  return { status: 'success', sessionId };
}`,

  vulnerableLine: `auditLog('Session operation completed', sessionData);`,

  options: [
    {
      code: `let sessionValid = true; /* track in switch */ if (sessionValid) { auditLog('Session operation completed', sessionData); }`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `auditLog('Session operation completed', sessionData);`,
      correct: false,
Use after free causes crashes'
    },
    {
      code: `if (action !== "logout" && action !== "timeout") { auditLog('Session operation completed', sessionData); }`,
      correct: false,
      explanation: 'Incomplete check misses expired sessions in timeout case. When session expires and gets deallocated, audit logging still occurs with freed memory.'
    },
    {
      code: `auditLog('Session operation completed', { sessionId, action });`,
      correct: false,
      explanation: 'Logging different data avoids use-after-free but loses valuable session state information needed for comprehensive security auditing.'
    },
    {
      code: `try { auditLog('Session operation completed', sessionData); } catch(e) { auditLog('Session logging failed'); }`,
      correct: false,
      explanation: 'Try-catch cannot prevent vulnerability'
    },
    {
      code: `if (sessionData !== null) { auditLog('Session operation completed', sessionData); }`,
      correct: false,
      explanation: 'Null check insufficient for freed memory. Deallocated session pointers often retain their reference value while pointing to invalid memory.'
    },
    {
      code: `sessionData = getSessionData(sessionId); auditLog('Session operation completed', sessionData);`,
      correct: false,
      explanation: 'Re-fetching session after potential deallocation may return null or different session data, producing inaccurate audit logs of the actual operation performed.'
    },
    {
      code: `const sessionCopy = {...sessionData}; auditLog('Session operation completed', sessionCopy);`,
      correct: false,
      explanation: 'Copying before switch statement works but creates performance overhead. Better to track validity and avoid copying data that might be freed.'
    },
    {
      code: `if (typeof sessionData === "object") { auditLog('Session operation completed', sessionData); }`,
      correct: false,
      explanation: 'Type checking does not detect freed memory. Freed session objects remain object type references pointing to invalid/reallocated memory.'
    },
    {
      code: `setTimeout(() => auditLog('Session completed', sessionData), 0);`,
      correct: false,
      explanation: 'Delayed logging does not solve use-after-free. Session data remains freed and may be reallocated, making delayed access even more dangerous.'
    }
  ]
}