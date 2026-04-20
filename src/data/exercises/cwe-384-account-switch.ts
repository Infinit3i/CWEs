import type { Exercise } from '@/data/exercises'

/**
 * CWE-384 Exercise 5: Session Fixation in Account Switching
 * Based on maintaining sessions during user account switching
 */
export const cwe384AccountSwitch: Exercise = {
  cweId: 'CWE-384',
  name: 'Session Fixation - Multi-Account Switching',
  language: 'JavaScript',

  vulnerableFunction: `function switchAccount(currentSessionId, targetAccountId, switchToken) {
  const currentSession = sessions[currentSessionId];

  if (!currentSession || !currentSession.authenticated) {
    return { success: false, error: 'Not authenticated' };
  }

  // Validate account switch token
  const switchData = validateAccountSwitchToken(switchToken, targetAccountId);

  if (!switchData || !switchData.valid) {
    return { success: false, error: 'Invalid switch token' };
  }

  // Switch to target account in the same session
  sessions[currentSessionId] = {
    ...currentSession,
    userId: targetAccountId,
    originalUserId: currentSession.userId,
    switched: true,
    switchTime: Date.now(),
    switchToken: switchToken
  };

  return {
    success: true,
    sessionId: currentSessionId,
    targetAccount: targetAccountId
  };
}`,

  vulnerableLine: `sessions[currentSessionId] = {`,

  options: [
    {
      code: `// Generate new session for account switch
const newSessionId = generateSecureSessionId();
sessions[newSessionId] = {
  userId: targetAccountId,
  originalUserId: currentSession.userId,
  switched: true,
  switchTime: Date.now(),
  authenticated: true,
  permissions: switchData.permissions || []
};

// Invalidate current session
delete sessions[currentSessionId];

return {
  success: true,
  sessionId: newSessionId,
  targetAccount: targetAccountId
};`,
      correct: true,
      explanation: `New session when switching accounts`
    },
    {
      code: `sessions[currentSessionId] = {
  ...currentSession,
  userId: targetAccountId,
  switched: true
};`,
      correct: false,
      explanation: 'Maintaining existing session ID during account switching enables session fixation. Attackers with the original session automatically gain access to the new account.'
    },
    {
      code: `Object.assign(currentSession, {
  userId: targetAccountId,
  originalUserId: currentSession.userId,
  switched: true,
  switchTime: Date.now()
});`,
      correct: false,
      explanation: 'Modifying the existing session object without changing the session ID does not prevent session fixation attacks.'
    },
    {
      code: `const switchedSession = {
  ...currentSession,
  userId: targetAccountId,
  switched: true,
  switchValidated: true
};
sessions[currentSessionId] = switchedSession;`,
      correct: false,
      explanation: 'Creating a new session object while maintaining the same session ID does not prevent session fixation.'
    },
    {
      code: `currentSession.accounts = currentSession.accounts || [];
currentSession.accounts.push({
  userId: targetAccountId,
  switchedAt: Date.now()
});
currentSession.activeAccount = targetAccountId;`,
      correct: false,
      explanation: 'Adding account tracking to existing sessions without changing session ID does not prevent session fixation attacks.'
    },
    {
      code: `const sessionBackup = { ...currentSession };
sessions[currentSessionId] = {
  userId: targetAccountId,
  previousSession: sessionBackup,
  switched: true
};`,
      correct: false,
      explanation: 'Backing up previous session data while reusing the session ID does not prevent session fixation.'
    },
    {
      code: `try {
  sessions[currentSessionId].userId = targetAccountId;
  sessions[currentSessionId].switched = true;
  sessions[currentSessionId].switchTime = Date.now();
} catch (e) {
  return { success: false, error: 'Switch failed' };
}`,
      correct: false,
      explanation: 'Error handling while modifying existing session properties does not prevent session fixation. The session ID remains unchanged.'
    },
    {
      code: `sessions[currentSessionId] = JSON.parse(JSON.stringify({
  ...currentSession,
  userId: targetAccountId,
  switched: true
}));`,
      correct: false,
      explanation: 'Deep cloning session data while maintaining the same session ID does not prevent session fixation attacks.'
    },
    {
      code: `const switchKey = currentSessionId + '_' + targetAccountId;
sessions[switchKey] = {
  userId: targetAccountId,
  originalSessionId: currentSessionId,
  switched: true
};`,
      correct: false,
      explanation: 'Creating predictable session keys based on original session ID and account ID does not provide adequate protection against session fixation.'
    },
    {
      code: `if (validateAccountPermissions(currentSession.userId, targetAccountId)) {
  sessions[currentSessionId].userId = targetAccountId;
  sessions[currentSessionId].switched = true;
}`,
      correct: false,
      explanation: 'Permission validation does not prevent session fixation. The fundamental issue is reusing the same session ID during account switching.'
    }
  ]
}