import type { Exercise } from '@/data/exercises'

/**
 * CWE-384 Exercise 3: Session Fixation in Password Reset
 * Based on maintaining session during security-sensitive operations
 */
export const cwe384PasswordReset: Exercise = {
  cweId: 'CWE-384',
  name: 'Session Fixation - Password Reset Completion',

  vulnerableFunction: `function completePasswordReset(resetToken, newPassword, sessionId) {
  // Validate the password reset token
  const resetData = validateResetToken(resetToken);

  if (!resetData || resetData.expired) {
    return { success: false, error: 'Invalid or expired reset token' };
  }

  // Update user password
  const userId = resetData.userId;
  updateUserPassword(userId, newPassword);

  // Automatically log the user in with existing session
  sessions[sessionId] = {
    userId: userId,
    username: resetData.username,
    role: resetData.role || 'user',
    authenticated: true,
    passwordResetAt: Date.now(),
    autoLoggedIn: true
  };

  return {
    success: true,
    message: 'Password reset successful',
    sessionId: sessionId
  };
}`,

  vulnerableLine: `sessions[sessionId] = {`,

  options: [
    {
      code: `// Generate new secure session after password reset
const newSessionId = generateSecureSessionId();
sessions[newSessionId] = {
  userId: userId,
  username: resetData.username,
  role: resetData.role || 'user',
  authenticated: true,
  passwordResetAt: Date.now(),
  autoLoggedIn: true
};

// Invalidate all existing sessions for this user
invalidateAllUserSessions(userId);

return {
  success: true,
  message: 'Password reset successful',
  sessionId: newSessionId
};`,
      correct: true,
      explanation: `Create new session after password reset`
    },
    {
      code: `sessions[sessionId] = {
  userId: userId,
  authenticated: true,
  passwordResetAt: Date.now()
};`,
      correct: false,
      explanation: 'Using existing session ID after password reset enables session fixation. Attackers can force a session, trigger password reset, then access the account with known session ID.'
    },
    {
      code: `if (sessions[sessionId]) {
  Object.assign(sessions[sessionId], {
    userId: userId,
    authenticated: true,
    passwordResetAt: Date.now()
  });
} else {
  sessions[sessionId] = { userId: userId, authenticated: true };
}`,
      correct: false,
      explanation: 'Modifying existing sessions or creating new ones with the same ID does not prevent session fixation attacks.'
    },
    {
      code: `const sessionData = {
  userId: userId,
  authenticated: true,
  passwordResetAt: Date.now(),
  secure: true
};
sessions[sessionId] = Object.freeze(sessionData);`,
      correct: false,
      explanation: 'Freezing session objects does not prevent session fixation. The fundamental issue is reusing the predictable session ID.'
    },
    {
      code: `sessions[sessionId] = {
  userId: userId,
  authenticated: true,
  sessionType: 'password-reset',
  timestamp: Date.now()
};`,
      correct: false,
      explanation: 'Adding metadata like session type does not prevent session fixation. The session ID is still reused and vulnerable.'
    },
    {
      code: `try {
  const existingSession = sessions[sessionId] || {};
  sessions[sessionId] = {
    ...existingSession,
    userId: userId,
    authenticated: true,
    passwordResetAt: Date.now()
  };
} catch (e) {
  return { success: false, error: 'Session error' };
}`,
      correct: false,
      explanation: 'Error handling and merging with existing session data does not prevent session fixation. The session ID remains predictable.'
    },
    {
      code: `if (sessionId && sessionId.length >= 32) {
  sessions[sessionId] = {
    userId: userId,
    authenticated: true,
    validated: true
  };
}`,
      correct: false,
      explanation: 'Session ID length validation does not prevent session fixation. Attackers can generate IDs of any required length.'
    },
    {
      code: `const sessionKey = hash(sessionId + resetToken);
sessions[sessionKey] = {
  userId: userId,
  authenticated: true,
  passwordResetAt: Date.now()
};`,
      correct: false,
      explanation: 'Hashing the session ID with the reset token is better but still not ideal. It\'s better to generate a completely new random session ID.'
    },
    {
      code: `sessions[sessionId] = {
  userId: userId,
  authenticated: true,
  tempSession: true,
  expiresAt: Date.now() + 3600000 // 1 hour
};`,
      correct: false,
      explanation: 'Adding expiration to sessions does not prevent session fixation. The session ID is still reused and can be hijacked before expiration.'
    },
    {
      code: `delete sessions[sessionId]; // Clear existing
sessions[sessionId] = {
  userId: userId,
  authenticated: true,
  resetComplete: true
};`,
      correct: false,
      explanation: 'Deleting and recreating with the same ID does not prevent session fixation. The attacker still knows the session ID.'
    }
  ]
}