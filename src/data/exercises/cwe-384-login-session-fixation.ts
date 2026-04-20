import type { Exercise } from '@/data/exercises'

/**
 * CWE-384 Exercise 1: Session Fixation in Login Handler
 * Based on MITRE Java demonstrative example for session fixation
 */
export const cwe384LoginSessionFixation: Exercise = {
  cweId: 'CWE-384',
  name: 'Session Fixation - User Login Handler',
  language: 'JavaScript',

  vulnerableFunction: `function authenticateUser(username, password, sessionId) {
  // Validate user credentials
  const user = validateCredentials(username, password);

  if (user) {
    // Store user information in the existing session
    sessions[sessionId] = {
      userId: user.id,
      username: user.username,
      role: user.role,
      loginTime: Date.now(),
      authenticated: true
    };

    return {
      success: true,
      sessionId: sessionId,
      user: user
    };
  }

  return { success: false, error: 'Invalid credentials' };
}`,

  vulnerableLine: `sessions[sessionId] = {`,

  options: [
    {
      code: `// Generate new session ID after successful authentication
const newSessionId = generateSecureSessionId();
sessions[newSessionId] = {
  userId: user.id,
  username: user.username,
  role: user.role,
  loginTime: Date.now(),
  authenticated: true
};

// Invalidate old session if it exists
if (sessions[sessionId]) {
  delete sessions[sessionId];
}

return {
  success: true,
  sessionId: newSessionId,
  user: user
};`,
      correct: true,
      explanation: `Generate new session after login`
    },
    {
      code: `sessions[sessionId] = {
  userId: user.id,
  username: user.username,
  authenticated: true
};`,
      correct: false,
      explanation: 'Reusing existing session IDs after authentication enables session fixation. Attackers can force a known session ID, then hijack the session after victim login.'
    },
    {
      code: `if (sessions[sessionId]) {
  sessions[sessionId].userId = user.id;
  sessions[sessionId].authenticated = true;
} else {
  sessions[sessionId] = { userId: user.id, authenticated: true };
}`,
      correct: false,
      explanation: 'Modifying existing sessions without changing the session ID still allows session fixation attacks.'
    },
    {
      code: `Object.assign(sessions[sessionId] || {}, {
  userId: user.id,
  authenticated: true
});`,
      correct: false,
      explanation: 'Using Object.assign with existing session data does not prevent session fixation - the session ID remains the same.'
    },
    {
      code: `sessions[sessionId + '_auth'] = {
  userId: user.id,
  authenticated: true
};`,
      correct: false,
      explanation: 'Modifying the session key while keeping the original ID does not prevent session fixation. The attacker still knows the base session ID.'
    },
    {
      code: `if (!sessions[sessionId]) {
  sessions[sessionId] = {};
}
sessions[sessionId].userId = user.id;
sessions[sessionId].authenticated = true;`,
      correct: false,
      explanation: 'Creating empty sessions and then populating them does not prevent session fixation. The session ID is still predictable and reused.'
    },
    {
      code: `const sessionData = sessions[sessionId] || {};
sessionData.userId = user.id;
sessionData.authenticated = true;
sessions[sessionId] = sessionData;`,
      correct: false,
      explanation: 'Retrieving and updating session data without changing the session ID does not prevent session fixation attacks.'
    },
    {
      code: `try {
  sessions[sessionId] = {
    userId: user.id,
    authenticated: true,
    timestamp: Date.now()
  };
} catch (e) {
  return { success: false, error: 'Session error' };
}`,
      correct: false,
      explanation: 'Error handling and timestamps do not prevent session fixation. The fundamental issue is reusing the same session ID.'
    },
    {
      code: `sessions[sessionId] = Object.freeze({
  userId: user.id,
  authenticated: true
});`,
      correct: false,
      explanation: 'Freezing session objects does not prevent session fixation. The session ID is still reused and can be hijacked.'
    },
    {
      code: `if (sessionId && sessionId.length > 10) {
  sessions[sessionId] = {
    userId: user.id,
    authenticated: true
  };
}`,
      correct: false,
      explanation: 'Session ID length validation does not prevent session fixation. Attackers can generate session IDs of any required length.'
    }
  ]
}