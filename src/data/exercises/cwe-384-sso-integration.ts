import type { Exercise } from '@/data/exercises'

/**
 * CWE-384 Exercise 4: Session Fixation in SSO Integration
 * Based on maintaining sessions during third-party authentication
 */
export const cwe384SsoIntegration: Exercise = {
  cweId: 'CWE-384',
  name: 'Session Fixation - SSO Authentication Callback',

  vulnerableFunction: `function handleSsoCallback(ssoToken, sessionId) {
  // Validate SSO token from trusted provider
  const ssoData = validateSsoToken(ssoToken);

  if (!ssoData || !ssoData.valid) {
    return { success: false, error: 'Invalid SSO token' };
  }

  // Create or update session with SSO user data
  sessions[sessionId] = {
    userId: ssoData.userId,
    username: ssoData.username,
    email: ssoData.email,
    provider: ssoData.provider,
    roles: ssoData.roles || ['user'],
    authenticated: true,
    ssoAuthenticated: true,
    loginTime: Date.now()
  };

  return {
    success: true,
    sessionId: sessionId,
    user: {
      username: ssoData.username,
      email: ssoData.email
    }
  };
}`,

  vulnerableLine: `sessions[sessionId] = {`,

  options: [
    {
      code: `// Generate new session ID for SSO authentication
const newSessionId = generateSecureSessionId();
sessions[newSessionId] = {
  userId: ssoData.userId,
  username: ssoData.username,
  email: ssoData.email,
  provider: ssoData.provider,
  roles: ssoData.roles || ['user'],
  authenticated: true,
  ssoAuthenticated: true,
  loginTime: Date.now()
};

// Invalidate old session
if (sessions[sessionId]) {
  delete sessions[sessionId];
}

return {
  success: true,
  sessionId: newSessionId,
  user: { username: ssoData.username, email: ssoData.email }
};`,
      correct: true,
      explanation: `Correct! Creating a new session ID after SSO authentication prevents session fixation attacks. This ensures attackers cannot pre-establish a session and then hijack it after successful SSO authentication.`
    },
    {
      code: `sessions[sessionId] = {
  userId: ssoData.userId,
  authenticated: true,
  ssoAuthenticated: true
};`,
      correct: false,
      explanation: 'Direct from MITRE: Reusing existing session ID after SSO authentication enables session fixation. Attackers can establish a session, initiate SSO flow, then hijack authenticated session.'
    },
    {
      code: `if (sessions[sessionId]) {
  Object.assign(sessions[sessionId], {
    userId: ssoData.userId,
    authenticated: true,
    ssoData: ssoData
  });
} else {
  sessions[sessionId] = { userId: ssoData.userId, authenticated: true };
}`,
      correct: false,
      explanation: 'Updating existing sessions or creating new ones with same ID does not prevent session fixation during SSO authentication.'
    },
    {
      code: `const ssoSession = {
  ...ssoData,
  authenticated: true,
  sessionId: sessionId
};
sessions[sessionId] = ssoSession;`,
      correct: false,
      explanation: 'Spreading SSO data while maintaining the same session ID does not prevent session fixation attacks.'
    },
    {
      code: `sessions[sessionId + '_sso'] = {
  userId: ssoData.userId,
  authenticated: true,
  provider: ssoData.provider
};`,
      correct: false,
      explanation: 'Appending to the session ID is predictable and does not provide adequate protection against session fixation.'
    },
    {
      code: `const sessionData = JSON.parse(JSON.stringify({
  userId: ssoData.userId,
  authenticated: true,
  ssoProvider: ssoData.provider
}));
sessions[sessionId] = sessionData;`,
      correct: false,
      explanation: 'Deep cloning session data while maintaining the same session ID does not prevent session fixation attacks.'
    },
    {
      code: `try {
  sessions[sessionId] = {
    userId: ssoData.userId,
    authenticated: true,
    ssoValidated: true,
    timestamp: Date.now()
  };
} catch (e) {
  return { success: false, error: 'Session creation failed' };
}`,
      correct: false,
      explanation: 'Error handling and validation flags do not prevent session fixation. The session ID is still reused and vulnerable.'
    },
    {
      code: `if (sessionId && sessionId.match(/^[a-f0-9]{32}$/)) {
  sessions[sessionId] = {
    userId: ssoData.userId,
    authenticated: true,
    validSessionFormat: true
  };
}`,
      correct: false,
      explanation: 'Session ID format validation does not prevent session fixation. Attackers can generate properly formatted session IDs.'
    },
    {
      code: `const existingSession = sessions[sessionId] || {};
sessions[sessionId] = {
  ...existingSession,
  userId: ssoData.userId,
  authenticated: true,
  ssoComplete: true
};`,
      correct: false,
      explanation: 'Merging with existing session data does not prevent session fixation. The fundamental issue is reusing the same session ID.'
    },
    {
      code: `sessions[sessionId] = Object.freeze({
  userId: ssoData.userId,
  authenticated: true,
  immutable: true
});`,
      correct: false,
      explanation: 'Making sessions immutable does not prevent session fixation. The session ID is still predictable and can be hijacked.'
    }
  ]
}