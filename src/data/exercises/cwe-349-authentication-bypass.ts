import type { Exercise } from '@/data/exercises'

/**
 * CWE-349 Exercise 4: Authentication Bypass via Extra Data
 * Based on accepting untrusted authentication data alongside trusted tokens
 */
export const cwe349AuthenticationBypass: Exercise = {
  cweId: 'CWE-349',
  name: 'Authentication Bypass - Token Plus Extra Data',
  language: 'JavaScript',

  vulnerableFunction: `function authenticateRequest(trustedJwtToken, clientAuthData) {
  // Verify the trusted JWT token
  const decodedToken = verifyJwtToken(trustedJwtToken);

  if (decodedToken) {
    // Merge trusted token data with client-provided auth data
    const authContext = {
      ...decodedToken,
      ...clientAuthData, // Include any additional auth info from client
      authenticated: true,
      tokenValid: true
    };

    // Make authorization decisions based on combined data
    if (authContext.role === 'admin' || authContext.permissions?.includes('admin')) {
      authContext.adminAccess = true;
    }

    return authContext;
  }

  return { authenticated: false };
}`,

  vulnerableLine: `...clientAuthData,`,

  options: [
    {
      code: `// Only trust data from verified JWT token
const authContext = {
  userId: decodedToken.userId,
  username: decodedToken.username,
  role: decodedToken.role,
  permissions: decodedToken.permissions,
  authenticated: true,
  tokenValid: true,
  clientMetadata: clientAuthData // Keep separate, don't use for auth decisions
};`,
      correct: true,
      explanation: `Verify authentication sources`
    },
    {
      code: `const authContext = {
  ...decodedToken,
  ...clientAuthData,
  authenticated: true
};`,
      correct: false,
      explanation: 'Merging untrusted client data with trusted authentication tokens allows privilege escalation. Clients can include {"role": "admin"} to bypass authorization controls.'
    },
    {
      code: `Object.assign(decodedToken, clientAuthData);
return { ...decodedToken, authenticated: true };`,
      correct: false,
      explanation: 'Directly modifying the trusted token with client data allows complete override of authentication properties.'
    },
    {
      code: `const authContext = {
  ...clientAuthData,
  ...decodedToken,
  authenticated: true
};`,
      correct: false,
      explanation: 'Reversing merge order does not prevent the issue. Client data can still influence subsequent authorization logic even if overridden.'
    },
    {
      code: `if (clientAuthData.role === decodedToken.role) {
  const authContext = { ...decodedToken, ...clientAuthData, authenticated: true };
  return authContext;
}`,
      correct: false,
      explanation: 'Validation that allows matching roles can be bypassed - attackers just need to set the client role to match any existing token role.'
    },
    {
      code: `const authContext = {
  token: decodedToken,
  client: clientAuthData,
  authenticated: true
};
if (authContext.token.role === 'admin' || authContext.client.role === 'admin') {
  authContext.adminAccess = true;
}`,
      correct: false,
      explanation: 'Even with namespace separation, checking both trusted and untrusted sources for authorization defeats the security boundary.'
    },
    {
      code: `const allowedClientFields = ['sessionId', 'locale', 'timezone'];
const filteredClientData = Object.keys(clientAuthData)
  .filter(key => allowedClientFields.includes(key))
  .reduce((obj, key) => { obj[key] = clientAuthData[key]; return obj; }, {});
const authContext = { ...decodedToken, ...filteredClientData, authenticated: true };`,
      correct: false,
      explanation: 'While allowlisting helps, any merging of client data with token data creates risk. Even seemingly harmless fields could affect authorization logic.'
    },
    {
      code: `try {
  const authContext = { ...decodedToken, ...clientAuthData, authenticated: true };
  return authContext;
} catch (e) {
  return { ...decodedToken, authenticated: true };
}`,
      correct: false,
      explanation: 'Error handling does not prevent the authentication bypass. The dangerous merge typically succeeds without throwing exceptions.'
    },
    {
      code: `if (typeof clientAuthData === 'object' && Object.keys(clientAuthData).length > 0) {
  return { ...decodedToken, ...clientAuthData, authenticated: true };
}`,
      correct: false,
      explanation: 'Conditional merging based on client data presence does not prevent the security issue - untrusted data still overrides trusted data.'
    },
    {
      code: `const authContext = JSON.parse(JSON.stringify({
  ...decodedToken,
  ...clientAuthData,
  authenticated: true
}));`,
      correct: false,
      explanation: 'Deep cloning does not prevent the fundamental issue of untrusted client data overriding trusted authentication properties.'
    }
  ]
}