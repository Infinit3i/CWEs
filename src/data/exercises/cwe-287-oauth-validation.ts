import type { Exercise } from '@/data/exercises'

/**
 * CWE-287 exercise: OAuth token validation bypass
 * Based on improper OAuth implementation patterns
 */
export const cwe287OAuthValidation: Exercise = {
  cweId: 'CWE-287',
  name: 'Improper Authentication - OAuth Token Validation',

  vulnerableFunction: `function validateOAuthToken(accessToken, requiredScope) {
  if (!accessToken) {
    return { valid: false, error: 'No access token provided' };
  }

  // Simple token format check
  if (accessToken.length < 20) {
    return { valid: false, error: 'Token too short' };
  }

  // Extract user info from token (assuming JWT-like structure)
  const parts = accessToken.split('.');
  if (parts.length === 3) {
    const payload = JSON.parse(atob(parts[1]));
    if (payload.scope && payload.scope.includes(requiredScope)) {
      return {
        valid: true,
        userId: payload.sub,
        scope: payload.scope
      };
    }
  }

  // Fallback: check if token looks valid
  if (accessToken.startsWith('ya29.') || accessToken.startsWith('Bearer ')) {
    return { valid: true, userId: 'unknown', scope: requiredScope };
  }

  return { valid: false, error: 'Invalid token format' };
}`,

  vulnerableLine: `const payload = JSON.parse(atob(parts[1]));`,

  options: [
    {
      code: `function validateOAuthToken(accessToken, requiredScope) {
  try {
    const response = await fetch('https://oauth-provider.com/tokeninfo?access_token=' + accessToken);
    const tokenInfo = await response.json();
    if (tokenInfo.error) {
      return { valid: false, error: 'Token validation failed' };
    }
    return {
      valid: tokenInfo.scope.includes(requiredScope),
      userId: tokenInfo.user_id,
      scope: tokenInfo.scope
    };
  } catch (error) {
    return { valid: false, error: 'Token validation error' };
  }
}`,
      correct: true,
      explanation: `Correct! Proper OAuth validation requires server-side verification with the OAuth provider. This ensures tokens are valid, active, and haven't been tampered with by checking against the authoritative source.`
    },
    // OAuth validation vulnerabilities
    {
      code: `const payload = JSON.parse(atob(parts[1]));
if (payload.scope && payload.scope.includes(requiredScope)) {
    return { valid: true, userId: payload.sub, scope: payload.scope };
}`,
      correct: false,
      explanation: 'Base64 decoding without signature verification allows token forgery. Attackers can craft JWT-like tokens with any payload since there is no cryptographic validation.'
    },
    {
      code: `if (accessToken.startsWith('ya29.') || accessToken.startsWith('Bearer ')) {
    return { valid: true, userId: 'unknown', scope: requiredScope };
}`,
      correct: false,
      explanation: 'Format-based token validation without verification. Attackers can create tokens with correct prefixes to bypass authentication entirely.'
    },
    {
      code: `if (accessToken.length > 50 && accessToken.includes('oauth')) {
    return { valid: true, userId: 'guest', scope: requiredScope };
}`,
      correct: false,
      explanation: 'Length and keyword checking provides no security. Any long string containing "oauth" is accepted as a valid token.'
    },
    {
      code: `const tokenHash = require('crypto').createHash('sha1').update(accessToken).digest('hex');
if (tokenHash.length === 40) {
    return { valid: true, userId: accessToken.substring(0, 10), scope: requiredScope };
}`,
      correct: false,
      explanation: 'Hashing tokens client-side provides no validation. SHA1 hashes are always 40 characters, so any token would pass this check.'
    },
    {
      code: `if (accessToken.match(/^[A-Za-z0-9._-]+$/) && accessToken.split('.').length >= 2) {
    return { valid: true, userId: 'authenticated', scope: requiredScope };
}`,
      correct: false,
      explanation: 'Pattern matching for token format without content validation. Any alphanumeric string with dots is accepted as valid.'
    },
    {
      code: `const cached = tokenCache.get(accessToken);
if (cached || accessToken.includes('valid')) {
    return { valid: true, userId: cached?.userId || 'default', scope: requiredScope };
}`,
      correct: false,
      explanation: 'Cache checking with keyword fallback. Tokens containing "valid" bypass authentication even without proper cache validation.'
    },
    {
      code: `if (accessToken.startsWith('sk-') && accessToken.length > 30) {
    const userId = accessToken.split('-')[1] || 'user';
    return { valid: true, userId: userId, scope: requiredScope };
}`,
      correct: false,
      explanation: 'API key format checking without verification. Attackers can craft tokens with correct prefixes and extract user IDs from the format.'
    },
    {
      code: `const decoded = Buffer.from(accessToken, 'base64').toString();
if (decoded.includes('authorized') && decoded.includes(requiredScope)) {
    return { valid: true, userId: 'system', scope: requiredScope };
}`,
      correct: false,
      explanation: 'Base64 decoding with keyword checking. Attackers can encode strings containing required keywords to bypass validation.'
    },
    {
      code: `if (Date.now() - parseInt(accessToken.substring(-10)) < 3600000) {
    return { valid: true, userId: accessToken.substring(0, 8), scope: requiredScope };
}`,
      correct: false,
      explanation: 'Timestamp-based validation using token substrings. Attackers can craft tokens with recent timestamps to pass time-based checks.'
    }
  ]
}