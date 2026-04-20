import type { Exercise } from '@/data/exercises'

/**
 * CWE-524 Exercise 4: Session Data Caching
 * Based on caching sensitive user session information
 */
export const cwe524SessionDataCache: Exercise = {
  cweId: 'CWE-524',
  name: 'Session Data Cache - User Profile Cache',

  vulnerableFunction: `function getUserProfile(userId, sessionId) {
  const cacheKey = \`profile:\${userId}\`;

  // Check cache first for performance
  if (profileCache[cacheKey]) {
    return profileCache[cacheKey];
  }

  // Fetch user profile from database
  const profile = database.getUserProfile(userId);
  const session = database.getUserSession(sessionId);

  if (profile && session) {
    // Cache complete user profile including sensitive data
    profileCache[cacheKey] = {
      userId: profile.userId,
      username: profile.username,
      email: profile.email,
      socialSecurityNumber: profile.socialSecurityNumber,
      creditCardNumber: profile.creditCardNumber,
      phoneNumber: profile.phoneNumber,
      address: profile.address,
      sessionData: {
        sessionId: sessionId,
        loginToken: session.loginToken,
        refreshToken: session.refreshToken,
        securityQuestions: session.securityQuestions
      },
      preferences: profile.preferences,
      lastAccessed: Date.now()
    };

    return profileCache[cacheKey];
  }

  return null;
}`,

  vulnerableLine: `socialSecurityNumber: profile.socialSecurityNumber,`,

  options: [
    {
      code: `// Cache only non-sensitive profile data
profileCache[cacheKey] = {
  userId: profile.userId,
  username: profile.username,
  email: profile.email,
  preferences: profile.preferences,
  lastAccessed: Date.now()
  // Exclude SSN, credit cards, tokens, and other sensitive data
};`,
      correct: true,
      explanation: `Correct! Excluding sensitive data like SSN, credit cards, and authentication tokens from cache prevents unauthorized access to personal and financial information while maintaining performance benefits.`
    },
    {
      code: `profileCache[cacheKey] = {
  userId: profile.userId,
  socialSecurityNumber: profile.socialSecurityNumber,
  creditCardNumber: profile.creditCardNumber,
  sessionData: {
    loginToken: session.loginToken,
    refreshToken: session.refreshToken
  }
};`,
      correct: false,
      explanation: 'Direct from MITRE: Caching sensitive personal data like SSN, credit cards, and authentication tokens enables identity theft and unauthorized access if cache is compromised.'
    },
    {
      code: `const maskedSSN = profile.socialSecurityNumber.replace(/\\d(?=\\d{4})/g, '*');
const maskedCC = profile.creditCardNumber.replace(/\\d(?=\\d{4})/g, '*');
profileCache[cacheKey] = {
  ...profile,
  socialSecurityNumber: maskedSSN,
  creditCardNumber: maskedCC
};`,
      correct: false,
      explanation: 'Partial masking reduces risk but is still unnecessary. Complete exclusion of sensitive data from cache is the safest approach.'
    },
    {
      code: `profileCache[cacheKey] = {
  publicData: {
    userId: profile.userId,
    username: profile.username,
    email: profile.email
  },
  sensitiveData: {
    socialSecurityNumber: profile.socialSecurityNumber,
    creditCardNumber: profile.creditCardNumber
  }
};`,
      correct: false,
      explanation: 'Organizing sensitive data separately does not prevent exposure. The sensitive data is still stored in cache memory.'
    },
    {
      code: `const encryptedSSN = encrypt(profile.socialSecurityNumber);
const encryptedCC = encrypt(profile.creditCardNumber);
profileCache[cacheKey] = {
  ...profile,
  socialSecurityNumber: encryptedSSN,
  creditCardNumber: encryptedCC
};`,
      correct: false,
      explanation: 'Encryption in cache adds complexity and risk. If encryption keys are accessible, sensitive data becomes exposed.'
    },
    {
      code: `if (profile.socialSecurityNumber && profile.socialSecurityNumber.length === 11) {
  profileCache[cacheKey] = { ...profile };
} else {
  profileCache[cacheKey] = {
    userId: profile.userId,
    username: profile.username
  };
}`,
      correct: false,
      explanation: 'Conditional caching based on data format is unreliable. Valid SSNs would still be cached with this logic.'
    },
    {
      code: `try {
  profileCache[cacheKey] = Object.freeze({
    ...profile,
    socialSecurityNumber: profile.socialSecurityNumber,
    creditCardNumber: profile.creditCardNumber
  });
} catch {}`,
      correct: false,
      explanation: 'Freezing objects does not prevent sensitive data exposure. The personal information is still accessible in cache memory.'
    },
    {
      code: `const profileCopy = JSON.parse(JSON.stringify(profile));
delete profileCopy.password; // Only delete password
profileCache[cacheKey] = profileCopy;`,
      correct: false,
      explanation: 'Deleting only password is incomplete. Other sensitive data like SSN, credit cards, and tokens are still cached.'
    },
    {
      code: `profileCache[cacheKey] = {
  ...profile,
  socialSecurityNumber: hash(profile.socialSecurityNumber),
  creditCardNumber: hash(profile.creditCardNumber)
};`,
      correct: false,
      explanation: 'Hashing sensitive personal data is unnecessary and potentially harmful. Hashed values could still be valuable to attackers.'
    },
    {
      code: `const cacheData = { ...profile };
if (Math.random() > 0.5) {
  delete cacheData.socialSecurityNumber;
  delete cacheData.creditCardNumber;
}
profileCache[cacheKey] = cacheData;`,
      correct: false,
      explanation: 'Random exclusion of sensitive data is unreliable and still exposes personal information approximately half the time.'
    }
  ]
}