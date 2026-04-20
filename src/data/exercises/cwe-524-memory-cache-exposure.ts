import type { Exercise } from '@/data/exercises'

/**
 * CWE-524 Exercise 1: Sensitive Data in Memory Cache
 * Based on MITRE examples of cache containing sensitive information
 */
export const cwe524MemoryCacheExposure: Exercise = {
  cweId: 'CWE-524',
  name: 'Memory Cache Exposure - User Credentials Cache',

  vulnerableFunction: `function authenticateUser(username, password) {
  // Check cache first for performance
  const cacheKey = \`user:\${username}\`;

  if (userCache[cacheKey]) {
    const cachedUser = userCache[cacheKey];
    if (cachedUser.password === password) {
      return { success: true, user: cachedUser };
    }
  }

  // Fetch from database if not in cache
  const user = database.getUserByUsername(username);

  if (user && user.password === password) {
    // Cache the full user object including password
    userCache[cacheKey] = {
      id: user.id,
      username: user.username,
      password: user.password,
      email: user.email,
      role: user.role,
      lastLogin: user.lastLogin
    };

    return { success: true, user: user };
  }

  return { success: false, error: 'Invalid credentials' };
}`,

  vulnerableLine: `password: user.password,`,

  options: [
    {
      code: `// Cache only non-sensitive user data
userCache[cacheKey] = {
  id: user.id,
  username: user.username,
  email: user.email,
  role: user.role,
  lastLogin: user.lastLogin
  // Do not cache password or other sensitive data
};`,
      correct: true,
      explanation: `Avoid caching sensitive memory`
    },
    {
      code: `userCache[cacheKey] = {
  id: user.id,
  username: user.username,
  password: user.password,
  email: user.email,
  role: user.role
};`,
      correct: false,
      explanation: 'Caching passwords and sensitive data enables unauthorized access. Attackers who gain access to memory or cache dumps can extract plaintext credentials.'
    },
    {
      code: `const encryptedPassword = encrypt(user.password);
userCache[cacheKey] = {
  ...user,
  password: encryptedPassword
};`,
      correct: false,
      explanation: 'Encryption in cache is better but not ideal. The encryption key might be accessible, and caching passwords is generally unnecessary for performance.'
    },
    {
      code: `userCache[cacheKey] = {
  ...user,
  password: hash(user.password)
};`,
      correct: false,
      explanation: 'Even hashed passwords should not be cached unnecessarily. The hash could still be valuable to attackers for offline cracking attempts.'
    },
    {
      code: `userCache[cacheKey] = Object.freeze({
  id: user.id,
  username: user.username,
  password: user.password,
  email: user.email
});`,
      correct: false,
      explanation: 'Freezing objects does not prevent sensitive data exposure. The password is still stored in cache and accessible to unauthorized actors.'
    },
    {
      code: `if (user.password.length < 50) {
  userCache[cacheKey] = { ...user };
} else {
  userCache[cacheKey] = { ...user, password: undefined };
}`,
      correct: false,
      explanation: 'Password length-based caching decisions are arbitrary and still cache sensitive data. Most passwords would be cached with this logic.'
    },
    {
      code: `const userCopy = JSON.parse(JSON.stringify(user));
delete userCopy.sensitiveField;
userCache[cacheKey] = userCopy;`,
      correct: false,
      explanation: 'Deleting arbitrary sensitive fields is incomplete. The password and potentially other sensitive data are still cached.'
    },
    {
      code: `try {
  userCache[cacheKey] = {
    ...user,
    password: btoa(user.password) // Base64 encode
  };
} catch {}`,
      correct: false,
      explanation: 'Base64 encoding is not security - it is easily decoded. The password is still effectively stored in plaintext in the cache.'
    },
    {
      code: `userCache[cacheKey] = {
  publicData: {
    id: user.id,
    username: user.username,
    email: user.email
  },
  privateData: {
    password: user.password
  }
};`,
      correct: false,
      explanation: 'Organizing sensitive data in a separate object does not prevent exposure. The password is still stored in cache memory.'
    },
    {
      code: `setTimeout(() => {
  userCache[cacheKey] = { ...user };
}, 100);`,
      correct: false,
      explanation: 'Delayed caching does not prevent sensitive data exposure. The password would still be cached after the timeout.'
    }
  ]
}