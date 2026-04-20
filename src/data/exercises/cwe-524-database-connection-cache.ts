import type { Exercise } from '@/data/exercises'

/**
 * CWE-524 Exercise 3: Database Connection String Caching
 * Based on caching sensitive connection information
 */
export const cwe524DatabaseConnectionCache: Exercise = {
  cweId: 'CWE-524',
  name: 'Database Connection Cache - Connection Pool Manager',

  vulnerableFunction: `function getDbConnection(connectionParams) {
  const cacheKey = \`db:\${connectionParams.host}:\${connectionParams.database}\`;

  // Check cache for existing connection
  if (connectionCache[cacheKey]) {
    const cached = connectionCache[cacheKey];
    if (cached.connection.isConnected()) {
      return cached.connection;
    }
  }

  // Create new database connection
  const connectionString = \`postgresql://\${connectionParams.username}:\${connectionParams.password}@\${connectionParams.host}:\${connectionParams.port}/\${connectionParams.database}\`;

  const connection = new DatabaseConnection(connectionString);

  // Cache the connection and all connection details
  connectionCache[cacheKey] = {
    connection: connection,
    connectionString: connectionString,
    credentials: {
      username: connectionParams.username,
      password: connectionParams.password,
      host: connectionParams.host,
      database: connectionParams.database
    },
    createdAt: Date.now()
  };

  return connection;
}`,

  vulnerableLine: `password: connectionParams.password,`,

  options: [
    {
      code: `// Cache only connection object and non-sensitive metadata
connectionCache[cacheKey] = {
  connection: connection,
  host: connectionParams.host,
  database: connectionParams.database,
  createdAt: Date.now()
  // Do not cache passwords or connection strings with credentials
};`,
      correct: true,
      explanation: `Secure database connection caching`
    },
    {
      code: `connectionCache[cacheKey] = {
  connection: connection,
  connectionString: connectionString,
  credentials: {
    username: connectionParams.username,
    password: connectionParams.password
  }
};`,
      correct: false,
      explanation: 'Caching database credentials enables unauthorized access. Attackers who access cache memory can extract database passwords and connection strings.'
    },
    {
      code: `const maskedPassword = '*'.repeat(connectionParams.password.length);
connectionCache[cacheKey] = {
  connection: connection,
  credentials: {
    username: connectionParams.username,
    password: maskedPassword
  }
};`,
      correct: false,
      explanation: 'Password masking is better but still unnecessary. It is safer to completely exclude credentials from cache to prevent any potential exposure.'
    },
    {
      code: `connectionCache[cacheKey] = {
  connection: connection,
  connectionString: connectionString.replace(connectionParams.password, 'HIDDEN'),
  metadata: { host: connectionParams.host }
};`,
      correct: false,
      explanation: 'String replacement is fragile and error-prone. Special characters in passwords could cause incomplete replacement, leading to credential exposure.'
    },
    {
      code: `const encryptedPassword = encrypt(connectionParams.password);
connectionCache[cacheKey] = {
  connection: connection,
  credentials: {
    username: connectionParams.username,
    password: encryptedPassword
  }
};`,
      correct: false,
      explanation: 'Encryption adds complexity and risk. If encryption keys are accessible or compromised, the database password becomes exposed.'
    },
    {
      code: `connectionCache[cacheKey] = Object.freeze({
  connection: connection,
  credentials: {
    username: connectionParams.username,
    password: connectionParams.password,
    host: connectionParams.host
  }
});`,
      correct: false,
      explanation: 'Freezing objects does not prevent sensitive data exposure. The password is still stored in cache memory and accessible to attackers.'
    },
    {
      code: `if (connectionParams.password.length < 20) {
  connectionCache[cacheKey] = {
    connection: connection,
    host: connectionParams.host
  };
} else {
  connectionCache[cacheKey] = {
    connection: connection,
    credentials: connectionParams
  };
}`,
      correct: false,
      explanation: 'Password length-based caching decisions are arbitrary and unreliable. Strong passwords would be cached with this logic.'
    },
    {
      code: `try {
  connectionCache[cacheKey] = {
    connection: connection,
    config: JSON.parse(JSON.stringify({
      ...connectionParams,
      password: btoa(connectionParams.password)
    }))
  };
} catch {}`,
      correct: false,
      explanation: 'Base64 encoding provides no security - it is easily decoded. The password is still effectively stored in plaintext in the cache.'
    },
    {
      code: `const connectionHash = hash(connectionString);
connectionCache[cacheKey] = {
  connection: connection,
  hash: connectionHash,
  originalParams: connectionParams
};`,
      correct: false,
      explanation: 'Hashing connection strings while storing original parameters still exposes the password in the originalParams object.'
    },
    {
      code: `setTimeout(() => delete connectionCache[cacheKey], 300000); // 5 minutes
connectionCache[cacheKey] = {
  connection: connection,
  credentials: connectionParams,
  temporary: true
};`,
      correct: false,
      explanation: 'Temporary caching with expiration does not prevent exposure during the cache lifetime. Credentials are still accessible to attackers.'
    }
  ]
}