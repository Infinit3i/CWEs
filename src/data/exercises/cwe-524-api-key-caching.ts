import type { Exercise } from '@/data/exercises'

/**
 * CWE-524 Exercise 2: API Key Caching in HTTP Client
 * Based on caching sensitive authentication tokens
 */
export const cwe524ApiKeyCaching: Exercise = {
  cweId: 'CWE-524',
  name: 'API Key Caching - HTTP Client Cache',

  vulnerableFunction: `function makeApiRequest(endpoint, apiKey, params) {
  const cacheKey = \`api:\${endpoint}:\${JSON.stringify(params)}\`;

  // Check cache for previous response
  if (responseCache[cacheKey]) {
    return responseCache[cacheKey];
  }

  // Make API request
  const response = httpClient.get(endpoint, {
    headers: {
      'Authorization': \`Bearer \${apiKey}\`,
      'Content-Type': 'application/json'
    },
    params: params
  });

  // Cache the complete response including headers
  responseCache[cacheKey] = {
    data: response.data,
    headers: response.headers,
    status: response.status,
    request: {
      endpoint: endpoint,
      apiKey: apiKey,
      params: params,
      timestamp: Date.now()
    }
  };

  return responseCache[cacheKey];
}`,

  vulnerableLine: `apiKey: apiKey,`,

  options: [
    {
      code: `// Cache response without sensitive request data
responseCache[cacheKey] = {
  data: response.data,
  status: response.status,
  timestamp: Date.now(),
  endpoint: endpoint
  // Do not cache API keys, tokens, or other sensitive data
};`,
      correct: true,
      explanation: `Correct! Excluding API keys and sensitive authentication data from cache prevents credential exposure. This maintains caching benefits while protecting sensitive information from unauthorized access.`
    },
    {
      code: `responseCache[cacheKey] = {
  data: response.data,
  request: {
    endpoint: endpoint,
    apiKey: apiKey,
    params: params
  }
};`,
      correct: false,
      explanation: 'Direct from MITRE: Caching API keys and authentication tokens enables unauthorized access. Attackers who access cache memory can extract and reuse these credentials.'
    },
    {
      code: `const maskedApiKey = apiKey.substring(0, 8) + '***';
responseCache[cacheKey] = {
  data: response.data,
  request: {
    apiKey: maskedApiKey,
    endpoint: endpoint
  }
};`,
      correct: false,
      explanation: 'Partial masking is better but unnecessary. It is safer to completely exclude API keys from cache rather than risk implementation errors.'
    },
    {
      code: `const encryptedKey = encrypt(apiKey, CACHE_KEY);
responseCache[cacheKey] = {
  data: response.data,
  request: {
    apiKey: encryptedKey,
    endpoint: endpoint
  }
};`,
      correct: false,
      explanation: 'Encryption in cache adds complexity and risk. If the encryption key is compromised or accessible, the API key becomes exposed.'
    },
    {
      code: `responseCache[cacheKey] = {
  data: response.data,
  headers: { ...response.headers },
  request: Object.freeze({
    apiKey: apiKey,
    endpoint: endpoint
  })
};`,
      correct: false,
      explanation: 'Freezing objects does not prevent sensitive data exposure. The API key is still stored in cache memory and accessible to attackers.'
    },
    {
      code: `const requestData = {
  endpoint: endpoint,
  apiKey: hash(apiKey),
  params: params
};
responseCache[cacheKey] = { data: response.data, request: requestData };`,
      correct: false,
      explanation: 'Hashing API keys is unnecessary and potentially harmful. Hashed keys could still provide information to attackers.'
    },
    {
      code: `if (apiKey.length > 20) {
  responseCache[cacheKey] = {
    data: response.data,
    request: { endpoint: endpoint }
  };
} else {
  responseCache[cacheKey] = {
    data: response.data,
    request: { endpoint: endpoint, apiKey: apiKey }
  };
}`,
      correct: false,
      explanation: 'Arbitrary length-based decisions for caching sensitive data are unreliable and still expose credentials in some cases.'
    },
    {
      code: `try {
  responseCache[cacheKey] = JSON.parse(JSON.stringify({
    data: response.data,
    request: { apiKey: btoa(apiKey), endpoint: endpoint }
  }));
} catch {}`,
      correct: false,
      explanation: 'Base64 encoding is not security - it is easily decoded. The API key is still effectively stored in plaintext.'
    },
    {
      code: `responseCache[cacheKey] = {
  data: response.data,
  metadata: {
    hasApiKey: !!apiKey,
    keyPrefix: apiKey.substring(0, 4),
    endpoint: endpoint
  }
};`,
      correct: false,
      explanation: 'Storing metadata about API keys is better but the key prefix could still provide useful information to attackers.'
    },
    {
      code: `const cacheData = {
  data: response.data,
  request: { apiKey: apiKey, endpoint: endpoint }
};
responseCache[cacheKey] = Object.seal(cacheData);`,
      correct: false,
      explanation: 'Sealing objects does not prevent sensitive data exposure. The API key is still accessible in cache memory.'
    }
  ]
}