import type { Exercise } from '@/data/exercises'

/**
 * CWE-349 Exercise 5: Configuration File Injection
 * Based on CAPEC-75 configuration manipulation through extra untrusted data
 */
export const cwe349ConfigInjection: Exercise = {
  cweId: 'CWE-349',
  name: 'Configuration Injection - Environment Override',
  language: 'JavaScript',

  vulnerableFunction: `function loadApplicationConfig(defaultConfig, userOverrides, envVars) {
  // Load base configuration from trusted source
  const baseConfig = { ...defaultConfig };

  // Apply environment variables
  for (const [key, value] of Object.entries(envVars)) {
    if (key.startsWith('APP_')) {
      const configKey = key.substring(4).toLowerCase();
      baseConfig[configKey] = value;
    }
  }

  // Apply user-provided overrides on top
  const finalConfig = {
    ...baseConfig,
    ...userOverrides, // Allow users to override any configuration
    loaded: true,
    source: 'merged'
  };

  return finalConfig;
}`,

  vulnerableLine: `...userOverrides,`,

  options: [
    {
      code: `// Only allow specific user-configurable properties
const ALLOWED_USER_OVERRIDES = ['theme', 'language', 'timezone', 'pageSize'];
const safeOverrides = Object.keys(userOverrides)
  .filter(key => ALLOWED_USER_OVERRIDES.includes(key))
  .reduce((obj, key) => { obj[key] = userOverrides[key]; return obj; }, {});

const finalConfig = {
  ...baseConfig,
  userPreferences: safeOverrides,
  loaded: true,
  source: 'merged'
};`,
      correct: true,
      explanation: `Validate config data sources`
    },
    {
      code: `const finalConfig = {
  ...baseConfig,
  ...userOverrides,
  loaded: true
};`,
      correct: false,
      explanation: 'Accepting arbitrary user configuration overrides enables security bypass. Users can override critical settings like database URLs, admin flags, or security configurations (CAPEC-75).'
    },
    {
      code: `Object.assign(baseConfig, userOverrides);
return { ...baseConfig, loaded: true };`,
      correct: false,
      explanation: 'Direct assignment of user overrides allows complete modification of the trusted configuration object.'
    },
    {
      code: `const finalConfig = Object.assign({},
  userOverrides,
  baseConfig,
  { loaded: true }
);`,
      correct: false,
      explanation: 'Reversing merge order does not prevent configuration injection. User data can still influence security decisions even if some values are overridden.'
    },
    {
      code: `if (Object.keys(userOverrides).every(key => typeof userOverrides[key] === 'string')) {
  const finalConfig = { ...baseConfig, ...userOverrides, loaded: true };
  return finalConfig;
}`,
      correct: false,
      explanation: 'Type validation does not prevent configuration injection. String values can still override critical settings like "{"adminMode": "true"}".'
    },
    {
      code: `const blockedKeys = ['password', 'secret', 'key'];
const filteredOverrides = Object.keys(userOverrides)
  .filter(key => !blockedKeys.some(blocked => key.includes(blocked)))
  .reduce((obj, key) => { obj[key] = userOverrides[key]; return obj; }, {});
const finalConfig = { ...baseConfig, ...filteredOverrides, loaded: true };`,
      correct: false,
      explanation: 'Blacklisting specific sensitive keywords is insufficient. Many other critical configuration properties exist that could be exploited.'
    },
    {
      code: `try {
  const finalConfig = { ...baseConfig, ...userOverrides, loaded: true };
  return finalConfig;
} catch (e) {
  return { ...baseConfig, loaded: true };
}`,
      correct: false,
      explanation: 'Error handling does not prevent configuration injection. The dangerous merge typically succeeds without throwing exceptions.'
    },
    {
      code: `const finalConfig = {
  base: baseConfig,
  user: userOverrides,
  loaded: true
};
// Use finalConfig.base for security decisions`,
      correct: false,
      explanation: 'Namespace separation is good but incomplete if application logic might accidentally use both base and user configurations for security decisions.'
    },
    {
      code: `if (userOverrides && Object.keys(userOverrides).length <= 5) {
  const finalConfig = { ...baseConfig, ...userOverrides, loaded: true };
  return finalConfig;
}`,
      correct: false,
      explanation: 'Limiting override count does not prevent configuration injection. A few carefully chosen overrides can compromise security.'
    },
    {
      code: `const finalConfig = {
  ...JSON.parse(JSON.stringify(baseConfig)),
  ...JSON.parse(JSON.stringify(userOverrides)),
  loaded: true
};`,
      correct: false,
      explanation: 'Deep cloning does not prevent the fundamental issue of allowing user overrides of security-critical configuration properties.'
    }
  ]
}