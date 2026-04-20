import type { Exercise } from '@/data/exercises'

/**
 * CWE-476 exercise - Configuration Parser
 * Based on MITRE patterns for NULL pointer dereference in data processing
 */
export const cwe476ConfigParser: Exercise = {
  cweId: 'CWE-476',
  name: 'NULL Pointer Dereference - Configuration Parser',
  language: 'Go',

  vulnerableFunction: `function parseConfigValue(configData, key) {
  // Extract configuration value
  const configValue = configData.getValue(key);

  // Process the configuration value
  const processedValue = configValue.toUpperCase(); // Potential null dereference

  return processedValue;
}`,

  vulnerableLine: `const processedValue = configValue.toUpperCase();`,

  options: [
    {
      code: `const configValue = configData.getValue(key); if (configValue === null || configValue === undefined) { throw new Error(\`Configuration key '\${key}' not found or has null value\`); } const processedValue = configValue.toUpperCase();`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `char* config_value = get_config_value(key); int length = strlen(config_value);`,
      correct: false,
      explanation: 'Following MITRE patterns: get_config_value() can return NULL for missing configuration keys, but strlen() is called without null checking, causing a segmentation fault when processing the NULL pointer.'
    },
    {
      code: `const configValue = configData.getValue(key); try { const processedValue = configValue.toUpperCase(); } catch (error) { return "DEFAULT_VALUE"; }`,
      correct: false,
      explanation: 'Exception handling cannot prevent NULL dereference crashes in many contexts. The error occurs at the method invocation level before proper exception handling can intercept it.'
    },
    {
      code: `const configValue = configData.getValue(key); if (configData.hasKey(key)) { const processedValue = configValue.toUpperCase(); }`,
      correct: false,
      explanation: 'Checking if the key exists is insufficient because the key can exist but have a NULL value assigned to it, which would still cause a dereference error when calling methods.'
    },
    {
      code: `const configValue = configData.getValue(key) || "default"; const processedValue = configValue.toUpperCase();`,
      correct: false,
      explanation: 'While this prevents the crash by providing a default value, it may not be the intended behavior and could mask configuration errors that should be explicitly handled.'
    },
    {
      code: `let configValue; setTimeout(() => { configValue = configData.getValue(key); const processedValue = configValue.toUpperCase(); }, 50);`,
      correct: false,
      explanation: 'Asynchronous processing does not solve NULL dereference issues. Configuration data availability typically does not change with time delays, and this creates unnecessary complexity.'
    },
    {
      code: `const configValue = configData.getValue(key); if (typeof configValue === 'string') { const processedValue = configValue.toUpperCase(); }`,
      correct: false,
      explanation: 'Type checking is good practice but may not catch all edge cases. In some implementations, NULL might have unexpected typeof results, and this does not handle undefined values.'
    },
    {
      code: `const configValue = configData.getValue(key); const hasLength = configValue.length > 0; if (hasLength) { const processedValue = configValue.toUpperCase(); }`,
      correct: false,
      explanation: 'Attempting to access the length property of a NULL value will cause the same type of dereference error we are trying to prevent, just at a different location.'
    },
    {
      code: `const configValue = configData.getValue(key); if (configValue.constructor === String) { const processedValue = configValue.toUpperCase(); }`,
      correct: false,
      explanation: 'Checking the constructor property will fail when configValue is NULL because accessing any property of NULL causes a dereference error before the constructor check can complete.'
    },
    {
      code: `const configValue = JSON.parse(JSON.stringify(configData.getValue(key))); const processedValue = configValue.toUpperCase();`,
      correct: false,
      explanation: 'JSON operations do not prevent NULL dereference. If getValue() returns NULL, JSON.stringify(null) returns "null" as a string, changing semantics and potentially masking the real issue.'
    }
  ]
}