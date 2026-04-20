import type { Exercise } from '@/data/exercises'

/**
 * CWE-829: Inclusion of Functionality from Untrusted Control Sphere - Configuration File Inclusion
 * Loading configuration from untrusted sources that can modify application behavior
 */
export const cwe829ConfigInclusion: Exercise = {
  cweId: 'CWE-829',
  name: 'Inclusion of Functionality from Untrusted Control Sphere - Config Loading',
  language: 'JavaScript',

  vulnerableFunction: `async function loadUserConfiguration(configSource, userId) {
  let configData;

  try {
    if (configSource.type === 'url') {
      // Load config from external URL
      const response = await fetch(configSource.url);
      configData = await response.json();
    } else if (configSource.type === 'file') {
      // Load config from file path
      const fs = require('fs');
      const configContent = fs.readFileSync(configSource.path, 'utf8');
      configData = JSON.parse(configContent);
    }

    // Apply configuration settings
    if (configData.features) {
      enableUserFeatures(userId, configData.features);
    }

    if (configData.permissions) {
      updateUserPermissions(userId, configData.permissions);
    }

    if (configData.apiEndpoints) {
      setUserApiEndpoints(userId, configData.apiEndpoints);
    }

    return { success: true, message: 'Configuration loaded successfully' };

  } catch (error) {
    return { success: false, error: error.message };
  }
}`,

  vulnerableLine: `configData = await response.json();`,

  options: [
    {
      code: `if (!isApprovedConfigSource(configSource.url)) { throw new Error('Untrusted config source'); } configData = await response.json(); validateConfigSchema(configData);`,
      correct: true,
      explanation: `Validate config file sources`
    },
    {
      code: `configData = await response.json(); // Load any config`,
      correct: false,
      explanation: 'Direct MITRE vulnerability pattern. Loading configuration from arbitrary URLs allows attackers to provide malicious configs that can modify user permissions, enable unauthorized features, or redirect API calls to malicious endpoints.'
    },
    {
      code: `const configText = await response.text(); configData = JSON.parse(configText.substring(0, 1000));`,
      correct: false,
      explanation: 'Size limiting doesn\'t prevent malicious configuration. Short configs can still contain permission escalations, feature flags, or endpoint redirections that compromise security within the size limit.'
    },
    {
      code: `if (configSource.url.endsWith('.json')) { configData = await response.json(); }`,
      correct: false,
      explanation: 'File extension validation is superficial. Attackers can host malicious JSON configs with proper extensions on compromised or controlled domains to bypass this simple check.'
    },
    {
      code: `configData = await response.json(); delete configData.permissions; // Remove permissions`,
      correct: false,
      explanation: 'Removing permissions after loading doesn\'t prevent other attacks. Malicious configs can still modify features, API endpoints, or other settings to compromise application security.'
    },
    {
      code: `if (configSource.url.startsWith('https://trusted-configs.example.com/')) { configData = await response.json(); }`,
      correct: false,
      explanation: 'Domain restriction helps but doesn\'t prevent subdomain takeover or path traversal attacks. If the trusted domain is compromised, malicious configs can still be served from the allowed URL pattern.'
    },
    {
      code: `configData = await response.json(); configData.permissions = configData.permissions?.slice(0, 5); // Limit permissions`,
      correct: false,
      explanation: 'Arbitrary permission limiting doesn\'t address the core trust issue. The first 5 permissions from a malicious config could still contain privilege escalations or unauthorized access grants.'
    },
    {
      code: `const configHash = crypto.createHash('sha256').update(JSON.stringify(configData)).digest('hex'); if (configHash.length === 64) { // Valid hash`,
      correct: false,
      explanation: 'Hash validation logic is flawed and doesn\'t verify authenticity. All SHA256 hashes are 64 characters, so this check always passes while providing no security validation.'
    },
    {
      code: `configData = await response.json(); if (configData.version !== '1.0') { throw new Error('Unsupported version'); }`,
      correct: false,
      explanation: 'Version checking doesn\'t prevent malicious content within supported versions. Attackers can create version 1.0 configs with malicious permissions or features that pass this validation.'
    },
    {
      code: `try { configData = await response.json(); } catch(e) { configData = getDefaultConfig(); }`,
      correct: false,
      explanation: 'Exception handling with fallback doesn\'t prevent malicious config processing. If the JSON parsing succeeds with malicious content, it will be applied before any safety checks occur.'
    }
  ]
}