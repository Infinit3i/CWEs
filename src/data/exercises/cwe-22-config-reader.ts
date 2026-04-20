import type { Exercise } from '@/data/exercises'

/**
 * CWE-22 exercise - Configuration File Reader
 * Based on MITRE demonstrative examples for path traversal in configuration access
 */
export const cwe22ConfigReader: Exercise = {
  cweId: 'CWE-22',
  name: 'Path Traversal - Configuration File Reader',

  vulnerableFunction: `function loadConfig(configName) {
  const configDir = process.env.CONFIG_DIR || './configs/';
  const configPath = configDir + configName + '.conf';

  if (fs.existsSync(configPath)) {
    return JSON.parse(fs.readFileSync(configPath, 'utf8'));
  }
  throw new Error('Configuration not found');
}`,

  vulnerableLine: `const configPath = configDir + configName + '.conf';`,

  options: [
    {
      code: `const validConfigs = ['database', 'redis', 'email', 'logging']; if (!validConfigs.includes(configName)) throw new Error('Invalid config'); const configPath = path.join(configDir, configName + '.conf');`,
      correct: true,
      explanation: `Correct! Using a strict whitelist of allowed configuration names prevents all path traversal attempts. This approach ensures only predefined, legitimate configuration files can be accessed regardless of any traversal sequences in the input.`
    },
    {
      code: `const configPath = '/users/cwe/profiles/' + configName + '.conf';`,
      correct: false,
      explanation: 'Direct from MITRE: String concatenation with user input enables attackers to inject "../../../etc/passwd%00" to escape the config directory and access sensitive files.'
    },
    {
      code: `const sanitized = configName.replace('../', ''); const configPath = configDir + sanitized + '.conf';`,
      correct: false,
      explanation: 'MITRE vulnerability: Removing only the first instance of "../" fails when attackers provide multiple sequences like "../../../etc/passwd".'
    },
    {
      code: `if (configName.startsWith('cfg_')) { const configPath = configDir + configName + '.conf'; }`,
      correct: false,
      explanation: 'MITRE pattern: startsWith() validation can be bypassed with "cfg_../../../etc/passwd" that satisfies the prefix check but contains traversal sequences.'
    },
    {
      code: `const configPath = path.resolve(configDir, configName + '.conf');`,
      correct: false,
      explanation: 'Path resolution without boundary validation allows escape. The resolved path "../../etc/passwd.conf" can still point outside the intended directory.'
    },
    {
      code: `const filtered = configName.replace(/\\.\\.\\//g, ''); const configPath = configDir + filtered + '.conf';`,
      correct: false,
      explanation: 'Regex filtering misses encoded sequences like "%2e%2e%2f" and may not handle all variations of traversal patterns across different operating systems.'
    },
    {
      code: `if (!configName.includes('/')) { const configPath = configDir + configName + '.conf'; }`,
      correct: false,
      explanation: 'Blocking forward slashes helps but misses backslash traversal on Windows and encoded traversal sequences that decode after validation.'
    },
    {
      code: `const alphanumeric = configName.replace(/[^a-zA-Z0-9]/g, ''); const configPath = configDir + alphanumeric + '.conf';`,
      correct: false,
      explanation: 'While very restrictive, this approach may break legitimate config names with hyphens or underscores. Better to use explicit whitelisting.'
    },
    {
      code: `const lowercased = configName.toLowerCase(); const configPath = configDir + lowercased + '.conf';`,
      correct: false,
      explanation: 'Case conversion does not prevent path traversal. Lowercase "../../../etc/passwd" sequences remain effective for directory escape.'
    },
    {
      code: `if (configName.length < 20) { const configPath = configDir + configName + '.conf'; }`,
      correct: false,
      explanation: 'Length validation alone is insufficient. Short traversal sequences like "../../../etc" can be very effective within reasonable length limits.'
    }
  ]
}