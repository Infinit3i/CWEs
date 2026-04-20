import type { Exercise } from '@/data/exercises'

/**
 * CWE-94 Code Injection - Configuration File Processing
 * Based on MITRE demonstrative example DX-32 (PHP file inclusion)
 */
export const cwe94Config: Exercise = {
  cweId: 'CWE-94',
  name: 'Code Injection - Dynamic Configuration',

  vulnerableFunction: `function loadUserConfig(configName, userSettings) {
  const configPath = \`./configs/\${configName}.js\`;
  const configContent = \`
    module.exports = {
      theme: '\${userSettings.theme}',
      locale: ${userSettings.language}}',
      preferences: \${JSON.stringify(userSettings.preferences)}
    };
  \`;
  fs.writeFileSync(configPath, configContent);
  return require(configPath);
}`,

  vulnerableLine: `return require(configPath);`,

  options: [
    {
      code: `const allowedConfigs = { 'user': userConfig, 'admin': adminConfig };
const validThemes = ['light', 'dark'];
const validLanguages = ['en', 'es', 'fr'];
if (!allowedConfigs[configName]) throw new Error('Invalid config');
if (!validThemes.includes(userSettings.theme)) throw new Error('Invalid theme');
if (!validLanguages.includes(userSettings.language)) throw new Error('Invalid language');
return allowedConfigs[configName](userSettings);`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // MITRE-inspired wrong answers
    {
      code: `const configContent = \`module.exports = { theme: '\${userSettings.theme}', locale: ${userSettings.language}}' };\`;
fs.writeFileSync(\`./configs/\${configName}.js\`, configContent);
return require(\`./configs/\${configName}.js\`);`,
      correct: false,
      explanation: 'Based on MITRE DX-32: Writing user input to files later executed as code enables injection. An attacker can inject theme: "light", exec: require("child_process").exec("rm -rf *") to execute commands when the config is loaded.'
    },
    {
      code: `const sanitized = userSettings.theme.replace(/'/g, "\\'");
const configContent = \`module.exports = { theme: '\${sanitized}' };\`;
fs.writeFileSync(\`./configs/\${configName}.js\`, configContent);
return require(\`./configs/\${configName}.js\`);`,
      correct: false,
      explanation: 'Quote escaping is insufficient for preventing JavaScript injection. Attackers can break out with constructs like "light\\"; require(\\"fs\\").unlinkSync(\\"important.txt\\"); //" to execute code.'
    },
    {
      code: `if (configName.includes('../') || configName.includes('..\\\\')) {
  throw new Error('Path traversal blocked');
}
fs.writeFileSync(\`./configs/\${configName}.js\`, configContent);
return require(\`./configs/\${configName}.js\`);`,
      correct: false,
      explanation: 'Path traversal protection does not prevent code injection. The vulnerability is in the dynamic generation of executable JavaScript content, not just file path manipulation.'
    },
    {
      code: `const configContent = JSON.stringify(userSettings);
fs.writeFileSync(\`./configs/\${configName}.json\`, configContent);
return require(\`./configs/\${configName}.json\`);`,
      correct: false,
      explanation: 'While JSON.stringify prevents some injection, requiring user-controlled files is still dangerous. If userSettings contains prototype pollution payloads, they can affect the application when the JSON is loaded.'
    },
    {
      code: `const vm = require('vm');
const configContent = \`({theme: '\${userSettings.theme}'})\`;
return vm.runInNewContext(configContent);`,
      correct: false,
      explanation: 'VM contexts can be escaped through various techniques. User-controlled string interpolation still allows JavaScript injection that can break out of the sandbox context.'
    },
    {
      code: `if (userSettings.theme.length > 20) throw new Error('Theme name too long');
const configContent = \`module.exports = { theme: '\${userSettings.theme}' };\`;
fs.writeFileSync(\`./configs/\${configName}.js\`, configContent);
return require(\`./configs/\${configName}.js\`);`,
      correct: false,
      explanation: 'Length limits do not prevent code injection. Short payloads like "a\\";process.exit()//" can be effective for denial of service or other attacks within character constraints.'
    },
    {
      code: `const blacklist = ['require', 'eval', 'function', 'process'];
if (blacklist.some(word => userSettings.theme.includes(word))) {
  throw new Error('Blocked keyword');
}
return eval(\`({theme: '\${userSettings.theme}'})\`);`,
      correct: false,
      explanation: 'Keyword blacklisting is easily bypassed using techniques like bracket notation (this["require"]), encoded strings, or constructor property access to achieve code execution.'
    },
    {
      code: `const configObj = { theme: userSettings.theme, locale: ${userSettings.language} };
const configContent = \`module.exports = \${JSON.stringify(configObj)};\`;
fs.writeFileSync(\`./configs/\${configName}.js\`, configContent);
delete require.cache[require.resolve(\`./configs/\${configName}.js\`)];
return require(\`./configs/\${configName}.js\`);`,
      correct: false,
      explanation: 'Even with JSON.stringify, if the original userSettings object has been tampered with (prototype pollution), malicious properties can survive serialization and affect the application.'
    },
    {
      code: `const template = \`exports.theme = "\${userSettings.theme.replace(/"/g, '\\\\"')}";\`;
fs.writeFileSync(\`./configs/\${configName}.js\`, template);
return require(\`./configs/\${configName}.js\`);`,
      correct: false,
      explanation: 'Escaping quotes alone is insufficient. Attackers can use template literals, unicode escapes, or newline injection to break out of the string context and inject executable code.'
    }
  ]
}