import type { Exercise } from '@/data/exercises'

/**
 * CWE-913 Exercise 4: Dynamic Module Loading Vulnerability
 * Based on unsafe dynamic imports and require() calls
 */
export const cwe913DynamicImport: Exercise = {
  cweId: 'CWE-913',
  name: 'Dynamic Import - Plugin System',
  language: 'JavaScript',

  vulnerableFunction: `async function loadPlugin(pluginName, config) {
  // Dynamic plugin loading system
  try {
    const pluginPath = './plugins/' + pluginName;

    // Load plugin module dynamically
    const plugin = await import(pluginPath);

    // Initialize plugin with configuration
    const instance = new plugin.default(config);

    // Execute plugin initialization
    if (typeof instance.initialize === 'function') {
      await instance.initialize();
    }

    return instance;
  } catch (error) {
    console.error('Plugin loading failed:', error.message);
    return null;
  }
}`,

  vulnerableLine: `const plugin = await import(pluginPath);`,

  options: [
    {
      code: `const ALLOWED_PLUGINS = new Set(['auth', 'logger', 'cache', 'validator']);
if (!ALLOWED_PLUGINS.has(pluginName)) {
  throw new Error('Unauthorized plugin');
}
const plugin = await import(pluginPath);`,
      correct: true,
      explanation: `Whitelist allowed imports`
    },
    {
      code: `const plugin = await import(pluginPath);`,
      correct: false,
      explanation: 'Unchecked dynamic imports allow loading arbitrary modules. Attackers can use directory traversal like "../../dangerous-module" or import system modules with elevated privileges.'
    },
    {
      code: `const plugin = require('./plugins/' + pluginName);`,
      correct: false,
      explanation: 'require() has the same vulnerability as dynamic import() for loading untrusted modules. Both allow arbitrary module execution.'
    },
    {
      code: `if (!pluginName.includes('..')) {
  const plugin = await import(pluginPath);
}`,
      correct: false,
      explanation: 'Blocking only ".." is insufficient. Attackers can use absolute paths, symlinks, or encoded traversal sequences to bypass this check.'
    },
    {
      code: `const plugin = await import(path.join('./plugins/', pluginName));`,
      correct: false,
      explanation: 'path.join does not prevent directory traversal. It normalizes paths but "../" sequences can still escape the intended directory.'
    },
    {
      code: `if (pluginName.match(/^[a-zA-Z0-9_-]+$/)) {
  const plugin = await import('./plugins/' + pluginName + '.js');
}`,
      correct: false,
      explanation: 'Character validation helps but is incomplete. The issue is also unauthorized access to legitimate plugins that may contain vulnerabilities.'
    },
    {
      code: `try {
  const pluginPath = path.resolve('./plugins/', pluginName);
  const plugin = await import(pluginPath);
} catch (e) {
  return null;
}`,
      correct: false,
      explanation: 'path.resolve helps with normalization but does not prevent loading of unauthorized modules. Error handling does not address the core security issue.'
    },
    {
      code: `if (fs.existsSync('./plugins/' + pluginName + '.js')) {
  const plugin = await import(pluginPath + '.js');
}`,
      correct: false,
      explanation: 'File existence checks do not prevent loading dangerous modules. If dangerous files exist in the plugins directory, they will be loaded.'
    },
    {
      code: `const sanitized = pluginName.replace(/\\//g, '');
const plugin = await import('./plugins/' + sanitized);`,
      correct: false,
      explanation: 'Removing slashes breaks legitimate plugin names and can be bypassed with encoded characters or other traversal methods.'
    },
    {
      code: `if (pluginName.length < 20) {
  const plugin = await import('./plugins/' + pluginName);
}`,
      correct: false,
      explanation: 'Length restrictions do not prevent unauthorized module loading. Short dangerous module names or traversal paths can fit within the limit.'
    }
  ]
}