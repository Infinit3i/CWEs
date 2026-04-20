import type { Exercise } from '@/data/exercises'

/**
 * CWE-502 exercise: Configuration file deserialization
 * Based on configuration loading vulnerabilities
 */
export const cwe502ConfigLoader: Exercise = {
  cweId: 'CWE-502',
  name: 'Deserialization of Untrusted Data - Dynamic Configuration Loader',

  vulnerableFunction: `function loadDynamicConfig(configPath) {
  const fs = require('fs');
  const path = require('path');

  try {
    const configData = fs.readFileSync(configPath, 'utf8');
    let config;

    // Support multiple configuration formats
    if (configPath.endsWith('.json')) {
      config = JSON.parse(configData);
    } else if (configPath.endsWith('.yaml') || configPath.endsWith('.yml')) {
      config = require('js-yaml').load(configData);
    } else if (configPath.endsWith('.js')) {
      config = eval('(' + configData + ')');
    }

    // Apply configuration to global settings
    if (config.globalSettings) {
      Object.assign(global, config.globalSettings);
    }

    // Load plugins if specified
    if (config.plugins) {
      config.plugins.forEach(plugin => {
        if (plugin.code) {
          eval(plugin.code);
        }
      });
    }

    return config;
  } catch (error) {
    console.error('Config loading failed:', error);
    return {};
  }
}`,

  vulnerableLine: `config = eval('(' + configData + ')');`,

  options: [
    {
      code: `function loadDynamicConfig(configPath) {
  const fs = require('fs');
  const allowedKeys = ['database', 'api', 'features', 'logging'];

  if (!configPath.endsWith('.json')) {
    throw new Error('Only JSON configuration files are supported');
  }

  const configData = fs.readFileSync(configPath, 'utf8');
  const rawConfig = JSON.parse(configData);
  const sanitizedConfig = {};

  for (const key of allowedKeys) {
    if (rawConfig[key]) {
      sanitizedConfig[key] = sanitizeConfigValue(rawConfig[key]);
    }
  }

  return sanitizedConfig;
}`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // Configuration deserialization vulnerabilities
    {
      code: `config = eval('(' + configData + ')');`,
      correct: false,
      explanation: 'Direct eval() of configuration files allows arbitrary code execution. Malicious configuration files can contain JavaScript code that executes when the config is loaded.'
    },
    {
      code: `config = require('js-yaml').load(configData);
if (config.globalSettings) {
    Object.assign(global, config.globalSettings);
}`,
      correct: false,
      explanation: 'YAML.load() can execute arbitrary code through YAML constructors, and Object.assign to global pollutes the global namespace with attacker-controlled properties.'
    },
    {
      code: `config.plugins.forEach(plugin => {
    if (plugin.code) {
        eval(plugin.code);
    }
});`,
      correct: false,
      explanation: 'Plugin system with eval() allows configuration-driven code execution. Attackers can inject malicious plugins through configuration files.'
    },
    {
      code: `const vm = require('vm');
config = vm.runInThisContext('module.exports = ' + configData);`,
      correct: false,
      explanation: 'VM execution of configuration data as code. runInThisContext can access the global scope, allowing malicious configurations to affect the entire application.'
    },
    {
      code: `config = JSON.parse(configData, (key, value) => {
    if (key === 'script' && typeof value === 'string') {
        return new Function(value);
    }
    return value;
});`,
      correct: false,
      explanation: 'JSON.parse reviver function creating executable functions. Configuration files can contain script properties that become executable code during parsing.'
    },
    {
      code: `config = require(configPath);
if (config.initialize) {
    config.initialize();
}`,
      correct: false,
      explanation: 'Dynamic require() of configuration files allows code execution. .js config files can contain malicious code that executes during require() or initialization.'
    },
    {
      code: `const configModule = new Function('module', 'exports', configData);
const module = { exports: {} };
configModule(module, module.exports);
config = module.exports;`,
      correct: false,
      explanation: 'Function constructor execution of configuration data. This approach allows arbitrary code execution while appearing to create modules safely.'
    },
    {
      code: `config = JSON.parse(configData);
for (const key in config.prototype) {
    Object.prototype[key] = config.prototype[key];
}`,
      correct: false,
      explanation: 'Prototype pollution from configuration data. Attackers can inject properties into Object.prototype through configuration files, affecting all objects.'
    },
    {
      code: `const safeEval = require('safe-eval');
config = safeEval('(' + configData + ')', {});`,
      correct: false,
      explanation: 'Safe-eval libraries may have bypasses and vulnerabilities. Even "safe" evaluation can be exploited to execute unintended code or access restricted functionality.'
    },
    {
      code: `config = JSON.parse(configData);
if (config.environment) {
    for (const envVar in config.environment) {
        process.env[envVar] = config.environment[envVar];
    }
}`,
      correct: false,
      explanation: 'Environment variable pollution from configuration. Attackers can modify environment variables that affect application behavior, including NODE_OPTIONS for code execution.'
    }
  ]
}