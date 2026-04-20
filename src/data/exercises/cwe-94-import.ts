import type { Exercise } from '@/data/exercises'

/**
 * CWE-94 Code Injection - Dynamic Import Vulnerability
 * Based on MITRE patterns for dynamic module loading
 */
export const cwe94Import: Exercise = {
  cweId: 'CWE-94',
  name: 'Code Injection - Plugin System',
  language: 'JavaScript',

  vulnerableFunction: `async function loadPlugin(pluginName, userConfig) {
  const pluginCode = \`
    export default {
      name: '\${pluginName}',
      version: '1.0.0',
      config: \${JSON.stringify(userConfig)},
      execute: function() {
        return this.config.message || 'No message';
      }
    };
  \`;

  const dataUrl = 'data:text/javascript;base64,' + Buffer.from(pluginCode).toString('base64');
  const plugin = await import(dataUrl);
  return plugin.default;
}`,

  vulnerableLine: `const plugin = await import(dataUrl);`,

  options: [
    {
      code: `const allowedPlugins = {
  'weather': () => import('./plugins/weather.js'),
  'calendar': () => import('./plugins/calendar.js'),
  'notes': () => import('./plugins/notes.js')
};
if (!allowedPlugins[pluginName]) throw new Error('Plugin not found');
const plugin = await allowedPlugins[pluginName]();
return plugin.default;`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // Code injection vulnerabilities
    {
      code: `const pluginCode = \`export default { name: '\${pluginName}',
  version: '1.0';
      execute: () => '\${userConfig.message}' };\`;
const dataUrl = 'data:text/javascript;base64,' + Buffer.from(pluginCode).toString('base64');
const plugin = await import(dataUrl);`,
      correct: false,
      explanation: 'Dynamic module generation with user input enables code injection. An attacker can inject userConfig.message: "a\\"; import(\\"fs\\").then(fs => fs.unlinkSync(\\"data.txt\\")) //" to execute arbitrary code in the module context.'
    },
    {
      code: `if (pluginName.match(/^[a-zA-Z0-9_]+$/)) {
  const plugin = await import(\`./plugins/\${pluginName}.js\`);
  return plugin.default;
}
throw new Error('Invalid plugin name');`,
      correct: false,
      explanation: 'While validating the plugin name helps, dynamic imports of user-controlled paths can still be dangerous if attackers can control the plugin files or use path traversal techniques not caught by the regex.'
    },
    {
      code: `const sanitized = pluginName.replace(/[^a-zA-Z0-9]/g, '');
const pluginCode = \`export default { name: '\${sanitized}',
  language: 'JavaScript' };\`;
const blob = new Blob([pluginCode], { type: 'application/javascript' });
const plugin = await import(URL.createObjectURL(blob));`,
      correct: false,
      explanation: 'Creating object URLs from dynamic code is still vulnerable to injection through other parameters. If userConfig or other data sources contain JavaScript code, they can be injected into the module.'
    },
    {
      code: `const vm = require('vm');
const context = { exports: {}, userConfig };
vm.runInNewContext(\`exports.default = { name: '\${pluginName}',
  language: 'JavaScript' }\`, context);
return context.exports.default;`,
      correct: false,
      explanation: 'VM contexts provide limited security. String interpolation with user input can break out of the intended execution context, and VM sandboxes have known escape techniques.'
    },
    {
      code: `const moduleText = \`export default { name: "\${pluginName.replace(/"/g, '\\\\"')}" };\`;
const module = await import(\`data:text/javascript,\${encodeURIComponent(moduleText)}\`);
return module.default;`,
      correct: false,
      explanation: 'Quote escaping and URL encoding do not prevent code injection when generating executable modules. Attackers can use template literals, unicode escapes, or other JavaScript syntax to inject code.'
    },
    {
      code: `if (pluginName.includes('eval') || pluginName.includes('require')) {
  throw new Error('Dangerous keywords blocked');
}
const moduleCode = \`export default function() { return '\${pluginName}'; }\`;
return Function('return ' + moduleCode)();`,
      correct: false,
      explanation: 'Keyword blacklisting is insufficient. Function constructor with user input allows code execution through alternative methods like constructor.constructor or bracket notation access.'
    },
    {
      code: `const pluginPath = path.resolve('./plugins', pluginName + '.js');
if (!pluginPath.startsWith(path.resolve('./plugins'))) {
  throw new Error('Path traversal blocked');
}
return await import('file://' + pluginPath);`,
      correct: false,
      explanation: 'While path traversal protection helps, this approach still allows loading arbitrary files if an attacker can place malicious JavaScript files in the plugins directory through other means.'
    },
    {
      code: `const allowedChars = /^[a-zA-Z0-9_-]+$/;
if (!allowedChars.test(pluginName)) throw new Error('Invalid characters');
const moduleCode = \`export const plugin = { name: '\${pluginName}',
  language: 'JavaScript' };\`;
const worker = new Worker('data:application/javascript,' + moduleCode);
return await new Promise(resolve => worker.onmessage = e => resolve(e.data));`,
      correct: false,
      explanation: 'Web Workers with dynamic code generation are still vulnerable to injection. Even in a worker context, injected JavaScript can access worker APIs and potentially communicate with the main thread maliciously.'
    },
    {
      code: `const config = JSON.parse(JSON.stringify(userConfig));
const moduleCode = \`export default { name: '\${pluginName}',
  language: 'JavaScript', config: \${JSON.stringify(config)} };\`;
const plugin = await import('data:text/javascript,' + moduleCode);
return plugin.default;`,
      correct: false,
      explanation: 'Double JSON serialization does not prevent injection if the original userConfig contains prototype pollution or if pluginName still allows JavaScript injection through string interpolation.'
    }
  ]
}