import type { Exercise } from '@/data/exercises'

/**
 * CWE-913 Exercise 2: Unsafe Reflection in Command Dispatcher
 * Based on Java reflection vulnerabilities from MITRE examples
 */
export const cwe913ReflectionAbuse: Exercise = {
  cweId: 'CWE-913',
  name: 'Reflection Abuse - Command Dispatcher',

  vulnerableFunction: `function executeCommand(commandName, params) {
  // Dynamic command execution system
  const commandClasses = {
    'UserCommand': UserCommand,
    'FileCommand': FileCommand,
    'DatabaseCommand': DatabaseCommand
  };

  try {
    const CommandClass = commandClasses[commandName + 'Command'];
    if (!CommandClass) {
      throw new Error('Command not found');
    }

    const commandInstance = new CommandClass();
    return commandInstance.execute(params);
  } catch (error) {
    return { error: error.message };
  }
}`,

  vulnerableLine: `const CommandClass = commandClasses[commandName + 'Command'];`,

  options: [
    {
      code: `const ALLOWED_COMMANDS = new Set(['User', 'File', 'Database']);
if (!ALLOWED_COMMANDS.has(commandName)) {
  throw new Error('Unauthorized command');
}
const CommandClass = commandClasses[commandName + 'Command'];`,
      correct: true,
      explanation: `Correct! Allowlisting specific command names prevents unauthorized class instantiation. This blocks attempts to access dangerous classes like "System" or "Process" while allowing only legitimate business commands.`
    },
    {
      code: `const CommandClass = commandClasses[commandName + 'Command'];`,
      correct: false,
      explanation: 'Direct from MITRE: Unchecked dynamic class resolution allows instantiation of unintended classes. Attackers could use "System" to access SystemCommand with elevated privileges.'
    },
    {
      code: `if (typeof global[commandName + 'Command'] === 'function') {
  const CommandClass = global[commandName + 'Command'];
  const commandInstance = new CommandClass();
  return commandInstance.execute(params);
}`,
      correct: false,
      explanation: 'Accessing global scope is even more dangerous, allowing instantiation of any global constructor including built-in dangerous classes.'
    },
    {
      code: `const className = commandName.charAt(0).toUpperCase() + commandName.slice(1) + 'Command';
const CommandClass = commandClasses[className];`,
      correct: false,
      explanation: 'Case normalization does not prevent unauthorized access. Attackers can still reference dangerous classes through proper casing.'
    },
    {
      code: `if (!commandName.includes('System')) {
  const CommandClass = commandClasses[commandName + 'Command'];
}`,
      correct: false,
      explanation: 'Blacklisting specific dangerous names is insufficient. Many other potentially dangerous classes exist beyond just "System".'
    },
    {
      code: `const CommandClass = eval(\`\${commandName}Command\`);`,
      correct: false,
      explanation: 'Using eval makes the vulnerability worse by enabling direct code injection in addition to reflection abuse.'
    },
    {
      code: `if (commandName.length < 10) {
  const CommandClass = commandClasses[commandName + 'Command'];
}`,
      correct: false,
      explanation: 'Length restrictions do not prevent reflection abuse. Short dangerous class names like "OS" or "VM" can fit within the limit.'
    },
    {
      code: `const CommandClass = commandClasses[commandName.toLowerCase() + 'Command'];`,
      correct: false,
      explanation: 'Case conversion does not prevent unauthorized access. Dangerous classes may have lowercase variants or the mapping may include them.'
    },
    {
      code: `if (commandClasses.hasOwnProperty(commandName + 'Command')) {
  const CommandClass = commandClasses[commandName + 'Command'];
}`,
      correct: false,
      explanation: 'hasOwnProperty check does not prevent the core issue - if dangerous classes are in the commandClasses object, they remain accessible.'
    },
    {
      code: `try {
  const CommandClass = commandClasses[commandName + 'Command'];
  if (CommandClass.prototype.constructor === CommandClass) {
    const commandInstance = new CommandClass();
    return commandInstance.execute(params);
  }
} catch {}`,
      correct: false,
      explanation: 'Constructor verification does not prevent reflection abuse. Valid dangerous classes will pass this check and still pose security risks.'
    }
  ]
}