import type { Exercise } from '@/data/exercises'

/**
 * CWE-913 Exercise 1: Code Injection via eval()
 * Based on MITRE demonstrative examples for dynamic code execution
 */
export const cwe913EvalInjection: Exercise = {
  cweId: 'CWE-913',
  name: 'Code Injection - Expression Evaluator',
  language: 'JavaScript',

  vulnerableFunction: `function calculateExpression(userExpression, variables) {
  // Create a context with user variables
  let context = '';
  for (const [name, value] of Object.entries(variables)) {
    context += \`const \${name} = \${JSON.stringify(value)}; \`;
  }

  // Evaluate the user's mathematical expression
  const fullCode = context + \`return (\${userExpression});\`;

  try {
    return new Function(fullCode)();
  } catch (error) {
    return 'Invalid expression';
  }
}`,

  vulnerableLine: `return new Function(fullCode)();`,

  options: [
    {
      code: `const ALLOWED_TOKENS = /^[0-9+\\-*/().\\s]+$/;
if (!ALLOWED_TOKENS.test(userExpression)) throw new Error('Invalid characters');
return new Function(fullCode)();`,
      correct: true,
      explanation: `Avoid eval with dynamic input`
    },
    {
      code: `return new Function(fullCode)();`,
      correct: false,
      explanation: 'Dynamic code execution with user input allows arbitrary JavaScript injection. Attackers can execute "process.exit()" or "require(\'child_process\').exec(\'rm -rf /\')".'
    },
    {
      code: `return eval(fullCode);`,
      correct: false,
      explanation: 'eval() is even more dangerous than Function constructor, providing direct access to the current scope and all variables.'
    },
    {
      code: `if (!userExpression.includes('require')) return new Function(fullCode)();`,
      correct: false,
      explanation: 'Blacklisting specific keywords is insufficient. Attackers can use global variables, prototype pollution, or other JavaScript features for code execution.'
    },
    {
      code: `const vm = require('vm');
return vm.runInThisContext(fullCode);`,
      correct: false,
      explanation: 'vm.runInThisContext still allows dangerous code execution. While it runs in a separate context, it can still access global objects and cause harm.'
    },
    {
      code: `try {
  return new Function(fullCode)();
} catch (e) {
  return 'Safe error';
}`,
      correct: false,
      explanation: 'Error handling does not prevent code injection. Malicious code can execute successfully without throwing exceptions.'
    },
    {
      code: `const sanitized = userExpression.replace(/[^a-zA-Z0-9+\\-*/.()]/g, '');
return new Function(context + \`return (\${sanitized});\`)();`,
      correct: false,
      explanation: 'Character filtering is insufficient and may break legitimate expressions. Also, allowed characters can still form dangerous patterns.'
    },
    {
      code: `if (userExpression.length < 50) return new Function(fullCode)();`,
      correct: false,
      explanation: 'Length limits do not prevent code injection. Short payloads like "process.exit()" or "throw 1" can be very effective.'
    },
    {
      code: `const vm = require('vm');
return vm.runInNewContext(fullCode, {});`,
      correct: false,
      explanation: 'Even with empty context, vm.runInNewContext can access constructor chains and global objects, enabling escape and code execution.'
    },
    {
      code: `setTimeout(() => new Function(fullCode)(), 100);
return 'Processing...';`,
      correct: false,
      explanation: 'Asynchronous execution does not prevent code injection - it just delays the attack and may make detection harder.'
    }
  ]
}