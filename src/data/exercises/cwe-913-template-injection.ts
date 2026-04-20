import type { Exercise } from '@/data/exercises'

/**
 * CWE-913 Exercise 3: Server-Side Template Injection
 * Based on dynamic template rendering with untrusted input
 */
export const cwe913TemplateInjection: Exercise = {
  cweId: 'CWE-913',
  name: 'Template Injection - Dynamic Email Generator',

  vulnerableFunction: `function generateEmail(templateString, userData) {
  // Dynamic template processing with user data
  let processedTemplate = templateString;

  // Replace placeholders with user data
  for (const [key, value] of Object.entries(userData)) {
    const placeholder = '{{' + key + '}}';
    processedTemplate = processedTemplate.replace(
      new RegExp(placeholder, 'g'),
      value
    );
  }

  // Process any remaining template expressions
  const expressionRegex = /{{(.+?)}}/g;
  processedTemplate = processedTemplate.replace(expressionRegex, (match, expression) => {
    try {
      return eval(expression);
    } catch (e) {
      return match;
    }
  });

  return processedTemplate;
}`,

  vulnerableLine: `return eval(expression);`,

  options: [
    {
      code: `const SAFE_EXPRESSIONS = /^[a-zA-Z_$][a-zA-Z0-9_$]*$/;
if (!SAFE_EXPRESSIONS.test(expression.trim())) {
  return match; // Return unprocessed if not a simple variable
}
return userData[expression.trim()] || match;`,
      correct: true,
      explanation: `Validate template syntax`
    },
    {
      code: `return eval(expression);`,
      correct: false,
      explanation: 'eval() with user-controlled expressions enables arbitrary code execution. Attackers can inject "process.exit()" or "require(\'fs\').readFileSync(\'/etc/passwd\')".'
    },
    {
      code: `return new Function('return ' + expression)();`,
      correct: false,
      explanation: 'Function constructor is equivalent to eval for code injection. Attackers can still execute arbitrary JavaScript expressions.'
    },
    {
      code: `if (!expression.includes('require')) return eval(expression);`,
      correct: false,
      explanation: 'Blacklisting specific functions is insufficient. Many other dangerous operations exist like global variable access, prototype pollution, or process manipulation.'
    },
    {
      code: `const vm = require('vm');
return vm.runInNewContext(expression, userData);`,
      correct: false,
      explanation: 'vm.runInNewContext can still be exploited through constructor chains and prototype pollution to escape the sandbox and execute code.'
    },
    {
      code: `try {
  return eval(expression);
} catch (e) {
  return 'Error';
}`,
      correct: false,
      explanation: 'Error handling does not prevent code injection. Malicious expressions can execute successfully and cause damage without throwing exceptions.'
    },
    {
      code: `if (expression.length < 20) return eval(expression);`,
      correct: false,
      explanation: 'Length limits do not prevent code injection. Short dangerous payloads like "process.exit()" are within typical limits.'
    },
    {
      code: `const sanitized = expression.replace(/[()]/g, '');
return eval(sanitized);`,
      correct: false,
      explanation: 'Removing parentheses is insufficient. Many dangerous expressions do not require parentheses, such as property access or template literals.'
    },
    {
      code: `if (userData.hasOwnProperty(expression)) {
  return userData[expression];
} else {
  return eval(expression);
}`,
      correct: false,
      explanation: 'Fallback to eval defeats any security benefit. If the expression is not in userData, dangerous code can still be executed.'
    },
    {
      code: `const result = eval('(' + expression + ')');
return typeof result === 'string' ? result : match;`,
      correct: false,
      explanation: 'Type filtering after eval is too late. The dangerous code has already executed, and side effects like file operations have already occurred.'
    }
  ]
}