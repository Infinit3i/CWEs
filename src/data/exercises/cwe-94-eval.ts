import type { Exercise } from '@/data/exercises'

/**
 * CWE-94 Code Injection - Eval Function Vulnerability
 * Based on MITRE demonstrative example DX-156
 */
export const cwe94Eval: Exercise = {
  cweId: 'CWE-94',
  name: 'Code Injection - Calculator Function',
  language: 'JavaScript',

  vulnerableFunction: `function calculateExpression(userInput) {
  try {
    const result = eval(userInput);
    return { success: true, value: result };
  } catch (e) {
    return { success: false, error: 'Invalid expression' };
  }
}`,

  vulnerableLine: `const result = eval(userInput);`,

  options: [
    {
      code: `const allowedOperators = ['+', '-', '*', '/', '(', ')', ' ', '.'];
const allowedChars = /^[0-9+\-*/().\s]+$/;
if (!allowedChars.test(userInput)) throw new Error('Invalid characters');
return { success: true, value: Function('"use strict"; return (' + userInput + ')')() };`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // MITRE demonstrative examples as wrong answers
    {
      code: `const result = eval(userInput);`,
      correct: false,
      explanation: 'Direct from MITRE DX-156: Using eval() on untrusted input allows arbitrary code execution. An attacker can inject __import__("subprocess").getoutput("rm -rf *") to execute system commands.'
    },
    {
      code: `if (userInput.includes('import')) return { success: false, error: 'Blocked' };
const result = eval(userInput);`,
      correct: false,
      explanation: 'Blacklist filtering is insufficient. Attackers can use alternatives like require(), process.exit(), or encoded payloads to bypass simple string checks.'
    },
    {
      code: `const sanitized = userInput.replace(/[^0-9+\-*/().]/g, '');
const result = eval(sanitized);`,
      correct: false,
      explanation: 'Character filtering helps but eval() remains dangerous. Even with limited characters, attacks like eval("1+1;process.exit()") can still work if semicolons slip through.'
    },
    {
      code: `try {
  const result = Function('return ' + userInput)();
  return { success: true, value: result };
} catch (e) { return { success: false, error: e.message }; }`,
      correct: false,
      explanation: 'Function constructor without strict mode is nearly as dangerous as eval(). Attackers can still access global objects and execute arbitrary code through the global scope.'
    },
    {
      code: `const vm = require('vm');
const result = vm.runInNewContext(userInput);`,
      correct: false,
      explanation: 'VM contexts provide some isolation but are not secure against determined attackers. Node.js VM contexts can be escaped through prototype pollution and other techniques.'
    },
    {
      code: `if (userInput.length > 50) return { success: false, error: 'Too long' };
const result = eval(userInput);`,
      correct: false,
      explanation: 'Length limits do not prevent code injection. Short payloads like process.exit(1) or require("fs") can be very effective within character limits.'
    },
    {
      code: `const escaped = userInput.replace(/"/g, '\\"').replace(/'/g, "\\'");
const result = eval(escaped);`,
      correct: false,
      explanation: 'Quote escaping does not prevent code injection when eval() is used. Attackers can construct payloads without quotes or use template literals.'
    },
    {
      code: `if (!userInput.match(/^[0-9+\-*/().\s]+$/)) return { success: false };
const result = eval(userInput);`,
      correct: false,
      explanation: 'Input validation helps but eval() fundamentally allows code execution. Even mathematical expressions can be chained with semicolons or use implicit type conversion for attacks.'
    },
    {
      code: `const result = eval('(' + userInput + ')');`,
      correct: false,
      explanation: 'Wrapping in parentheses does not prevent code injection. Attackers can break out with constructs like "1)+alert(1)+(" or use function expressions within the parentheses.'
    }
  ]
}