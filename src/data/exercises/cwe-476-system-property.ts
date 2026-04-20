import type { Exercise } from '@/data/exercises'

/**
 * CWE-476 exercise - System Property Access
 * Based on MITRE Java example for NULL pointer dereference
 */
export const cwe476SystemProperty: Exercise = {
  cweId: 'CWE-476',
  name: 'NULL Pointer Dereference - System Property Access',

  vulnerableFunction: `function executeCommand() {
  // Get command from system property
  const cmd = process.env.EXEC_CMD;

  // Trim whitespace and execute
  const trimmedCmd = cmd.trim(); // Potential null dereference
  const result = execSync(trimmedCmd);

  return result.toString();
}`,

  vulnerableLine: `const trimmedCmd = cmd.trim();`,

  options: [
    {
      code: `const cmd = process.env.EXEC_CMD; if (cmd === null || cmd === undefined) { throw new Error('EXEC_CMD environment variable not set'); } const trimmedCmd = cmd.trim();`,
      correct: true,
      explanation: `Correct! This validates the environment variable exists before calling methods on it. The MITRE example shows "if the property doesn't exist, getProperty() returns null, triggering a NullPointerException on trim()".`
    },
    {
      code: `String cmd = System.getProperty("cmd"); cmd = cmd.trim();`,
      correct: false,
      explanation: 'Direct from MITRE: "If the property doesn\'t exist, getProperty() returns null" but the code proceeds to call trim() on NULL, "triggering a NullPointerException".'
    },
    {
      code: `const cmd = process.env.EXEC_CMD; try { const trimmedCmd = cmd.trim(); } catch (error) { return "Command failed"; }`,
      correct: false,
      explanation: 'Exception handling after the fact cannot prevent the NULL dereference crash. The error occurs when accessing properties/methods of NULL, before the catch block can handle it.'
    },
    {
      code: `const cmd = process.env.EXEC_CMD; if (process.env.hasOwnProperty('EXEC_CMD')) { const trimmedCmd = cmd.trim(); }`,
      correct: false,
      explanation: 'Checking property existence using hasOwnProperty() is insufficient because the property can exist but have a NULL or undefined value, which would still cause the dereference error.'
    },
    {
      code: `const cmd = process.env.EXEC_CMD || ''; const trimmedCmd = cmd.trim();`,
      correct: false,
      explanation: 'While this prevents the crash by providing a default empty string, it may not be the intended behavior and could mask configuration errors that should be explicitly handled.'
    },
    {
      code: `let cmd; setTimeout(() => { cmd = process.env.EXEC_CMD; }, 10); const trimmedCmd = cmd.trim();`,
      correct: false,
      explanation: 'Asynchronous assignment does not solve NULL dereference issues and creates race conditions. The trim() call may execute before the assignment completes, accessing undefined.'
    },
    {
      code: `const cmd = process.env.EXEC_CMD; if (typeof cmd === 'string') { const trimmedCmd = cmd.trim(); }`,
      correct: false,
      explanation: 'Type checking is good practice but incomplete. This misses the case where cmd could be null (which has typeof "object" in some contexts) or other falsy values.'
    },
    {
      code: `const cmd = process.env.EXEC_CMD; const hasLength = cmd.length > 0; if (hasLength) { const trimmedCmd = cmd.trim(); }`,
      correct: false,
      explanation: 'Attempting to access the length property of a NULL value will cause the same type of dereference error we are trying to prevent, just at a different location.'
    },
    {
      code: `const cmd = process.env.EXEC_CMD; const isValid = cmd && cmd.constructor === String; if (isValid) { const trimmedCmd = cmd.trim(); }`,
      correct: false,
      explanation: 'Checking the constructor property will fail when cmd is NULL because accessing any property of NULL causes a dereference error before the constructor check can complete.'
    },
    {
      code: `const cmd = JSON.parse(JSON.stringify(process.env.EXEC_CMD)); const trimmedCmd = cmd.trim();`,
      correct: false,
      explanation: 'JSON operations do not prevent NULL dereference. If process.env.EXEC_CMD is NULL, JSON.stringify(null) returns "null" as a string, but this changes the semantics unexpectedly.'
    }
  ]
}