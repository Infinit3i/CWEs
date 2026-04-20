import type { Exercise } from '@/data/exercises'

/**
 * CWE-913 Exercise 5: Unsafe Deserialization Leading to RCE
 * Based on Python pickle and Node.js deserialization vulnerabilities
 */
export const cwe913DeserializationRce: Exercise = {
  cweId: 'CWE-913',
  name: 'Unsafe Deserialization - Session Recovery',

  vulnerableFunction: `function deserializeUserSession(serializedData) {
  try {
    // Parse the serialized session data
    const sessionObject = JSON.parse(serializedData);

    // Check if it contains executable code for session restoration
    if (sessionObject.restoreCode) {
      // Execute restoration code to rebuild session state
      const restoreFunction = new Function('session', sessionObject.restoreCode);
      restoreFunction(sessionObject);
    }

    // Process any initialization functions
    if (sessionObject.initFunctions) {
      for (const funcCode of sessionObject.initFunctions) {
        const initFunc = new Function(funcCode);
        initFunc();
      }
    }

    return sessionObject;
  } catch (error) {
    return { error: 'Invalid session data' };
  }
}`,

  vulnerableLine: `const restoreFunction = new Function('session', sessionObject.restoreCode);`,

  options: [
    {
      code: `// Remove any executable code from deserialization
delete sessionObject.restoreCode;
delete sessionObject.initFunctions;
// Only use static data properties
return {
  userId: sessionObject.userId,
  username: sessionObject.username,
  preferences: sessionObject.preferences || {}
};`,
      correct: true,
      explanation: `Correct! Avoiding execution of deserialized code and only using static data properties prevents RCE. This approach treats serialized data as pure data rather than executable content, blocking injection of malicious JavaScript.`
    },
    {
      code: `const restoreFunction = new Function('session', sessionObject.restoreCode);`,
      correct: false,
      explanation: 'Direct from MITRE: Executing code from deserialized data enables RCE. Attackers can inject "require(\'child_process\').exec(\'malicious-command\')" to achieve system compromise.'
    },
    {
      code: `eval(sessionObject.restoreCode);`,
      correct: false,
      explanation: 'eval() makes the vulnerability even worse by executing code in the current scope with access to all local variables and global objects.'
    },
    {
      code: `if (typeof sessionObject.restoreCode === 'string' && sessionObject.restoreCode.length < 100) {
  const restoreFunction = new Function('session', sessionObject.restoreCode);
  restoreFunction(sessionObject);
}`,
      correct: false,
      explanation: 'Length and type validation do not prevent code injection. Short malicious payloads like "process.exit()" can cause significant damage.'
    },
    {
      code: `const vm = require('vm');
vm.runInNewContext(sessionObject.restoreCode, {session: sessionObject});`,
      correct: false,
      explanation: 'vm.runInNewContext can be escaped through prototype pollution and constructor chains, allowing attackers to break out of the sandbox.'
    },
    {
      code: `if (!sessionObject.restoreCode.includes('require') && !sessionObject.restoreCode.includes('process')) {
  const restoreFunction = new Function('session', sessionObject.restoreCode);
  restoreFunction(sessionObject);
}`,
      correct: false,
      explanation: 'Blacklisting specific dangerous functions is insufficient. Many other attack vectors exist including global object access and prototype manipulation.'
    },
    {
      code: `try {
  const restoreFunction = new Function('session', 'return ' + sessionObject.restoreCode);
  const result = restoreFunction(sessionObject);
  if (typeof result === 'object') sessionObject = result;
} catch {}`,
      correct: false,
      explanation: 'Wrapping in return statement and error handling does not prevent code execution. The malicious code still runs before the return.'
    },
    {
      code: `if (sessionObject.restoreCode && sessionObject.restoreCode.match(/^[a-zA-Z0-9.\\s=]+$/)) {
  const restoreFunction = new Function('session', sessionObject.restoreCode);
  restoreFunction(sessionObject);
}`,
      correct: false,
      explanation: 'Regular expression filtering can be bypassed and may break legitimate code. Also, allowed characters can still form dangerous expressions.'
    },
    {
      code: `const worker = new Worker('data:application/javascript,' + sessionObject.restoreCode);`,
      correct: false,
      explanation: 'Web Workers do not prevent code execution - they just isolate it. The malicious code still runs and can potentially communicate back to the main thread.'
    },
    {
      code: `setTimeout(() => {
  const restoreFunction = new Function('session', sessionObject.restoreCode);
  restoreFunction(sessionObject);
}, 0);`,
      correct: false,
      explanation: 'Asynchronous execution does not prevent the vulnerability - it just delays the attack and may make detection and prevention harder.'
    }
  ]
}