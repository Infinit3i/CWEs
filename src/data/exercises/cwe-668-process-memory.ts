import type { Exercise } from '@/data/exercises'

export const cwe668ProcessMemory: Exercise = {
  cweId: 'CWE-668',
  name: 'Exposure of Resource to Wrong Sphere - Process Memory Access',

  vulnerableFunction: `function debugProcessInfo(processName) {
  const { exec } = require('child_process');

  return new Promise((resolve, reject) => {
    const command = \`ps aux | grep \${processName}\`;

    exec(command, (error, stdout, stderr) => {
      if (error) {
        reject(error);
        return;
      }

      resolve(stdout);
    });
  });
}`,

  vulnerableLine: `const command = \`ps aux | grep \${processName}\`;`,

  options: [
    {
      code: `const sanitizedName = processName.replace(/[^a-zA-Z0-9_-]/g, ''); const command = \`ps -o pid,comm -C \${sanitizedName}\`;`,
      correct: true,
      explanation: `Correct! Sanitizing input and using specific ps flags (-o for output format, -C for command name) limits information exposure to only PID and command name, preventing access to sensitive process details like arguments and user contexts.`
    },
    {
      code: `const command = \`ps aux | grep \${processName}\`;`,
      correct: false,
      explanation: 'Direct from MITRE: ps aux exposes all process information including command arguments, user contexts, and memory usage for all users. This violates sphere boundaries by exposing system-wide process data.'
    },
    {
      code: `const command = \`ps -ef | grep \${processName}\`;`,
      correct: false,
      explanation: 'ps -ef shows full command lines including arguments which may contain passwords, API keys, or other sensitive data. This exposes process information across user spheres.'
    },
    {
      code: `const command = \`ps axo pid,comm,args | grep \${processName}\`;`,
      correct: false,
      explanation: 'Including args in the output exposes command-line arguments that may contain sensitive information like database passwords or configuration paths.'
    },
    {
      code: `const command = \`ps aux | grep \${processName} | grep -v grep\`;`,
      correct: false,
      explanation: 'Filtering out the grep process itself does not address the core issue of exposing detailed process information from all users and system spheres.'
    },
    {
      code: `const command = \`ps u -C \${processName}\`;`,
      correct: false,
      explanation: 'The "u" flag shows user-oriented information including CPU/memory usage and start times, which may leak information about system resource usage patterns.'
    },
    {
      code: `const command = \`pgrep \${processName}\`;`,
      correct: false,
      explanation: 'While pgrep only returns PIDs, the unsanitized process name could still be exploited for command injection, allowing access to unintended system information.'
    },
    {
      code: `const command = \`ps | grep \${processName}\`;`,
      correct: false,
      explanation: 'Basic ps without flags still shows process information, and the unsanitized process name parameter allows potential command injection to access broader system information.'
    }
  ]
}