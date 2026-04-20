import type { Exercise } from '@/data/exercises'

export const cwe78FileListing: Exercise = {
  cweId: 'CWE-78',
  name: 'OS Command Injection - Directory Listing',

  vulnerableFunction: `function listUserFiles(userName) {
  const { exec } = require('child_process');

  // List files in user's home directory
  const command = 'ls -l /home/' + userName;

  return new Promise((resolve, reject) => {
    exec(command, (error, stdout, stderr) => {
      if (error) {
        reject(error);
      } else {
        resolve(stdout);
      }
    });
  });
}`,

  vulnerableLine: `const command = 'ls -l /home/' + userName;`,

  options: [
    {
      code: `const command = ['ls', '-l', '/home/' + userName.replace(/[^a-zA-Z0-9_-]/g, '')];`,
      correct: true,
      explanation: `Use array arguments to prevent injection`
    },
    {
      code: `const command = 'ls -l /home/' + userName;`,
      correct: false,
      explanation: '      explanation: 'User input allows command injection'
    },
    {
      code: `const command = 'ls -l /home/' + userName.replace(';', '');`,
      correct: false,
      explanation: 'Removing semicolons only misses other separators'
    },
    {
      code: `const command = 'ls -l /home/' + encodeURIComponent(userName);`,
      correct: false,
      explanation: 'URL encoding does not prevent command injection in shell context. The shell still interprets special characters after URL decoding, allowing command injection attacks.'
    },
    {
      code: `const command = 'ls -l /home/' + JSON.stringify(userName);`,
      correct: false,
      explanation: 'JSON.stringify adds quotes but does not prevent shell injection. Commands like user"; rm -rf /" can escape the quotes and execute arbitrary commands.'
    },
    {
      code: `const command = 'ls -l /home/' + userName.substring(0, 20);`,
      correct: false,
      explanation: 'Length truncation does not prevent command injection. Short payloads like ";rm *" or "&&id" can be very effective within the character limit.'
    },
    {
      code: `const command = 'ls -l /home/' + userName.toLowerCase();`,
      correct: false,
      explanation: 'Case conversion does not prevent command injection. Lowercase shell commands and metacharacters like ";", "&&", "||" remain functional for injection attacks.'
    },
    {
      code: `const command = 'ls -l /home/' + userName.replace(/[<>]/g, '');`,
      correct: false,
      explanation: 'Removing only redirect operators is insufficient. Command injection uses many other metacharacters like semicolons, pipes, and command substitution that remain dangerous.'
    },
    {
      code: `const command = 'ls -l /home/' + userName.trim();`,
      correct: false,
      explanation: 'Trimming whitespace does not address command injection. Malicious commands can be crafted without leading/trailing spaces while still containing dangerous metacharacters.'
    },
    {
      code: `if (userName.includes('..')) { throw new Error('Invalid path'); } const command = 'ls -l /home/' + userName;`,
      correct: false,
      explanation: '      explanation: 'User input allows command injection'
    }
  ]
}