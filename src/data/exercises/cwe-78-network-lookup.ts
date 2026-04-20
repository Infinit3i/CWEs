import type { Exercise } from '@/data/exercises'

export const cwe78NetworkLookup: Exercise = {
  cweId: 'CWE-78',
  name: 'OS Command Injection - Network Hostname Lookup',

  vulnerableFunction: `function performNetworkLookup(hostName) {
  const { exec } = require('child_process');
  const nslookupPath = '/usr/bin/nslookup';

  // Perform DNS lookup for hostname
  const command = nslookupPath + ' ' + hostName;

  return new Promise((resolve, reject) => {
    exec(command, (error, stdout, stderr) => {
      if (error) {
        reject(error);
      } else {
        // Return parsed lookup results
        resolve(stdout.split('\n').filter(line => line.trim()));
      }
    });
  });
}`,

  vulnerableLine: `const command = nslookupPath + ' ' + hostName;`,

  options: [
    {
      code: `const sanitizedHost = hostName.replace(/[^a-zA-Z0-9.-]/g, ''); const command = [nslookupPath, sanitizedHost];`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `const command = nslookupPath + ' ' + hostName;`,
      correct: false,
      explanation: 'MITRE Perl pipe command pattern: User input directly concatenated into shell command. Attacker can inject commands like "host; rm -rf /" or "host && cat /etc/passwd" to execute arbitrary system commands through DNS lookup.'
    },
    {
      code: `const command = nslookupPath + ' ' + hostName.replace(';', '');`,
      correct: false,
      explanation: 'Removing only semicolons insufficient. Attackers can use other separators like && (host && cmd), || (host || cmd), | (host | cmd), or backticks for command substitution.'
    },
    {
      code: `const command = nslookupPath + ' ' + hostName.replace(/\s/g, '');`,
      correct: false,
      explanation: 'Removing whitespace does not prevent command injection. Commands can be constructed without spaces using techniques like ${IFS} or other shell metacharacters for separation.'
    },
    {
      code: `const command = nslookupPath + ' ' + encodeURIComponent(hostName);`,
      correct: false,
      explanation: 'URL encoding does not prevent shell command injection. The shell interprets special characters after any URL decoding, allowing command execution.'
    },
    {
      code: `if (hostName.length < 100) { const command = nslookupPath + ' ' + hostName; }`,
      correct: false,
      explanation: 'Length restriction does not prevent command injection. Short but effective payloads like ";id" or "&&whoami" can execute within reasonable hostname length limits.'
    },
    {
      code: `const command = nslookupPath + ' ' + hostName.substring(0, 253);`,
      correct: false,
      explanation: 'DNS length limits do not prevent command injection. Malicious commands can be crafted well within DNS hostname length constraints while still being dangerous.'
    },
    {
      code: `const command = nslookupPath + ' ' + JSON.stringify(hostName);`,
      correct: false,
      explanation: 'JSON.stringify adds quotes but shell can still interpret escaped content or break out using command substitution and other injection techniques.'
    },
    {
      code: `const command = nslookupPath + ' ' + hostName.replace(/[|&]/g, '');`,
      correct: false,
      explanation: 'Partial filtering misses many injection vectors like semicolons, backticks, command substitution $(cmd), newlines, and redirection operators that enable command execution.'
    },
    {
      code: `try { const command = nslookupPath + ' ' + hostName; /* exec */ } catch(e) { throw new Error('Lookup failed'); }`,
      correct: false,
      explanation: 'Exception handling does not prevent command injection. Malicious commands execute during the shell invocation before exception handling can intervene.'
    }
  ]
}