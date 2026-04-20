import type { Exercise } from '@/data/exercises'

export const cwe78CoordinateConverter: Exercise = {
  cweId: 'CWE-78',
  name: 'OS Command Injection - Coordinate Conversion',

  vulnerableFunction: `function convertCoordinates(latlonCoords) {
  const { exec } = require('child_process');

  // Convert latitude/longitude to UTM using external tool
  const command = 'latlon2utm.exe -' + latlonCoords;

  return new Promise((resolve, reject) => {
    exec(command, (error, stdout, stderr) => {
      if (error) {
        reject(error);
      } else {
        resolve(stdout.trim());
      }
    });
  });
}`,

  vulnerableLine: `const command = 'latlon2utm.exe -' + latlonCoords;`,

  options: [
    {
      code: `const sanitizedCoords = latlonCoords.replace(/[^0-9.,-]/g, ''); const command = ['latlon2utm.exe', '-' + sanitizedCoords];`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `const command = 'latlon2utm.exe -' + latlonCoords;`,
      correct: false,
      explanation: 'MITRE Java Runtime.exec pattern: User coordinates directly concatenated into command execution. Attacker can inject commands like "1,2; rm -rf /" or "1,2 && wget malicious_url" to execute arbitrary system commands.'
    },
    {
      code: `const command = 'latlon2utm.exe -' + latlonCoords.replace(';', '');`,
      correct: false,
      explanation: 'Removing only semicolons is insufficient. Attackers can use other command separators like && (coords && cmd), | (coords | cmd), or backticks `cmd` for command substitution.'
    },
    {
      code: `const command = 'latlon2utm.exe -' + encodeURIComponent(latlonCoords);`,
      correct: false,
      explanation: 'URL encoding does not prevent command injection in shell execution context. Special characters remain interpretable by the shell after processing.'
    },
    {
      code: `const command = 'latlon2utm.exe -' + latlonCoords.substring(0, 50);`,
      correct: false,
      explanation: 'Length limitation does not prevent command injection. Compact malicious payloads like ";id" or "&&whoami" fit easily within character limits while remaining dangerous.'
    },
    {
      code: `if (latlonCoords.match(/^[\d.,-]+$/)) { const command = 'latlon2utm.exe -' + latlonCoords; }`,
      correct: false,
      explanation: 'Input validation helps but string concatenation still creates shell injection risk. Even with validation, using array syntax or proper escaping provides better security.'
    },
    {
      code: `const command = 'latlon2utm.exe -' + JSON.stringify(latlonCoords);`,
      correct: false,
      explanation: 'JSON.stringify adds quotes but does not prevent shell command injection. Attackers can escape quotes or use command substitution to break out of string context.'
    },
    {
      code: `const command = 'latlon2utm.exe -' + latlonCoords.replace(/[|&;]/g, '');`,
      correct: false,
      explanation: 'Partial character filtering misses other injection vectors like backticks `cmd`, $() command substitution, newlines, and redirection operators that enable command execution.'
    },
    {
      code: `try { const command = 'latlon2utm.exe -' + latlonCoords; exec(command, callback); } catch(e) { /* handle */ }`,
      correct: false,
      explanation: 'Exception handling does not prevent command injection. Malicious commands execute before any exception handling can intervene to stop the attack.'
    },
    {
      code: `const command = 'latlon2utm.exe -' + latlonCoords.toLowerCase();`,
      correct: false,
      explanation: 'User input allows command injection'
    }
  ]
}