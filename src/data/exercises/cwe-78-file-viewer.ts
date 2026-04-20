import type { Exercise } from '@/data/exercises'

export const cwe78FileViewer: Exercise = {
  cweId: 'CWE-78',
  name: 'OS Command Injection - File Content Viewer',

  vulnerableFunction: `function viewFileContent(fileName) {
  const { exec } = require('child_process');

  // Use cat command to display file contents
  const catCommand = 'cat ';
  const command = catCommand + fileName;

  return new Promise((resolve, reject) => {
    exec(command, (error, stdout, stderr) => {
      if (error) {
        reject(new Error('Failed to read file: ' + error.message));
      } else {
        resolve({
          content: stdout,
          size: stdout.length,
          file: fileName
        });
      }
    });
  });
}`,

  vulnerableLine: `const command = catCommand + fileName;`,

  options: [
    {
      code: `const fs = require('fs'); return fs.promises.readFile(fileName, 'utf8');`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `const command = catCommand + fileName;`,
      correct: false,
      explanation: 'MITRE cat command pattern: User filename directly concatenated into shell command. Attacker can inject commands like "file.txt; rm -rf /" or "file.txt && wget malicious_url" to execute arbitrary system commands.'
    },
    {
      code: `const command = catCommand + fileName.replace(';', '');`,
      correct: false,
      explanation: 'Removing only semicolons insufficient. Attackers can use other command separators like && (file && cmd), || (file || cmd), | (file | cmd), or backticks for command substitution.'
    },
    {
      code: `const sanitized = fileName.replace(/[^a-zA-Z0-9._/-]/g, ''); const command = catCommand + sanitized;`,
      correct: false,
      explanation: 'Character filtering helps but shell interpretation still dangerous. Even with limited characters, path traversal like "../../../etc/passwd" can access sensitive system files.'
    },
    {
      code: `if (fileName.includes('..')) { throw new Error('Invalid path'); } const command = catCommand + fileName;`,
      correct: false,
      explanation: 'User input allows command injection'
    },
    {
      code: `const command = ['cat', fileName]; require('child_process').execFile('cat', [fileName], callback);`,
      correct: false,
      explanation: 'Using execFile with array is better but still risky if fileName contains shell metacharacters. Native file reading APIs are safer than any external command execution.'
    },
    {
      code: `const command = catCommand + JSON.stringify(fileName);`,
      correct: false,
      explanation: 'JSON.stringify adds quotes but shell can interpret escaped content or break out using command substitution, backticks, or other injection techniques.'
    },
    {
      code: `if (fileName.match(/^[a-zA-Z0-9._-]+$/)) { const command = catCommand + fileName; }`,
      correct: false,
      explanation: 'Input validation reduces risk but shell execution still creates unnecessary attack surface. Native file APIs provide better security and performance.'
    },
    {
      code: `const command = catCommand + encodeURIComponent(fileName);`,
      correct: false,
      explanation: 'URL encoding does not prevent shell command injection. The shell still interprets special characters after decoding, allowing command execution.'
    },
    {
      code: `try { const command = catCommand + fileName; exec(command, callback); } catch(e) { reject(e); }`,
      correct: false,
      explanation: 'Exception handling does not prevent command injection. Malicious commands execute during shell invocation before exception handling can intervene.'
    }
  ]
}