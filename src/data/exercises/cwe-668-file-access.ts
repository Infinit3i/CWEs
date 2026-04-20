import type { Exercise } from '@/data/exercises'

export const cwe668FileAccess: Exercise = {
  cweId: 'CWE-668',
  name: 'Exposure of Resource to Wrong Sphere - File Access Control',
  language: 'PHP',

  vulnerableFunction: `function downloadUserFile(userId, filename) {
  const path = require('path');
  const fs = require('fs');

  const userDir = '/home/users/' + userId;
  const filePath = path.join(userDir, filename);

  if (fs.existsSync(filePath)) {
    return fs.readFileSync(filePath);
  }

  throw new Error('File not found');
}`,

  vulnerableLine: `const filePath = path.join(userDir, filename);`,

  options: [
    {
      code: `const filePath = path.resolve(userDir, filename); if (!filePath.startsWith(path.resolve(userDir))) throw new Error('Access denied');`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `const filePath = path.join(userDir, filename);`,
      correct: false,
      explanation: 'path.join() does not prevent directory traversal. An attacker can use "../../../etc/passwd" to access system files outside their directory sphere.'
    },
    {
      code: `const filePath = userDir + '/' + filename;`,
      correct: false,
      explanation: 'String concatenation is vulnerable to directory traversal attacks. Similar to MITRE examples where users access files beyond their intended boundary.'
    },
    {
      code: `const filePath = path.join(userDir, filename.replace('..', ''));`,
      correct: false,
      explanation: 'Simple filtering of ".." is insufficient. Attackers can use variations like "....//" or encoded sequences to bypass this protection.'
    },
    {
      code: `const filePath = path.normalize(path.join(userDir, filename));`,
      correct: false,
      explanation: 'path.normalize() resolves ".." sequences but does not prevent access outside the user directory. The normalized path could still point to system files.'
    },
    {
      code: `const filePath = path.join(userDir, filename); if (filename.includes('..')) throw new Error('Invalid filename');`,
      correct: false,
      explanation: 'Checking for ".." in the filename misses other traversal techniques like symbolic links or URL-encoded sequences (%2e%2e).'
    },
    {
      code: `const filePath = path.join(userDir, path.basename(filename));`,
      correct: false,
      explanation: 'While path.basename() prevents some directory traversal, it does not validate that the file belongs to the user or prevent access to other users\' files of the same name.'
    },
    {
      code: `const filePath = path.join(userDir, filename.substring(filename.lastIndexOf('/') + 1));`,
      correct: false,
      explanation: 'Manual path extraction is error-prone and may still allow access to files outside the intended scope if the filename contains unexpected characters.'
    }
  ]
}