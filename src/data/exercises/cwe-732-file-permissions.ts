import type { Exercise } from '@/data/exercises'

export const cwe732FilePermissions: Exercise = {
  cweId: 'CWE-732',
  name: 'Incorrect Permission Assignment - File Creation',

  vulnerableFunction: `function createSecretFile(secretData) {
  const fs = require('fs');
  // Clear umask to ensure specific permissions
  process.umask(0);

  fs.writeFileSync('/tmp/secret.txt', secretData, { mode: 0o666 });
  return '/tmp/secret.txt';
}`,

  vulnerableLine: `fs.writeFileSync('/tmp/secret.txt', secretData, { mode: 0o666 });`,

  options: [
    {
      code: `fs.writeFileSync('/tmp/secret.txt', secretData, { mode: 0o600 });`,
      correct: true,
      explanation: `Correct! Mode 0o600 grants read/write permissions only to the file owner, protecting sensitive data from other users. This follows the principle of least privilege for file access.`
    },
    {
      code: `fs.writeFileSync('/tmp/secret.txt', secretData, { mode: 0o666 });`,
      correct: false,
      explanation: 'Direct from MITRE: Mode 0o666 grants read/write access to owner, group, and others. Any user on the system can read or modify secret data.'
    },
    {
      code: `fs.writeFileSync('/tmp/secret.txt', secretData, { mode: 0o777 });`,
      correct: false,
      explanation: 'Mode 0o777 is extremely dangerous - grants full read/write/execute permissions to all users. From MITRE examples of world-writable files.'
    },
    {
      code: `fs.writeFileSync('/tmp/secret.txt', secretData, { mode: 0o644 });`,
      correct: false,
      explanation: 'Mode 0o644 allows all users to read the file. While not writable by others, secret data becomes readable system-wide.'
    },
    {
      code: `fs.writeFileSync('/tmp/secret.txt', secretData); // Use default permissions`,
      correct: false,
      explanation: 'Default permissions with umask(0) result in 0o666 mode, making the file world-readable and writable.'
    },
    {
      code: `fs.writeFileSync('/tmp/secret.txt', secretData, { mode: 0o755 });`,
      correct: false,
      explanation: 'Mode 0o755 grants read and execute access to group and others. Secret data becomes readable to all system users.'
    },
    {
      code: `fs.writeFileSync('/tmp/secret.txt', secretData, { mode: 0o664 });`,
      correct: false,
      explanation: 'Mode 0o664 allows group and others to read the file. Similar to MITRE examples where group permissions expose sensitive data.'
    },
    {
      code: `fs.writeFileSync('/tmp/secret.txt', secretData, { mode: 0o660 });`,
      correct: false,
      explanation: 'Mode 0o660 grants read/write access to the group. Group members can access and modify secret data, violating least privilege.'
    },
    {
      code: `fs.writeFileSync('/tmp/secret.txt', secretData, { mode: 0o622 });`,
      correct: false,
      explanation: 'Mode 0o622 allows others to write to the file. Attackers could overwrite secret data or inject malicious content.'
    }
  ]
}