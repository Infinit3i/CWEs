import type { Exercise } from '@/data/exercises'

/**
 * CWE-276 Incorrect Default Permissions - File Creation
 * Based on MITRE CVE examples of world-writable/readable files
 */
export const cwe276File: Exercise = {
  cweId: 'CWE-276',
  name: 'Incorrect Default Permissions - Log File Creation',

  vulnerableFunction: `function createUserLogFile(userId, logData) {
  const logPath = \`/var/logs/user_\${userId}.log\`;

  // Create log file with default permissions
  const fd = fs.openSync(logPath, 'w');
  fs.writeSync(fd, JSON.stringify(logData));
  fs.closeSync(fd);

  return {
    success: true,
    logPath: logPath,
    message: 'Log file created successfully'
  };
}`,

  vulnerableLine: `const fd = fs.openSync(logPath, 'w');`,

  options: [
    {
      code: `const logPath = \`/var/logs/user_\${userId}.log\`;
const fd = fs.openSync(logPath, 'w', 0o600); // Owner read/write only
fs.writeSync(fd, JSON.stringify(logData));
fs.closeSync(fd);
return { success: true, logPath: logPath };`,
      correct: true,
      explanation: `Correct! This explicitly sets file permissions to 0o600 (owner read/write only), following the principle of least privilege. This prevents other users from reading potentially sensitive log data or modifying the log files.`
    },
    // MITRE CVE-inspired wrong answers
    {
      code: `const fd = fs.openSync(logPath, 'w');
fs.writeSync(fd, JSON.stringify(logData));
fs.closeSync(fd);`,
      correct: false,
      explanation: 'Based on MITRE CVE-2002-1713: Using default file permissions often results in world-readable files. On many systems, this creates files with 644 permissions, allowing any user to read potentially sensitive log data.'
    },
    {
      code: `const fd = fs.openSync(logPath, 'w', 0o666); // Read/write for all
fs.writeSync(fd, JSON.stringify(logData));
fs.closeSync(fd);`,
      correct: false,
      explanation: 'Based on MITRE CVE-2005-1941: World-writable files (666 permissions) allow any user to modify log contents, potentially destroying audit trails, injecting false data, or hiding malicious activity.'
    },
    {
      code: `fs.writeFileSync(logPath, JSON.stringify(logData));
// File created with default umask permissions`,
      correct: false,
      explanation: 'Default permissions depend on system umask settings. Without explicit permission setting, files may be created world-readable or even world-writable, exposing sensitive data to unauthorized users.'
    },
    {
      code: `const fd = fs.openSync(logPath, 'w', 0o644); // Owner write, world read
fs.writeSync(fd, JSON.stringify(logData));
fs.closeSync(fd);`,
      correct: false,
      explanation: 'While preventing world-write, 644 permissions still allow all users to read the log file. User logs may contain sensitive information that should only be accessible to the file owner.'
    },
    {
      code: `const fd = fs.openSync(logPath, 'w', 0o755); // Executable permissions
fs.writeSync(fd, JSON.stringify(logData));
fs.closeSync(fd);`,
      correct: false,
      explanation: 'Executable permissions (755) are inappropriate for data files and follow MITRE CVE patterns. This makes the file world-readable and potentially executable, creating security risks.'
    },
    {
      code: `fs.writeFileSync(logPath, JSON.stringify(logData), { mode: 0o777 });
// Full permissions for everyone`,
      correct: false,
      explanation: 'Based on MITRE CVE-2001-1550: 777 permissions are extremely dangerous - world-readable, writable, and executable. This allows any user to read, modify, or execute the file, creating maximum security exposure.'
    },
    {
      code: `const fd = fs.openSync(logPath, 'w', 0o622); // Group write, world read
fs.writeSync(fd, JSON.stringify(logData));
fs.closeSync(fd);`,
      correct: false,
      explanation: 'Group write permissions allow any member of the file\'s group to modify logs, while world-read allows information disclosure. This violates the principle of least privilege for sensitive log data.'
    },
    {
      code: `// Create file then change permissions later
fs.writeFileSync(logPath, JSON.stringify(logData));
fs.chmodSync(logPath, 0o600);`,
      correct: false,
      explanation: 'Race condition vulnerability: between file creation and chmod, the file exists with default (potentially insecure) permissions. Attackers could read or modify the file during this window.'
    },
    {
      code: `const fd = fs.openSync(logPath, 'w');
fs.writeSync(fd, JSON.stringify(logData));
fs.chmodSync(logPath, 0o600); // Set permissions after writing
fs.closeSync(fd);`,
      correct: false,
      explanation: 'Another race condition: the file is created and data is written before secure permissions are applied. During this window, other processes could access the sensitive log data with default permissions.'
    }
  ]
}