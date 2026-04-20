import type { Exercise } from '@/data/exercises'

/**
 * CWE-276 Incorrect Default Permissions - Temporary Files
 * Based on insecure temporary file creation patterns
 */
export const cwe276Temp: Exercise = {
  cweId: 'CWE-276',
  name: 'Incorrect Default Permissions - Session Storage',

  vulnerableFunction: `function saveUserSession(sessionId, userData) {
  const tempDir = '/tmp';
  const sessionFile = path.join(tempDir, \`session_\${sessionId}.tmp\`);

  const sessionData = {
    userId: userData.userId,
    authToken: userData.authToken,
    permissions: userData.permissions,
    timestamp: Date.now()
  };

  fs.writeFileSync(sessionFile, JSON.stringify(sessionData, null, 2));

  return {
    success: true,
    sessionFile: sessionFile,
    expiresIn: 3600
  };
}`,

  vulnerableLine: `fs.writeFileSync(sessionFile, JSON.stringify(sessionData, null, 2));`,

  options: [
    {
      code: `const crypto = require('crypto');
const tempDir = os.tmpdir();
const randomName = crypto.randomBytes(16).toString('hex');
const sessionFile = path.join(tempDir, \`session_\${randomName}.tmp\`);
fs.writeFileSync(sessionFile, JSON.stringify(sessionData), { mode: 0o600 });
// Set cleanup timer
setTimeout(() => { try { fs.unlinkSync(sessionFile); } catch(e) {} }, 3600000);
return { success: true, sessionFile };`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // Permission vulnerabilities
    {
      code: `fs.writeFileSync(sessionFile, JSON.stringify(sessionData, null, 2));`,
      correct: false,
      explanation: 'Creating temporary files with default permissions often results in world-readable files (644). Session data containing auth tokens and user permissions becomes accessible to any user on the system, leading to session hijacking.'
    },
    {
      code: `fs.writeFileSync(sessionFile, JSON.stringify(sessionData), { mode: 0o644 });`,
      correct: false,
      explanation: 'World-readable permissions (644) on session files allow any user to read authentication tokens and user permissions. Attackers can steal sessions and impersonate legitimate users.'
    },
    {
      code: `fs.writeFileSync(sessionFile, JSON.stringify(sessionData), { mode: 0o666 });`,
      correct: false,
      explanation: 'World-writable permissions (666) are extremely dangerous for session files. Attackers can read existing sessions and modify session data to escalate privileges or inject malicious permissions.'
    },
    {
      code: `const sessionFile = \`/tmp/session_\${userData.userId}.tmp\`;
fs.writeFileSync(sessionFile, JSON.stringify(sessionData), { mode: 0o600 });`,
      correct: false,
      explanation: 'While permissions are secure, predictable filenames based on user IDs allow attackers to guess session file locations. Combined with directory traversal or timing attacks, this could expose session data.'
    },
    {
      code: `fs.writeFileSync(sessionFile, JSON.stringify(sessionData), { mode: 0o755 });`,
      correct: false,
      explanation: 'Executable permissions (755) are inappropriate for data files and make session files world-readable. Authentication tokens become accessible to all users, and the execute bit could enable unexpected behavior.'
    },
    {
      code: `// Create file first, then secure it
fs.writeFileSync(sessionFile, JSON.stringify(sessionData));
fs.chmodSync(sessionFile, 0o600);`,
      correct: false,
      explanation: 'Race condition vulnerability: the session file exists with default permissions before chmod secures it. During this window, other processes could read authentication tokens and session data.'
    },
    {
      code: `fs.writeFileSync(sessionFile, JSON.stringify(sessionData), { mode: 0o640 });`,
      correct: false,
      explanation: 'Group-readable permissions (640) allow any member of the file\'s group to read session data including authentication tokens. This violates the principle of least privilege for sensitive session information.'
    },
    {
      code: `const oldUmask = process.umask(0o022);
fs.writeFileSync(sessionFile, JSON.stringify(sessionData));
process.umask(oldUmask);`,
      correct: false,
      explanation: 'Setting umask to 022 creates files with 644 permissions by default, making session files world-readable. Authentication tokens and user permissions become accessible to any system user.'
    },
    {
      code: `fs.mkdirSync(path.dirname(sessionFile), { recursive: true, mode: 0o777 });
fs.writeFileSync(sessionFile, JSON.stringify(sessionData), { mode: 0o600 });`,
      correct: false,
      explanation: 'While the file has secure permissions, creating the parent directory with 777 permissions allows any user to list, create, or delete files in that directory, potentially exposing or removing session files.'
    }
  ]
}