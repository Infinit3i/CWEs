import type { Exercise } from '@/data/exercises'

export const cwe732DirectoryCreation: Exercise = {
  cweId: 'CWE-732',
  name: 'Incorrect Permission Assignment - User Directory Setup',

  vulnerableFunction: `function createUserWorkspace(username) {
  const fs = require('fs');
  const path = '/opt/workspaces/' + username;

  // Create user directory with default permissions
  fs.mkdirSync(path, { recursive: true });

  // Set ownership after creation
  const { execSync } = require('child_process');
  execSync(\`chown \${username}:\${username} \${path}\`);

  return path;
}`,

  vulnerableLine: `fs.mkdirSync(path, { recursive: true });`,

  options: [
    {
      code: `fs.mkdirSync(path, { recursive: true, mode: 0o700 });`,
      correct: true,
      explanation: `Correct! Mode 0o700 creates the directory with read/write/execute permissions only for the owner. This prevents other users from accessing the workspace during the window between creation and ownership change.`
    },
    {
      code: `fs.mkdirSync(path, { recursive: true });`,
      correct: false,
      explanation: 'Direct from MITRE: Default permissions typically create world-readable directories (0o755). Other users can access the workspace before ownership is applied.'
    },
    {
      code: `fs.mkdirSync(path, { recursive: true, mode: 0o755 });`,
      correct: false,
      explanation: 'Mode 0o755 allows all users to read and traverse the directory. From MITRE examples showing race conditions in directory creation.'
    },
    {
      code: `fs.mkdirSync(path, { recursive: true, mode: 0o777 });`,
      correct: false,
      explanation: 'Mode 0o777 grants full permissions to everyone. Critical security flaw allowing any user to modify workspace contents.'
    },
    {
      code: `fs.mkdirSync(path, { recursive: true, mode: 0o644 });`,
      correct: false,
      explanation: 'Mode 0o644 on directories prevents traversal. This would make the directory unusable even for the intended owner.'
    },
    {
      code: `fs.mkdirSync(path, { recursive: true, mode: 0o750 });`,
      correct: false,
      explanation: 'Mode 0o750 allows group members to access the workspace. Broader access than necessary for user-specific directories.'
    },
    {
      code: `fs.mkdirSync(path, { recursive: true, mode: 0o711 });`,
      correct: false,
      explanation: 'Mode 0o711 allows others to traverse the directory if they know the path. Still provides unnecessary access to other users.'
    },
    {
      code: `fs.mkdirSync(path, { recursive: true, mode: 0o666 });`,
      correct: false,
      explanation: 'Mode 0o666 on directories is invalid - execute permission is required for directory access. Would create unusable directories.'
    }
  ]
}