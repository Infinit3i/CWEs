import type { Exercise } from '@/data/exercises'

/**
 * CWE-841: Improper Enforcement of Behavioral Workflow - Authentication Sequence
 * Based on MITRE FTP example where authentication can be bypassed in sequence
 */
export const cwe841AuthenticationSequence: Exercise = {
  cweId: 'CWE-841',
  name: 'Improper Enforcement of Behavioral Workflow - FTP Authentication',

  vulnerableFunction: `function handleFtpCommand(command, args, sessionState) {
  if (command === 'USER') {
    sessionState.username = args;
    return 'Username accepted';
  }

  if (command === 'PASS') {
    const isValid = validatePassword(sessionState.username, args);
    if (isValid) {
      sessionState.authenticated = true;
      return 'Authentication successful';
    }
    return 'Authentication failed';
  }

  if (command === 'LIST') {
    return listFiles(sessionState.currentDirectory);
  }

  if (command === 'RETR') {
    if (!sessionState.authenticated) {
      return 'Authentication required';
    }
    return retrieveFile(args);
  }

  return 'Unknown command';
}`,

  vulnerableLine: `if (command === 'LIST') {`,

  options: [
    {
      code: `if (command === 'LIST' && sessionState.authenticated) {`,
      correct: true,
      explanation: `Correct! Enforces authentication before allowing directory listing. This follows MITRE's pattern where all file operations must occur after proper authentication workflow completion, preventing unauthorized directory enumeration.`
    },
    {
      code: `if (command === 'LIST') { // No authentication check`,
      correct: false,
      explanation: 'Direct MITRE vulnerability pattern. Allows directory listing without authentication, violating the required login workflow sequence and exposing file system structure to unauthorized users.'
    },
    {
      code: `if (command === 'LIST' && sessionState.username) {`,
      correct: false,
      explanation: 'Checks username but not authentication status. Users can list files after providing username without completing password verification, bypassing the authentication workflow.'
    },
    {
      code: `if (command === 'LIST' && sessionState.currentDirectory) {`,
      correct: false,
      explanation: 'Validates directory state but ignores authentication workflow. Any session with a directory set can list files regardless of authentication completion, violating access control sequence.'
    },
    {
      code: `if (command === 'LIST' && args !== '/root') {`,
      correct: false,
      explanation: 'Path-based restriction but no authentication requirement. Unauthenticated users can list any directory except /root, still violating the authentication-before-access workflow requirement.'
    },
    {
      code: `if (command === 'LIST') { if (!sessionState.authenticated) return 'Warning: not authenticated'; return listFiles();`,
      correct: false,
      explanation: 'Warns about authentication but still executes command. The workflow violation occurs as directory listing proceeds without enforcing the mandatory authentication prerequisite.'
    },
    {
      code: `if (command === 'LIST' && (sessionState.authenticated || args === 'public')) {`,
      correct: false,
      explanation: 'Creates exception for public listings, violating consistent workflow enforcement. Attackers can bypass authentication by requesting public directory, subverting the login sequence requirement.'
    },
    {
      code: `if (command === 'LIST' && sessionState.connectionTime > 0) {`,
      correct: false,
      explanation: 'Time-based check instead of authentication workflow. Any established connection can list files regardless of authentication status, completely bypassing the required login sequence.'
    },
    {
      code: `if (command === 'LIST' && sessionState.attempts < 3) {`,
      correct: false,
      explanation: 'Attempt-based access control ignores authentication workflow. Users with few login attempts can list directories without authentication, violating the sequential access requirement.'
    },
    {
      code: `if (command === 'LIST') { const hasPermission = checkQuickPermission(); if (hasPermission) return listFiles();`,
      correct: false,
      explanation: 'Alternative permission check bypasses authentication workflow. Creates unauthorized pathway to file listing that violates the established authentication-first business logic sequence.'
    }
  ]
}