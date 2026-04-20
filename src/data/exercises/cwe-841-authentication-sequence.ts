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
      explanation: `Check authentication before listing files`
    },
    {
      code: `if (command === 'LIST') { // No authentication check`,
      correct: false,
      explanation: 'Lists files without authentication check'
    },
    {
      code: `if (command === 'LIST' && sessionState.username) {`,
      correct: false,
      explanation: 'Username set but password not verified'
    },
    {
      code: `if (command === 'LIST' && sessionState.currentDirectory) {`,
      correct: false,
      explanation: 'Directory exists but user not authenticated'
    },
    {
      code: `if (command === 'LIST' && args !== '/root') {`,
      correct: false,
      explanation: 'Blocks root folder but allows unauthenticated access'
    },
    {
      code: `if (command === 'LIST') { if (!sessionState.authenticated) return 'Warning: not authenticated'; return listFiles();`,
      correct: false,
      explanation: 'Warns but still lists files without authentication'
    },
    {
      code: `if (command === 'LIST' && (sessionState.authenticated || args === 'public')) {`,
      correct: false,
      explanation: 'Public folder bypass skips authentication requirement'
    },
    {
      code: `if (command === 'LIST' && sessionState.connectionTime > 0) {`,
      correct: false,
      explanation: 'Connection time check bypasses login requirement'
    },
    {
      code: `if (command === 'LIST' && sessionState.attempts < 3) {`,
      correct: false,
      explanation: 'Failed attempt count bypasses authentication step'
    },
    {
      code: `if (command === 'LIST') { const hasPermission = checkQuickPermission(); if (hasPermission) return listFiles();`,
      correct: false,
      explanation: 'Permission check bypasses authentication workflow'
    }
  ]
}