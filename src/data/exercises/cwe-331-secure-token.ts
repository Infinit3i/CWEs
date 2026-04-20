import type { Exercise } from '@/data/exercises'

/**
 * CWE-331: Insufficient Entropy - Secure Token Generation
 * Based on MITRE examples showing inadequate randomness for security tokens
 */
export const cwe331SecureToken: Exercise = {
  cweId: 'CWE-331',
  name: 'Insufficient Entropy - Security Token Creation',
  language: 'JavaScript',

  vulnerableFunction: `function generateSecureToken(userId, sessionType) {
  // Use user ID as base entropy
  const userNumber = parseInt(userId) || 1000;

  // Add session type entropy (limited options)
  const sessionTypes = ['admin', 'user', 'guest', 'api'];
  const typeIndex = sessionTypes.indexOf(sessionType) + 1;

  // Use current second as additional entropy
  const currentSecond = Math.floor(Date.now() / 1000) % 60;

  // Combine all entropy sources
  const entropy = userNumber + typeIndex + currentSecond;

  // Generate token from limited entropy
  const tokenBase = entropy.toString(16);
  const token = tokenBase.padStart(32, '0').substring(0, 32);

  return {
    token: token,
    userId: userId,
    sessionType: sessionType,
    algorithm: 'Combined-Limited',
    entropyBits: Math.log2(userNumber * sessionTypes.length * 60),
    entropy: {
      userNumber: userNumber,
      typeIndex: typeIndex,
      second: currentSecond,
      combined: entropy
    }
  };
}`,

  vulnerableLine: `const entropy = userNumber + typeIndex + currentSecond;`,

  options: [
    {
      code: `const crypto = require('crypto'); const tokenBytes = crypto.randomBytes(32); const token = tokenBytes.toString('hex'); return { token: token, userId: userId, sessionType: sessionType, algorithm: 'crypto.randomBytes', entropyBits: 256, entropy: { source: 'Cryptographic random number generator' } };`,
      correct: true,
      explanation: `Use crypto.randomBytes for secure randomness`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `const userNumber = parseInt(userId) || 1000; const sessionTypes = ['admin', 'user', 'guest', 'api']; const typeIndex = sessionTypes.indexOf(sessionType) + 1; const currentSecond = Math.floor(Date.now() / 1000) % 60; const entropy = userNumber + typeIndex + currentSecond; const token = entropy.toString(16).padStart(32, '0').substring(0, 32); return { token, userId, sessionType, algorithm: 'Combined-Limited', entropyBits: Math.log2(userNumber * sessionTypes.length * 60), entropy: { userNumber, typeIndex, second: currentSecond, combined: entropy } };`,
      correct: false,
      explanation: 'Insufficient entropy from predictable sources. User ID, session type (4 options), and current second (60 options) provide very limited total entropy, making tokens guessable.'
    },
    {
      code: `const timestamp = Date.now(); const token = (timestamp % 100000000).toString(16).padStart(32, '0').substring(0, 32); return { token, userId, sessionType, algorithm: 'Timestamp-Direct', entropyBits: Math.log2(100000000), entropy: { timestamp: timestamp, modulo: timestamp % 100000000 } };`,
      correct: false,
      explanation: 'Timestamp as primary entropy. Using timestamp modulo provides limited entropy (~27 bits) and creates predictable patterns in token generation.'
    },
    {
      code: `const userHash = userId.split('').reduce((a, b) => a + b.charCodeAt(0), 0); const typeHash = sessionType.length; const token = (userHash + typeHash).toString(16).padStart(32, '0').substring(0, 32); return { token, userId, sessionType, algorithm: 'Hash-Sum', entropyBits: Math.log2(userHash + typeHash), entropy: { userHash, typeHash, sum: userHash + typeHash } };`,
      correct: false,
      explanation: 'Character code sum entropy. Summing character codes of known strings provides minimal entropy and makes tokens predictable for known user IDs.'
    },
    {
      code: `const pid = process.pid || 1234; const uid = parseInt(userId) || 1; const token = (pid + uid + Date.now() % 1000).toString(16).padStart(32, '0').substring(0, 32); return { token, userId, sessionType, algorithm: 'PID-UID-Time', entropyBits: Math.log2(pid * uid * 1000), entropy: { processId: pid, userId: uid, timeComponent: Date.now() % 1000 } };`,
      correct: false,
      explanation: 'Process ID and user ID entropy. PIDs and UIDs can be observed or predicted, and millisecond timestamps provide limited additional entropy.'
    },
    {
      code: `const dayOfWeek = new Date().getDay(); const hourOfDay = new Date().getHours(); const userMod = parseInt(userId) % 1000; const token = (dayOfWeek * 24 * 1000 + hourOfDay * 1000 + userMod).toString(16).padStart(32, '0').substring(0, 32); return { token, userId, sessionType, algorithm: 'Calendar-User', entropyBits: Math.log2(7 * 24 * 1000), entropy: { dayOfWeek, hourOfDay, userMod } };`,
      correct: false,
      explanation: 'Calendar-based entropy. Day of week, hour, and user modulo provide limited entropy (~17 bits total) and are highly predictable.'
    },
    {
      code: `let sequenceValue = 1; for (let i = 0; i < userId.length; i++) { sequenceValue *= (userId.charCodeAt(i) % 10 + 1); } sequenceValue = sequenceValue % 1000000; const token = sequenceValue.toString(16).padStart(32, '0').substring(0, 32); return { token, userId, sessionType, algorithm: 'Character-Product', entropyBits: Math.log2(1000000), entropy: { sequenceValue } };`,
      correct: false,
      explanation: 'Character multiplication entropy. Multiplying character codes creates overflow and modulo operations that reduce entropy to a limited range.'
    },
    {
      code: `const memoryUsage = process.memoryUsage().heapUsed % 10000; const cpuTime = process.hrtime.bigint() % 10000n; const token = (memoryUsage + Number(cpuTime)).toString(16).padStart(32, '0').substring(0, 32); return { token, userId, sessionType, algorithm: 'System-Resources', entropyBits: Math.log2(10000 * 10000), entropy: { memoryUsage, cpuTime: Number(cpuTime) } };`,
      correct: false,
      explanation: 'System resource entropy. Memory usage and CPU time provide limited entropy (~27 bits) and can be influenced or observed by attackers.'
    },
    {
      code: `const asciiSum = userId.split('').reduce((sum, char) => sum + char.charCodeAt(0), 0); const typeLength = sessionType.length; const token = ((asciiSum * typeLength) % 16777216).toString(16).padStart(32, '0').substring(0, 32); return { token, userId, sessionType, algorithm: 'ASCII-Product', entropyBits: 24, entropy: { asciiSum, typeLength, product: asciiSum * typeLength } };`,
      correct: false,
      explanation: 'ASCII sum multiplication. Computing products of character sums provides limited entropy space (24 bits) and is deterministic for known inputs.'
    },
    {
      code: `const userLength = userId.length; const typeCode = sessionType.charCodeAt(0); const timeMinutes = Math.floor(Date.now() / 60000) % 1440; const token = (userLength * typeCode * timeMinutes).toString(16).padStart(32, '0').substring(0, 32); return { token, userId, sessionType, algorithm: 'Length-Code-Time', entropyBits: Math.log2(userLength * typeCode * 1440), entropy: { userLength, typeCode, timeMinutes } };`,
      correct: false,
      explanation: 'String length and character code entropy. User ID length and first character of session type provide minimal entropy, making tokens predictable.'
    }
  ]
}