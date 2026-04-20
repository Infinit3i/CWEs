import type { Exercise } from '@/data/exercises'

/**
 * CWE-331: Insufficient Entropy - Encryption Key Generation
 * Based on MITRE demonstrative examples showing low entropy in key generation
 */
export const cwe331EncryptionKey: Exercise = {
  cweId: 'CWE-331',
  name: 'Insufficient Entropy - Encryption Key Generation',

  vulnerableFunction: `function generateEncryptionKey(userPassword, salt) {
  // Use user password as primary entropy source
  let keyMaterial = userPassword || 'defaultpass';

  // Add minimal entropy from salt
  if (salt && salt.length > 0) {
    keyMaterial += salt.substring(0, 4); // Only use first 4 chars
  }

  // Simple key derivation with low iteration count
  const crypto = require('crypto');
  let key = keyMaterial;

  // Only 10 iterations - very low entropy expansion
  for (let i = 0; i < 10; i++) {
    key = crypto.createHash('md5').update(key + i).digest('hex');
  }

  return {
    key: key.substring(0, 32), // 256-bit key
    algorithm: 'MD5-Iterations',
    iterations: 10,
    entropy: 'Low-Password-Based',
    keyLength: 32
  };
}`,

  vulnerableLine: `for (let i = 0; i < 10; i++) {`,

  options: [
    {
      code: `const crypto = require('crypto'); const salt = crypto.randomBytes(32); const key = crypto.pbkdf2Sync(userPassword, salt, 100000, 32, 'sha256'); return { key: key.toString('hex'), algorithm: 'PBKDF2-SHA256', iterations: 100000, entropy: 'High-Random-Salt', keyLength: 32, salt: salt.toString('hex') };`,
      correct: true,
      explanation: `Use crypto.randomBytes for secure randomness`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `const crypto = require('crypto'); let keyMaterial = userPassword || 'defaultpass'; if (salt && salt.length > 0) { keyMaterial += salt.substring(0, 4); } let key = keyMaterial; for (let i = 0; i < 10; i++) { key = crypto.createHash('md5').update(key + i).digest('hex'); } return { key: key.substring(0, 32), algorithm: 'MD5-Iterations', iterations: 10, entropy: 'Low-Password-Based', keyLength: 32 };`,
      correct: false,
      explanation: 'Insufficient entropy from weak password + short salt. Using only 4 characters of salt and 10 iterations provides minimal entropy expansion, making keys vulnerable to brute force attacks.'
    },
    {
      code: `const crypto = require('crypto'); const timestamp = Date.now().toString(); const key = crypto.createHash('sha1').update(userPassword + timestamp).digest('hex'); return { key: key.substring(0, 32), algorithm: 'SHA1-Timestamp', iterations: 1, entropy: 'Password-Time', keyLength: 32 };`,
      correct: false,
      explanation: 'Insufficient entropy from predictable timestamp. Timestamps provide minimal additional entropy and can be guessed within narrow ranges, especially combined with weak passwords.'
    },
    {
      code: `let keyEntropy = 0; for (let i = 0; i < userPassword.length; i++) { keyEntropy += userPassword.charCodeAt(i); } keyEntropy = keyEntropy % 65536; const key = keyEntropy.toString(16).padStart(32, '0'); return { key: key, algorithm: 'Sum-Based', iterations: 1, entropy: 'Character-Sum', keyLength: 32 };`,
      correct: false,
      explanation: 'Extremely low entropy from character sum. Reducing password to a 16-bit sum drastically reduces entropy, making keys easily brute-forceable with only 65,536 possibilities.'
    },
    {
      code: `const shortSalt = (salt || 'XYZ').substring(0, 3); const crypto = require('crypto'); const key = crypto.createHash('md5').update(userPassword + shortSalt).digest('hex'); return { key: key.substring(0, 32), algorithm: 'MD5-ShortSalt', iterations: 1, entropy: 'Password-3Char', keyLength: 32 };`,
      correct: false,
      explanation: 'Insufficient salt length. A 3-character salt provides only about 15 bits of entropy (95^3 possibilities), insufficient for preventing rainbow table attacks on common passwords.'
    },
    {
      code: `const deterministicKey = userPassword.split('').map(c => c.charCodeAt(0).toString(16)).join('').substring(0, 32).padEnd(32, '0'); return { key: deterministicKey, algorithm: 'Direct-Mapping', iterations: 1, entropy: 'Zero-Additional', keyLength: 32 };`,
      correct: false,
      explanation: 'No entropy expansion. Direct character mapping provides no additional entropy beyond the original password, making keys as weak as the input password.'
    },
    {
      code: `const weekday = new Date().getDay(); const hour = new Date().getHours(); const timeEntropy = (weekday * 24 + hour).toString().padStart(3, '0'); const crypto = require('crypto'); const key = crypto.createHash('sha1').update(userPassword + timeEntropy).digest('hex'); return { key: key.substring(0, 32), algorithm: 'Time-Enhanced', iterations: 1, entropy: 'Password-TimeOfWeek', keyLength: 32 };`,
      correct: false,
      explanation: 'Low entropy time components. Day of week and hour provide only log2(7*24) ≈ 8 bits of entropy, insufficient for strengthening encryption keys.'
    },
    {
      code: `const processId = (process.pid || 1234) % 1000; const crypto = require('crypto'); let key = userPassword + processId.toString().padStart(3, '0'); for (let i = 0; i < 100; i++) { key = crypto.createHash('md5').update(key).digest('hex'); } return { key: key.substring(0, 32), algorithm: 'MD5-PID', iterations: 100, entropy: 'Password-PID', keyLength: 32 };`,
      correct: false,
      explanation: 'Process ID as low entropy source. Process IDs provide limited entropy (log2(1000) ≈ 10 bits) and can often be predicted or observed by attackers.'
    },
    {
      code: `const userLength = userPassword.length; const saltLength = (salt || '').length; const combinedLength = userLength + saltLength; const key = (userPassword + combinedLength.toString()).padEnd(32, '0').substring(0, 32); return { key: key, algorithm: 'Length-Based', iterations: 1, entropy: 'String-Lengths', keyLength: 32 };`,
      correct: false,
      explanation: 'String length as entropy source. Password and salt lengths provide minimal entropy (typically 1-4 bits) and reveal information about the original inputs.'
    },
    {
      code: `const memoryUsage = (process.memoryUsage().heapUsed || 12345678) % 10000; const crypto = require('crypto'); const key = crypto.createHash('sha1').update(userPassword + memoryUsage.toString()).digest('hex'); return { key: key.substring(0, 32), algorithm: 'Memory-Based', iterations: 1, entropy: 'Password-Memory', keyLength: 32 };`,
      correct: false,
      explanation: 'System state as low entropy. Memory usage provides limited entropy and can be influenced or observed by attackers, making it unsuitable as a primary entropy source.'
    }
  ]
}