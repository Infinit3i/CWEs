import type { Exercise } from '@/data/exercises'

/**
 * CWE-328: Weak Hash - User Authentication System
 * Based on MITRE SHA-1 demonstrative examples without salt
 */
export const cwe328AuthenticationSystem: Exercise = {
  cweId: 'CWE-328',
  name: 'Weak Hash - User Login Authentication',

  vulnerableFunction: `function authenticateUser(username, plainTextPassword, storedPasswordHash) {
  const crypto = require('crypto');

  // Hash the provided password using SHA-1
  const hasher = crypto.createHash('sha1');
  hasher.update(plainTextPassword);
  const computedHash = hasher.digest('hex');

  // Compare with stored hash
  if (computedHash === storedPasswordHash) {
    console.log('User authenticated successfully');
    return {
      authenticated: true,
      username: username,
      algorithm: 'SHA-1'
    };
  } else {
    throw new Error('Authentication failed');
  }
}`,

  vulnerableLine: `const hasher = crypto.createHash('sha1');`,

  options: [
    {
      code: `const bcrypt = require('bcrypt'); const authenticated = bcrypt.compareSync(plainTextPassword, storedPasswordHash); if (authenticated) { return { authenticated: true, username: username, algorithm: 'bcrypt' }; } else { throw new Error('Authentication failed'); }`,
      correct: true,
      explanation: `Correct! bcrypt is specifically designed for password hashing with built-in salt and adaptive cost. It's resistant to rainbow table attacks and allows adjusting computational cost as hardware improves. bcrypt handles both hashing and comparison securely.`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `const crypto = require('crypto'); const hasher = crypto.createHash('sha1'); hasher.update(plainTextPassword); const computedHash = hasher.digest('hex'); return computedHash === storedPasswordHash ? { authenticated: true, username, algorithm: 'SHA-1' } : null;`,
      correct: false,
      explanation: 'MITRE pattern: SHA-1 without salt. SHA-1 is cryptographically weak (broken in 2017) and without salt, passwords are vulnerable to rainbow table attacks and collision attacks.'
    },
    {
      code: `const crypto = require('crypto'); const hasher = crypto.createHash('md5'); hasher.update(plainTextPassword); const computedHash = hasher.digest('hex'); return computedHash === storedPasswordHash ? { authenticated: true, username, algorithm: 'MD5' } : null;`,
      correct: false,
      explanation: 'MITRE pattern: MD5 hash function. MD5 is cryptographically broken with known collision vulnerabilities and is too fast for password hashing, enabling brute force attacks.'
    },
    {
      code: `let hash = 0; for (let i = 0; i < plainTextPassword.length; i++) { hash = ((hash << 5) - hash + plainTextPassword.charCodeAt(i)) & 0xFFFFFF; } const computedHash = hash.toString(16); return computedHash === storedPasswordHash ? { authenticated: true, username, algorithm: 'Custom' } : null;`,
      correct: false,
      explanation: 'MITRE pattern: Custom weak hash. Simple hash functions like this provide no cryptographic security and can be easily reverse-engineered or brute-forced.'
    },
    {
      code: `const crc32 = (str) => { let crc = 0xFFFFFFFF; const table = Array.from({length: 256}, (_, i) => { let c = i; for (let j = 0; j < 8; j++) c = (c & 1) ? (c >>> 1) ^ 0xEDB88320 : (c >>> 1); return c; }); for (let i = 0; i < str.length; i++) { crc = table[(crc ^ str.charCodeAt(i)) & 0xFF] ^ (crc >>> 8); } return ((crc ^ 0xFFFFFFFF) >>> 0).toString(16); }; const computedHash = crc32(plainTextPassword); return computedHash === storedPasswordHash ? { authenticated: true, username, algorithm: 'CRC32' } : null;`,
      correct: false,
      explanation: 'MITRE pattern: CRC32 checksum. CRC is designed for error detection, not cryptographic security. It provides no collision resistance and can be easily manipulated.'
    },
    {
      code: `const crypto = require('crypto'); const hasher = crypto.createHash('sha1'); hasher.update(plainTextPassword + username); const computedHash = hasher.digest('hex'); return computedHash === storedPasswordHash ? { authenticated: true, username, algorithm: 'SHA1+Username' } : null;`,
      correct: false,
      explanation: 'MITRE pattern: SHA-1 with predictable salt. While adding username as salt is better than no salt, SHA-1 is still broken and username is predictable, reducing security.'
    },
    {
      code: `let xorHash = 0; for (let i = 0; i < plainTextPassword.length; i++) { xorHash ^= plainTextPassword.charCodeAt(i); } const computedHash = xorHash.toString(16); return computedHash === storedPasswordHash ? { authenticated: true, username, algorithm: 'XOR' } : null;`,
      correct: false,
      explanation: 'MITRE pattern: XOR checksum. XOR operations provide no cryptographic security and can be easily manipulated. Many different passwords can produce the same XOR result.'
    },
    {
      code: `let sum = 0; for (let i = 0; i < plainTextPassword.length; i++) { sum = (sum + plainTextPassword.charCodeAt(i)) % 65536; } const computedHash = sum.toString(16); return computedHash === storedPasswordHash ? { authenticated: true, username, algorithm: 'Sum' } : null;`,
      correct: false,
      explanation: 'MITRE pattern: Simple checksum. Addition-based checksums provide no cryptographic security and many different passwords will produce the same sum.'
    },
    {
      code: `const adler32 = (data) => { let a = 1, b = 0; for (let i = 0; i < data.length; i++) { a = (a + data.charCodeAt(i)) % 65521; b = (b + a) % 65521; } return ((b << 16) | a).toString(16); }; const computedHash = adler32(plainTextPassword); return computedHash === storedPasswordHash ? { authenticated: true, username, algorithm: 'Adler32' } : null;`,
      correct: false,
      explanation: 'MITRE pattern: Adler-32 checksum. Like other checksums, Adler-32 is designed for error detection and provides no cryptographic security against intentional attacks.'
    },
    {
      code: `const rot13 = (str) => str.replace(/[a-zA-Z]/g, c => String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26)); const crypto = require('crypto'); const rotated = rot13(plainTextPassword); const hasher = crypto.createHash('sha1'); hasher.update(rotated); const computedHash = hasher.digest('hex'); return computedHash === storedPasswordHash ? { authenticated: true, username, algorithm: 'ROT13+SHA1' } : null;`,
      correct: false,
      explanation: 'MITRE pattern: ROT13 obfuscation with weak hash. ROT13 provides no security improvement, and SHA-1 remains cryptographically broken regardless of input transformation.'
    }
  ]
}