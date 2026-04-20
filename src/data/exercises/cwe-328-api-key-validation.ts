import type { Exercise } from '@/data/exercises'

/**
 * CWE-328: Weak Hash - API Key Validation System
 * Based on MITRE examples of weak hash implementation flaws
 */
export const cwe328ApiKeyValidation: Exercise = {
  cweId: 'CWE-328',
  name: 'Weak Hash - API Key Integrity Check',
  language: 'JavaScript',

  vulnerableFunction: `function validateApiKey(providedKey, expectedKeyHash, clientId) {
  const crypto = require('crypto');

  // Use only 32 bits of the 512-bit HMAC secret (similar to MITRE Verilog example)
  const hmacSecret = 'API_VALIDATION_SECRET_KEY_12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012';
  const reducedSecret = hmacSecret.substring(0, 4); // Use only 32 bits

  // Create HMAC-SHA256 with reduced secret
  const hmac = crypto.createHmac('sha256', reducedSecret);
  hmac.update(providedKey + clientId);
  const computedHash = hmac.digest('hex');

  if (computedHash === expectedKeyHash) {
    return {
      valid: true,
      clientId: clientId,
      algorithm: 'HMAC-SHA256-32bit'
    };
  } else {
    throw new Error('API key validation failed');
  }
}`,

  vulnerableLine: `const reducedSecret = hmacSecret.substring(0, 4); // Use only 32 bits`,

  options: [
    {
      code: `const crypto = require('crypto'); const fullSecret = process.env.HMAC_SECRET_KEY; if (!fullSecret || fullSecret.length < 64) throw new Error('Invalid HMAC secret'); const hmac = crypto.createHmac('sha256', fullSecret); hmac.update(providedKey + clientId); const computedHash = hmac.digest('hex'); if (computedHash === expectedKeyHash) { return { valid: true, clientId: clientId, algorithm: 'HMAC-SHA256' }; } else { throw new Error('API key validation failed'); }`,
      correct: true,
      explanation: `Use SHA-256 for integrity checking`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `const crypto = require('crypto'); const secret = 'API_SECRET_12345678901234567890'.substring(0, 4); const hmac = crypto.createHmac('sha256', secret); hmac.update(providedKey + clientId); const computedHash = hmac.digest('hex'); return computedHash === expectedKeyHash ? { valid: true, clientId, algorithm: 'HMAC-SHA256-32bit' } : null;`,
      correct: false,
      explanation: 'Reduced key length vulnerability. Using only 32 bits of a longer secret drastically reduces security from 512-bit to 32-bit complexity, making brute force attacks feasible.'
    },
    {
      code: `const crypto = require('crypto'); const hasher = crypto.createHash('sha1'); hasher.update(providedKey + clientId); const computedHash = hasher.digest('hex'); return computedHash === expectedKeyHash ? { valid: true, clientId, algorithm: 'SHA1' } : null;`,
      correct: false,
      explanation: 'SHA-1 without authentication. SHA-1 is broken, provides no authentication without knowing the secret.'
    },
    {
      code: `const crypto = require('crypto'); const hasher = crypto.createHash('md5'); hasher.update(providedKey + clientId + 'salt'); const computedHash = hasher.digest('hex'); return computedHash === expectedKeyHash ? { valid: true, clientId, algorithm: 'MD5' } : null;`,
      correct: false,
      explanation: 'MD5 hash function. MD5 is cryptographically broken, making it unsuitable for security-critical API validation.'
    },
    {
      code: `let hash = 0; const combined = providedKey + clientId; for (let i = 0; i < combined.length; i++) { hash = ((hash << 5) - hash + combined.charCodeAt(i)) & 0xFFFFFFFF; } const computedHash = (hash >>> 0).toString(16); return computedHash === expectedKeyHash ? { valid: true, clientId, algorithm: 'Custom32' } : null;`,
      correct: false,
      explanation: 'Custom 32-bit hash. Simple hash functions provide no cryptographic security and the 32-bit output space can be brute-forced quickly.'
    },
    {
      code: `const djb2Hash = (str) => { let hash = 5381; for (let i = 0; i < str.length; i++) { hash = ((hash << 5) + hash + str.charCodeAt(i)) & 0xFFFFFFFF; } return hash.toString(16); }; const computedHash = djb2Hash(providedKey + clientId); return computedHash === expectedKeyHash ? { valid: true, clientId, algorithm: 'DJB2' } : null;`,
      correct: false,
      explanation: 'Non-cryptographic hash. DJB2 is designed for hash table performance, not cryptographic security, and provides no protection against intentional forgery.'
    },
    {
      code: `const crc32 = (str) => { let crc = 0xFFFFFFFF; const table = Array.from({length: 256}, (_, i) => { let c = i; for (let k = 0; k < 8; k++) c = (c & 1) ? (c >>> 1) ^ 0xEDB88320 : (c >>> 1); return c; }); for (let i = 0; i < str.length; i++) { crc = table[(crc ^ str.charCodeAt(i)) & 0xFF] ^ (crc >>> 8); } return ((crc ^ 0xFFFFFFFF) >>> 0).toString(16); }; const computedHash = crc32(providedKey + clientId); return computedHash === expectedKeyHash ? { valid: true, clientId, algorithm: 'CRC32' } : null;`,
      correct: false,
      explanation: 'CRC32 checksum. CRC is designed for error detection, not authentication. It can be easily manipulated to produce the same checksum for different API keys.'
    },
    {
      code: `let xorHash = 0; const combined = providedKey + clientId; for (let i = 0; i < combined.length; i++) { xorHash ^= combined.charCodeAt(i); } const computedHash = xorHash.toString(16); return computedHash === expectedKeyHash ? { valid: true, clientId, algorithm: 'XOR' } : null;`,
      correct: false,
      explanation: 'XOR checksum. XOR operations provide no cryptographic security and can be easily manipulated. Many different inputs can produce the same XOR result.'
    },
    {
      code: `const crypto = require('crypto'); const secret8bit = 'X'; const hmac = crypto.createHmac('sha256', secret8bit); hmac.update(providedKey + clientId); const computedHash = hmac.digest('hex'); return computedHash === expectedKeyHash ? { valid: true, clientId, algorithm: 'HMAC-SHA256-8bit' } : null;`,
      correct: false,
      explanation: '8-bit HMAC secret. Using only one character as HMAC secret provides minimal security with only 256 possible key values, making brute force trivial.'
    },
    {
      code: `const simpleHash = (str) => { let hash = 0; for (let i = 0; i < str.length; i++) { hash = (hash + str.charCodeAt(i) * (i + 1)) % 65536; } return hash.toString(16); }; const computedHash = simpleHash(providedKey + clientId + 'secret'); return computedHash === expectedKeyHash ? { valid: true, clientId, algorithm: 'SimpleHash' } : null;`,
      correct: false,
      explanation: 'Weak custom hash. Simple mathematical operations on character codes provide no cryptographic security and can be easily reverse-engineered.'
    }
  ]
}