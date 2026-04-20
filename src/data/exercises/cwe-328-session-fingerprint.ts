import type { Exercise } from '@/data/exercises'

/**
 * CWE-328: Weak Hash - Session Fingerprinting System
 * Based on MITRE patterns showing weak hash in authentication contexts
 */
export const cwe328SessionFingerprint: Exercise = {
  cweId: 'CWE-328',
  name: 'Weak Hash - Session Security Fingerprint',

  vulnerableFunction: `function createSessionFingerprint(userAgent, ipAddress, sessionId) {
  const crypto = require('crypto');

  // Create session fingerprint using SHA-1
  const fingerprintData = userAgent + '|' + ipAddress + '|' + sessionId;

  const hasher = crypto.createHash('sha1');
  hasher.update(fingerprintData);
  const fingerprint = hasher.digest('hex');

  return {
    sessionId: sessionId,
    fingerprint: fingerprint,
    algorithm: 'SHA-1',
    components: {
      userAgent: userAgent.substring(0, 50) + '...',
      ipAddress: ipAddress,
      timestamp: Date.now()
    }
  };
}`,

  vulnerableLine: `const hasher = crypto.createHash('sha1');`,

  options: [
    {
      code: `const crypto = require('crypto'); const secret = process.env.SESSION_SECRET || 'fallback-secret-key'; const fingerprintData = userAgent + '|' + ipAddress + '|' + sessionId; const hmac = crypto.createHmac('sha256', secret); hmac.update(fingerprintData); const fingerprint = hmac.digest('hex'); return { sessionId: sessionId, fingerprint: fingerprint, algorithm: 'HMAC-SHA256', components: { userAgent: userAgent.substring(0, 50) + '...', ipAddress: ipAddress, timestamp: Date.now() } };`,
      correct: true,
      explanation: `Use SHA-256 for integrity checking`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `const crypto = require('crypto'); const fingerprintData = userAgent + '|' + ipAddress + '|' + sessionId; const hasher = crypto.createHash('sha1'); hasher.update(fingerprintData); const fingerprint = hasher.digest('hex'); return { sessionId, fingerprint, algorithm: 'SHA-1', components: { userAgent: userAgent.substring(0, 50) + '...', ipAddress, timestamp: Date.now() } };`,
      correct: false,
      explanation: 'SHA-1 without authentication. SHA-1 is cryptographically broken and without a secret key, attackers can compute the same fingerprint if they know the user agent, IP, and session ID.'
    },
    {
      code: `const crypto = require('crypto'); const fingerprintData = userAgent + '|' + ipAddress + '|' + sessionId; const hasher = crypto.createHash('md5'); hasher.update(fingerprintData); const fingerprint = hasher.digest('hex'); return { sessionId, fingerprint, algorithm: 'MD5', components: { userAgent: userAgent.substring(0, 50) + '...', ipAddress, timestamp: Date.now() } };`,
      correct: false,
      explanation: 'MD5 hash function. MD5 is cryptographically broken and provides no authentication without a secret key.'
    },
    {
      code: `let hash = 5381; const fingerprintData = userAgent + '|' + ipAddress + '|' + sessionId; for (let i = 0; i < fingerprintData.length; i++) { hash = ((hash << 5) + hash + fingerprintData.charCodeAt(i)) & 0xFFFFFFFF; } const fingerprint = hash.toString(16); return { sessionId, fingerprint, algorithm: 'DJB2', components: { userAgent: userAgent.substring(0, 50) + '...', ipAddress, timestamp: Date.now() } };`,
      correct: false,
      explanation: 'Non-cryptographic hash. DJB2 is designed for hash table performance, not cryptographic security, and provides no protection against fingerprint forgery.'
    },
    {
      code: `const crc32 = (str) => { let crc = 0xFFFFFFFF; for (let i = 0; i < str.length; i++) { crc = (crc >>> 8) ^ crc32Table[(crc ^ str.charCodeAt(i)) & 0xFF]; } return (crc ^ 0xFFFFFFFF) >>> 0; }; const fingerprintData = userAgent + '|' + ipAddress + '|' + sessionId; const fingerprint = crc32(fingerprintData).toString(16); return { sessionId, fingerprint, algorithm: 'CRC32', components: { userAgent: userAgent.substring(0, 50) + '...', ipAddress, timestamp: Date.now() } };`,
      correct: false,
      explanation: 'CRC32 checksum. CRC is designed for error detection, not cryptographic security, and can be easily manipulated to produce the same fingerprint.'
    },
    {
      code: `let xorHash = 0; const fingerprintData = userAgent + '|' + ipAddress + '|' + sessionId; for (let i = 0; i < fingerprintData.length; i++) { xorHash ^= fingerprintData.charCodeAt(i); } const fingerprint = xorHash.toString(16); return { sessionId, fingerprint, algorithm: 'XOR', components: { userAgent: userAgent.substring(0, 50) + '...', ipAddress, timestamp: Date.now() } };`,
      correct: false,
      explanation: 'XOR checksum. XOR operations provide no cryptographic security and can be easily manipulated. Many different inputs can produce the same XOR result.'
    },
    {
      code: `let sum = 0; const fingerprintData = userAgent + '|' + ipAddress + '|' + sessionId; for (let i = 0; i < fingerprintData.length; i++) { sum = (sum + fingerprintData.charCodeAt(i)) % 65536; } const fingerprint = sum.toString(16); return { sessionId, fingerprint, algorithm: 'Sum', components: { userAgent: userAgent.substring(0, 50) + '...', ipAddress, timestamp: Date.now() } };`,
      correct: false,
      explanation: 'Simple checksum. Addition-based checksums provide no cryptographic security and many different fingerprint combinations can produce the same sum.'
    },
    {
      code: `const adler32 = (data) => { let a = 1, b = 0; for (let i = 0; i < data.length; i++) { a = (a + data.charCodeAt(i)) % 65521; b = (b + a) % 65521; } return ((b << 16) | a).toString(16); }; const fingerprintData = userAgent + '|' + ipAddress + '|' + sessionId; const fingerprint = adler32(fingerprintData); return { sessionId, fingerprint, algorithm: 'Adler32', components: { userAgent: userAgent.substring(0, 50) + '...', ipAddress, timestamp: Date.now() } };`,
      correct: false,
      explanation: 'Adler-32 checksum. Like other checksums, Adler-32 is designed for error detection and provides no protection against intentional fingerprint manipulation.'
    },
    {
      code: `let rot13Hash = ''; const fingerprintData = userAgent + '|' + ipAddress + '|' + sessionId; for (let i = 0; i < fingerprintData.length; i++) { const char = fingerprintData[i]; if (/[a-zA-Z]/.test(char)) { rot13Hash += String.fromCharCode(((char.charCodeAt(0) - (char < 'a' ? 65 : 97) + 13) % 26) + (char < 'a' ? 65 : 97)); } else { rot13Hash += char; } } const crypto = require('crypto'); const hasher = crypto.createHash('sha1'); hasher.update(rot13Hash); const fingerprint = hasher.digest('hex'); return { sessionId, fingerprint, algorithm: 'ROT13-SHA1', components: { userAgent: userAgent.substring(0, 50) + '...', ipAddress, timestamp: Date.now() } };`,
      correct: false,
      explanation: 'ROT13 obfuscation with weak hash. ROT13 provides no cryptographic value, and SHA-1 remains broken regardless of input transformation.'
    },
    {
      code: `const fnv1a = (str) => { let hash = 0x811c9dc5; for (let i = 0; i < str.length; i++) { hash ^= str.charCodeAt(i); hash = (hash * 0x01000193) & 0xFFFFFFFF; } return hash.toString(16); }; const fingerprintData = userAgent + '|' + ipAddress + '|' + sessionId; const fingerprint = fnv1a(fingerprintData); return { sessionId, fingerprint, algorithm: 'FNV1a', components: { userAgent: userAgent.substring(0, 50) + '...', ipAddress, timestamp: Date.now() } };`,
      correct: false,
      explanation: 'Non-cryptographic hash. FNV-1a is optimized for hash table applications and provides no cryptographic security for session fingerprinting.'
    }
  ]
}