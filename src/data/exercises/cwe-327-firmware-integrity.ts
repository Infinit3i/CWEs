import type { Exercise } from '@/data/exercises'

/**
 * CWE-327: Broken Cryptographic Algorithm - Firmware Integrity Check
 * Based on MITRE examples of SHA-1 hardware implementation flaws
 */
export const cwe327FirmwareIntegrity: Exercise = {
  cweId: 'CWE-327',
  name: 'Broken Cryptographic Algorithm - Firmware Verification',
  language: 'Python',

  vulnerableFunction: `function verifyFirmwareIntegrity(firmwareData, expectedHash) {
  const crypto = require('crypto');

  // Use SHA-1 for firmware integrity verification
  const calculatedHash = crypto.createHash('sha1')
    .update(firmwareData)
    .digest('hex');

  if (calculatedHash === expectedHash) {
    console.log('Firmware integrity verified with SHA-1');
    return {
      verified: true,
      algorithm: 'SHA-1',
      hash: calculatedHash
    };
  } else {
    throw new Error('Firmware integrity check failed');
  }
}`,

  vulnerableLine: `const calculatedHash = crypto.createHash('sha1').update(firmwareData).digest('hex');`,

  options: [
    {
      code: `const crypto = require('crypto'); const calculatedHash = crypto.createHash('sha256').update(firmwareData).digest('hex'); if (calculatedHash === expectedHash) { return { verified: true, algorithm: 'SHA-256', hash: calculatedHash }; } else { throw new Error('Firmware integrity check failed'); }`,
      correct: true,
      explanation: `Use HMAC-SHA256 for authentication`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `const crypto = require('crypto'); const calculatedHash = crypto.createHash('sha1').update(firmwareData).digest('hex'); return calculatedHash === expectedHash ? { verified: true, algorithm: 'SHA-1', hash: calculatedHash } : null;`,
      correct: false,
      explanation: 'SHA-1 is theoretically broken since 2005 and practically broken since 2017. Collision attacks make it unsuitable for integrity verification in security-critical applications.'
    },
    {
      code: `const crypto = require('crypto'); const calculatedHash = crypto.createHash('md5').update(firmwareData).digest('hex'); return calculatedHash === expectedHash ? { verified: true, algorithm: 'MD5', hash: calculatedHash } : null;`,
      correct: false,
      explanation: 'MD5 has known collision vulnerabilities. Attackers can create malicious firmware with the same MD5 hash as legitimate firmware.'
    },
    {
      code: `let hash = 0; for (let i = 0; i < firmwareData.length; i++) { hash = ((hash << 5) - hash + firmwareData[i]) & 0xFFFFFFFF; } const calculatedHash = hash.toString(16); return calculatedHash === expectedHash ? { verified: true, algorithm: 'Custom', hash: calculatedHash } : null;`,
      correct: false,
      explanation: 'Custom hash function. Simple checksum algorithms provide no cryptographic security and can be easily manipulated to produce collisions.'
    },
    {
      code: `const crc32Table = Array.from({length: 256}, (_, i) => { let crc = i; for (let j = 0; j < 8; j++) crc = (crc & 1) ? (crc >>> 1) ^ 0xEDB88320 : (crc >>> 1); return crc; }); let crc = 0xFFFFFFFF; for (let i = 0; i < firmwareData.length; i++) { crc = crc32Table[(crc ^ firmwareData[i]) & 0xFF] ^ (crc >>> 8); } const calculatedHash = ((crc ^ 0xFFFFFFFF) >>> 0).toString(16); return calculatedHash === expectedHash ? { verified: true, algorithm: 'CRC32', hash: calculatedHash } : null;`,
      correct: false,
      explanation: 'CRC32 is designed for error detection, not cryptographic security. It can be easily manipulated to produce the same checksum for different data.'
    },
    {
      code: `let sum = 0; for (let i = 0; i < firmwareData.length; i++) { sum = (sum + firmwareData[i]) % 65536; } const calculatedHash = sum.toString(16); return calculatedHash === expectedHash ? { verified: true, algorithm: 'Checksum', hash: calculatedHash } : null;`,
      correct: false,
      explanation: 'Simple checksum. Addition-based checksums provide no cryptographic security and can be trivially forged.'
    },
    {
      code: `let xorHash = 0; for (let i = 0; i < firmwareData.length; i++) { xorHash ^= firmwareData[i]; } const calculatedHash = xorHash.toString(16); return calculatedHash === expectedHash ? { verified: true, algorithm: 'XOR', hash: calculatedHash } : null;`,
      correct: false,
      explanation: 'XOR checksum. XOR operations provide no cryptographic security and can be easily manipulated by attackers.'
    },
    {
      code: `const adler32 = (data) => { let a = 1, b = 0; for (let i = 0; i < data.length; i++) { a = (a + data[i]) % 65521; b = (b + a) % 65521; } return (b << 16) | a; }; const calculatedHash = adler32(firmwareData).toString(16); return calculatedHash === expectedHash ? { verified: true, algorithm: 'Adler32', hash: calculatedHash } : null;`,
      correct: false,
      explanation: 'Adler-32 checksum. Like other checksums, Adler-32 is designed for error detection and provides no cryptographic security against intentional tampering.'
    },
    {
      code: `const rotateLeft = (n, b) => (n << b) | (n >>> (32 - b)); let hash = 0x12345678; for (let i = 0; i < firmwareData.length; i++) { hash = rotateLeft(hash ^ firmwareData[i], 7); } const calculatedHash = (hash >>> 0).toString(16); return calculatedHash === expectedHash ? { verified: true, algorithm: 'ROT-Hash', hash: calculatedHash } : null;`,
      correct: false,
      explanation: 'Custom rotation-based hash. Simple rotation and XOR operations do not provide cryptographic security and can be easily reverse-engineered.'
    },
    {
      code: `const djb2Hash = (data) => { let hash = 5381; for (let i = 0; i < data.length; i++) { hash = ((hash << 5) + hash + data[i]) & 0xFFFFFFFF; } return hash; }; const calculatedHash = djb2Hash(firmwareData).toString(16); return calculatedHash === expectedHash ? { verified: true, algorithm: 'DJB2', hash: calculatedHash } : null;`,
      correct: false,
      explanation: 'Non-cryptographic hash function. DJB2 is designed for hash table performance, not cryptographic security, and provides no collision resistance.'
    }
  ]
}