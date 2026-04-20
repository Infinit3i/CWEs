import type { Exercise } from '@/data/exercises'

/**
 * CWE-328: Weak Hash - File Integrity Verification
 * Based on MITRE examples showing inappropriate hash usage
 */
export const cwe328FileIntegrity: Exercise = {
  cweId: 'CWE-328',
  name: 'Weak Hash - Document Integrity Check',

  vulnerableFunction: `function generateFileIntegrityHash(fileData, fileName) {
  const crypto = require('crypto');

  // Use MD5 for file integrity verification
  const md5Hash = crypto.createHash('md5');
  md5Hash.update(fileData);
  md5Hash.update(fileName); // Include filename in hash

  const fileHash = md5Hash.digest('hex');

  return {
    fileName: fileName,
    size: fileData.length,
    hash: fileHash,
    algorithm: 'MD5',
    timestamp: Date.now()
  };
}`,

  vulnerableLine: `const md5Hash = crypto.createHash('md5');`,

  options: [
    {
      code: `const crypto = require('crypto'); const sha256Hash = crypto.createHash('sha256'); sha256Hash.update(fileData); sha256Hash.update(fileName); const fileHash = sha256Hash.digest('hex'); return { fileName: fileName, size: fileData.length, hash: fileHash, algorithm: 'SHA256', timestamp: Date.now() };`,
      correct: true,
      explanation: `Use SHA-256 for integrity checking`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `const crypto = require('crypto'); const md5Hash = crypto.createHash('md5'); md5Hash.update(fileData); md5Hash.update(fileName); const fileHash = md5Hash.digest('hex'); return { fileName, size: fileData.length, hash: fileHash, algorithm: 'MD5', timestamp: Date.now() };`,
      correct: false,
      explanation: 'MD5 hash function. MD5 has known collision vulnerabilities - attackers can create malicious files with the same MD5 hash as legitimate files, breaking integrity verification.'
    },
    {
      code: `const crypto = require('crypto'); const sha1Hash = crypto.createHash('sha1'); sha1Hash.update(fileData); sha1Hash.update(fileName); const fileHash = sha1Hash.digest('hex'); return { fileName, size: fileData.length, hash: fileHash, algorithm: 'SHA1', timestamp: Date.now() };`,
      correct: false,
      explanation: 'SHA-1 weak hash. SHA-1 is cryptographically broken with practical collision attacks demonstrated, making it unsuitable for file integrity verification.'
    },
    {
      code: `let hash = 0; for (let i = 0; i < fileData.length; i++) { hash = ((hash << 5) - hash + fileData[i]) & 0xFFFFFFFF; } const nameHash = fileName.split('').reduce((a, b) => ((a << 5) - a + b.charCodeAt(0)) & 0xFFFFFFFF, 0); const fileHash = (hash ^ nameHash).toString(16); return { fileName, size: fileData.length, hash: fileHash, algorithm: 'Custom', timestamp: Date.now() };`,
      correct: false,
      explanation: 'Custom weak hash. Simple bit shifting and XOR operations provide no cryptographic security and can be easily manipulated to produce collisions.'
    },
    {
      code: `const crc32 = (data) => { let crc = 0xFFFFFFFF; const table = Array.from({length: 256}, (_, i) => { let c = i; for (let j = 0; j < 8; j++) c = (c & 1) ? (c >>> 1) ^ 0xEDB88320 : (c >>> 1); return c; }); for (let i = 0; i < data.length; i++) { crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >>> 8); } return (crc ^ 0xFFFFFFFF) >>> 0; }; const dataHash = crc32(fileData); const nameHash = crc32(Buffer.from(fileName)); const fileHash = (dataHash ^ nameHash).toString(16); return { fileName, size: fileData.length, hash: fileHash, algorithm: 'CRC32', timestamp: Date.now() };`,
      correct: false,
      explanation: 'CRC32 checksum. CRC is designed for error detection, not cryptographic integrity. It can be easily manipulated to produce the same checksum for different file contents.'
    },
    {
      code: `let sum = 0; for (let i = 0; i < fileData.length; i++) { sum = (sum + fileData[i]) % 65536; } const nameSum = fileName.split('').reduce((a, b) => (a + b.charCodeAt(0)) % 65536, 0); const fileHash = (sum + nameSum).toString(16); return { fileName, size: fileData.length, hash: fileHash, algorithm: 'Checksum', timestamp: Date.now() };`,
      correct: false,
      explanation: 'Simple checksum. Addition-based checksums provide no cryptographic security and many different files can produce the same checksum value.'
    },
    {
      code: `let xorHash = 0; for (let i = 0; i < fileData.length; i++) { xorHash ^= fileData[i]; } for (let i = 0; i < fileName.length; i++) { xorHash ^= fileName.charCodeAt(i); } const fileHash = xorHash.toString(16); return { fileName, size: fileData.length, hash: fileHash, algorithm: 'XOR', timestamp: Date.now() };`,
      correct: false,
      explanation: 'XOR checksum. XOR operations provide no cryptographic security and can be trivially manipulated. Many different files can produce the same XOR result.'
    },
    {
      code: `const adler32 = (data) => { let a = 1, b = 0; for (let i = 0; i < data.length; i++) { a = (a + (typeof data[i] === 'number' ? data[i] : data.charCodeAt(i))) % 65521; b = (b + a) % 65521; } return (b << 16) | a; }; const dataHash = adler32(fileData); const nameHash = adler32(fileName); const fileHash = (dataHash ^ nameHash).toString(16); return { fileName, size: fileData.length, hash: fileHash, algorithm: 'Adler32', timestamp: Date.now() };`,
      correct: false,
      explanation: 'Adler-32 checksum. Like other checksums, Adler-32 is designed for error detection and provides no protection against intentional file modification.'
    },
    {
      code: `const djb2 = (data) => { let hash = 5381; if (typeof data === 'string') { for (let i = 0; i < data.length; i++) hash = ((hash << 5) + hash + data.charCodeAt(i)) & 0xFFFFFFFF; } else { for (let i = 0; i < data.length; i++) hash = ((hash << 5) + hash + data[i]) & 0xFFFFFFFF; } return hash; }; const dataHash = djb2(fileData); const nameHash = djb2(fileName); const fileHash = (dataHash ^ nameHash).toString(16); return { fileName, size: fileData.length, hash: fileHash, algorithm: 'DJB2', timestamp: Date.now() };`,
      correct: false,
      explanation: 'Non-cryptographic hash. DJB2 is optimized for hash table performance, not cryptographic security, and provides no collision resistance.'
    },
    {
      code: `const fnv1a = (data) => { let hash = 0x811c9dc5; if (typeof data === 'string') { for (let i = 0; i < data.length; i++) { hash ^= data.charCodeAt(i); hash = (hash * 0x01000193) & 0xFFFFFFFF; } } else { for (let i = 0; i < data.length; i++) { hash ^= data[i]; hash = (hash * 0x01000193) & 0xFFFFFFFF; } } return hash; }; const dataHash = fnv1a(fileData); const nameHash = fnv1a(fileName); const fileHash = (dataHash ^ nameHash).toString(16); return { fileName, size: fileData.length, hash: fileHash, algorithm: 'FNV1a', timestamp: Date.now() };`,
      correct: false,
      explanation: 'Non-cryptographic hash. FNV-1a is designed for hash table applications and provides no cryptographic security for integrity verification.'
    }
  ]
}