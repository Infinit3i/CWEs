import type { Exercise } from '@/data/exercises'

/**
 * CWE-328: Weak Hash - Database Backup Verification
 * Based on MITRE examples of inadequate hash algorithms for integrity
 */
export const cwe328BackupVerification: Exercise = {
  cweId: 'CWE-328',
  name: 'Weak Hash - Database Backup Integrity',
  language: 'JavaScript',

  vulnerableFunction: `function verifyBackupIntegrity(backupData, expectedHash, backupTimestamp) {
  const crypto = require('crypto');

  // Use MD5 for backup integrity verification
  const md5Hasher = crypto.createHash('md5');

  // Hash backup data in chunks
  const chunkSize = 64 * 1024; // 64KB chunks
  for (let i = 0; i < backupData.length; i += chunkSize) {
    const chunk = backupData.slice(i, i + chunkSize);
    md5Hasher.update(chunk);
  }

  // Include timestamp in hash
  md5Hasher.update(backupTimestamp.toString());
  const computedHash = md5Hasher.digest('hex');

  if (computedHash === expectedHash) {
    return {
      verified: true,
      algorithm: 'MD5',
      size: backupData.length,
      timestamp: backupTimestamp,
      hash: computedHash
    };
  } else {
    throw new Error('Backup integrity verification failed');
  }
}`,

  vulnerableLine: `const md5Hasher = crypto.createHash('md5');`,

  options: [
    {
      code: `const crypto = require('crypto'); const sha256Hasher = crypto.createHash('sha256'); const chunkSize = 64 * 1024; for (let i = 0; i < backupData.length; i += chunkSize) { const chunk = backupData.slice(i, i + chunkSize); sha256Hasher.update(chunk); } sha256Hasher.update(backupTimestamp.toString()); const computedHash = sha256Hasher.digest('hex'); if (computedHash === expectedHash) { return { verified: true, algorithm: 'SHA256', size: backupData.length, timestamp: backupTimestamp, hash: computedHash }; } else { throw new Error('Backup integrity verification failed'); }`,
      correct: true,
      explanation: `Use SHA-256 for integrity checking`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `const crypto = require('crypto'); const md5Hasher = crypto.createHash('md5'); const chunkSize = 64 * 1024; for (let i = 0; i < backupData.length; i += chunkSize) { const chunk = backupData.slice(i, i + chunkSize); md5Hasher.update(chunk); } md5Hasher.update(backupTimestamp.toString()); const computedHash = md5Hasher.digest('hex'); return computedHash === expectedHash ? { verified: true, algorithm: 'MD5', size: backupData.length, timestamp: backupTimestamp, hash: computedHash } : null;`,
      correct: false,
      explanation: 'MD5 hash function. MD5 has known collision vulnerabilities - attackers can create corrupted backups with the same MD5 hash as legitimate backups, defeating integrity verification.'
    },
    {
      code: `const crypto = require('crypto'); const sha1Hasher = crypto.createHash('sha1'); const chunkSize = 64 * 1024; for (let i = 0; i < backupData.length; i += chunkSize) { const chunk = backupData.slice(i, i + chunkSize); sha1Hasher.update(chunk); } sha1Hasher.update(backupTimestamp.toString()); const computedHash = sha1Hasher.digest('hex'); return computedHash === expectedHash ? { verified: true, algorithm: 'SHA1', size: backupData.length, timestamp: backupTimestamp, hash: computedHash } : null;`,
      correct: false,
      explanation: 'SHA-1 weak hash. SHA-1 is cryptographically broken with practical collision attacks demonstrated, making it unsuitable for backup integrity verification.'
    },
    {
      code: `let crc = 0xFFFFFFFF; const chunkSize = 64 * 1024; for (let i = 0; i < backupData.length; i += chunkSize) { const chunk = backupData.slice(i, i + chunkSize); for (let j = 0; j < chunk.length; j++) { crc = (crc >>> 8) ^ crc32Table[(crc ^ chunk[j]) & 0xFF]; } } const timestampBytes = Buffer.from(backupTimestamp.toString()); for (let i = 0; i < timestampBytes.length; i++) { crc = (crc >>> 8) ^ crc32Table[(crc ^ timestampBytes[i]) & 0xFF]; } const computedHash = ((crc ^ 0xFFFFFFFF) >>> 0).toString(16); return computedHash === expectedHash ? { verified: true, algorithm: 'CRC32', size: backupData.length, timestamp: backupTimestamp, hash: computedHash } : null;`,
      correct: false,
      explanation: 'CRC32 checksum. CRC is designed for error detection, not cryptographic integrity. It can be easily manipulated to produce the same checksum for different backup data.'
    },
    {
      code: `let hash = 0; const chunkSize = 64 * 1024; for (let i = 0; i < backupData.length; i += chunkSize) { const chunk = backupData.slice(i, i + chunkSize); for (let j = 0; j < chunk.length; j++) { hash = ((hash << 5) - hash + chunk[j]) & 0xFFFFFFFF; } } const timestampStr = backupTimestamp.toString(); for (let i = 0; i < timestampStr.length; i++) { hash = ((hash << 5) - hash + timestampStr.charCodeAt(i)) & 0xFFFFFFFF; } const computedHash = (hash >>> 0).toString(16); return computedHash === expectedHash ? { verified: true, algorithm: 'Custom', size: backupData.length, timestamp: backupTimestamp, hash: computedHash } : null;`,
      correct: false,
      explanation: 'Custom weak hash. Simple bit shifting operations provide no cryptographic security and can be easily manipulated to produce hash collisions.'
    },
    {
      code: `let sum = 0; const chunkSize = 64 * 1024; for (let i = 0; i < backupData.length; i += chunkSize) { const chunk = backupData.slice(i, i + chunkSize); for (let j = 0; j < chunk.length; j++) { sum = (sum + chunk[j]) % 65536; } } sum = (sum + backupTimestamp) % 65536; const computedHash = sum.toString(16); return computedHash === expectedHash ? { verified: true, algorithm: 'Checksum', size: backupData.length, timestamp: backupTimestamp, hash: computedHash } : null;`,
      correct: false,
      explanation: 'Simple checksum. Addition-based checksums provide no cryptographic security and many different backup contents can produce the same checksum.'
    },
    {
      code: `let xorHash = 0; const chunkSize = 64 * 1024; for (let i = 0; i < backupData.length; i += chunkSize) { const chunk = backupData.slice(i, i + chunkSize); for (let j = 0; j < chunk.length; j++) { xorHash ^= chunk[j]; } } const timestampBytes = Buffer.from(backupTimestamp.toString()); for (let i = 0; i < timestampBytes.length; i++) { xorHash ^= timestampBytes[i]; } const computedHash = xorHash.toString(16); return computedHash === expectedHash ? { verified: true, algorithm: 'XOR', size: backupData.length, timestamp: backupTimestamp, hash: computedHash } : null;`,
      correct: false,
      explanation: 'XOR checksum. XOR operations provide no cryptographic security and can be easily manipulated. Many different backup contents can produce the same XOR result.'
    },
    {
      code: `const adler32 = (data) => { let a = 1, b = 0; for (let i = 0; i < data.length; i++) { a = (a + data[i]) % 65521; b = (b + a) % 65521; } return (b << 16) | a; }; let hash = adler32(backupData); const timestampBytes = Buffer.from(backupTimestamp.toString()); hash ^= adler32(timestampBytes); const computedHash = (hash >>> 0).toString(16); return computedHash === expectedHash ? { verified: true, algorithm: 'Adler32', size: backupData.length, timestamp: backupTimestamp, hash: computedHash } : null;`,
      correct: false,
      explanation: 'Adler-32 checksum. Like other checksums, Adler-32 is designed for error detection and provides no protection against intentional backup corruption.'
    },
    {
      code: `const djb2 = (data) => { let hash = 5381; for (let i = 0; i < data.length; i++) { hash = ((hash << 5) + hash + data[i]) & 0xFFFFFFFF; } return hash; }; const chunkSize = 64 * 1024; let hash = 5381; for (let i = 0; i < backupData.length; i += chunkSize) { const chunk = backupData.slice(i, i + chunkSize); const chunkHash = djb2(chunk); hash = ((hash << 5) + hash + chunkHash) & 0xFFFFFFFF; } hash = ((hash << 5) + hash + backupTimestamp) & 0xFFFFFFFF; const computedHash = (hash >>> 0).toString(16); return computedHash === expectedHash ? { verified: true, algorithm: 'DJB2', size: backupData.length, timestamp: backupTimestamp, hash: computedHash } : null;`,
      correct: false,
      explanation: 'Non-cryptographic hash. DJB2 is optimized for hash table performance, not cryptographic security, and provides no collision resistance for backup integrity.'
    },
    {
      code: `const fnv1a = (data) => { let hash = 0x811c9dc5; for (let i = 0; i < data.length; i++) { hash ^= data[i]; hash = (hash * 0x01000193) & 0xFFFFFFFF; } return hash; }; const chunkSize = 64 * 1024; let hash = 0x811c9dc5; for (let i = 0; i < backupData.length; i += chunkSize) { const chunk = backupData.slice(i, i + chunkSize); const chunkHash = fnv1a(chunk); hash ^= chunkHash; hash = (hash * 0x01000193) & 0xFFFFFFFF; } const timestampBytes = Buffer.from(backupTimestamp.toString()); for (let i = 0; i < timestampBytes.length; i++) { hash ^= timestampBytes[i]; hash = (hash * 0x01000193) & 0xFFFFFFFF; } const computedHash = (hash >>> 0).toString(16); return computedHash === expectedHash ? { verified: true, algorithm: 'FNV1a', size: backupData.length, timestamp: backupTimestamp, hash: computedHash } : null;`,
      correct: false,
      explanation: 'Non-cryptographic hash. FNV-1a is designed for hash table applications and provides no cryptographic security for backup verification.'
    }
  ]
}