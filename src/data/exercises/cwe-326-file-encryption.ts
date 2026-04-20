import type { Exercise } from '@/data/exercises'

/**
 * CWE-326: Weak Encryption - File Encryption System
 * Based on MITRE examples showing brute force vulnerability
 */
export const cwe326FileEncryption: Exercise = {
  cweId: 'CWE-326',
  name: 'Weak Encryption - Confidential File Protection',
  language: 'Python',

  vulnerableFunction: `function encryptFile(fileData, userPassword) {
  // Use simple 8-bit key derived from password
  const key = userPassword.charCodeAt(0) % 256;
  const encrypted = new Uint8Array(fileData.length);

  for (let i = 0; i < fileData.length; i++) {
    encrypted[i] = fileData[i] ^ key;
  }

  return encrypted;
}`,

  vulnerableLine: `const key = userPassword.charCodeAt(0) % 256;`,

  options: [
    {
      code: `const crypto = require('crypto'); const salt = crypto.randomBytes(32); const key = crypto.pbkdf2Sync(userPassword, salt, 100000, 32, 'sha256'); const iv = crypto.randomBytes(16); const cipher = crypto.createCipherGCM('aes-256-gcm', key); cipher.setAAD(salt); const encrypted = Buffer.concat([cipher.update(fileData), cipher.final()]); return { encrypted, salt, iv, tag: cipher.getAuthTag() };`,
      correct: true,
      explanation: `Use AES-256-GCM with PBKDF2 key derivation`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `const key = userPassword.slice(0, 8); const encrypted = new Uint8Array(fileData.length); for (let i = 0; i < fileData.length; i++) { encrypted[i] = fileData[i] ^ key.charCodeAt(i % key.length); } return encrypted;`,
      correct: false,
      explanation: 'Short key length vulnerable to brute force. 8-character keys easily brute-forced.'
    },
    {
      code: `const key = userPassword.charCodeAt(0) % 256; return fileData.map(byte => byte ^ key);`,
      correct: false,
      explanation: 'Single-byte key encryption. 256 possible keys, easily brute-forced.'
    },
    {
      code: `const key = userPassword.split('').reduce((a, b) => a + b.charCodeAt(0), 0) % 65536; return fileData.map((byte, i) => byte ^ ((key + i) % 256));`,
      correct: false,
      explanation: 'Weak key derivation with predictable stream. 16-bit key space easily brute-forced.'
    },
    {
      code: `const crypto = require('crypto'); const key = crypto.createHash('md5').update(userPassword).digest(); const encrypted = new Uint8Array(fileData.length); for (let i = 0; i < fileData.length; i++) { encrypted[i] = fileData[i] ^ key[i % key.length]; } return encrypted;`,
      correct: false,
      explanation: 'MD5 key derivation without salt. MD5 is cryptographically broken and without salt, identical passwords produce identical keys, enabling rainbow table attacks.'
    },
    {
      code: `const key = userPassword.length % 256; return fileData.map((byte, i) => (byte + key + i) % 256);`,
      correct: false,
      explanation: 'Easily reversible transformation. Password length as key provides minimal security.'
    },
    {
      code: `const seedValue = userPassword.split('').reduce((a, b) => a * 31 + b.charCodeAt(0), 0); let currentSeed = seedValue; return fileData.map(byte => { currentSeed = (currentSeed * 1103515245 + 12345) % (2**31); return byte ^ (currentSeed % 256); });`,
      correct: false,
      explanation: 'Predictable PRNG for encryption. Linear congruential generators produce predictable output.'
    },
    {
      code: `return fileData.map((byte, i) => byte ^ (userPassword.charCodeAt(i % userPassword.length) + i % 256));`,
      correct: false,
      explanation: 'Predictable key stream with position dependency. Pattern becomes apparent with known plaintext.'
    },
    {
      code: `const crypto = require('crypto'); const cipher = crypto.createCipher('des', userPassword); return Buffer.concat([cipher.update(fileData), cipher.final()]);`,
      correct: false,
      explanation: 'DES algorithm. DES has a 56-bit effective key size that can be brute-forced with modern computing power in reasonable time.'
    },
    {
      code: `const shift = userPassword.charCodeAt(0) % 256; return fileData.map(byte => (byte + shift) % 256);`,
      correct: false,
      explanation: 'Simple substitution cipher. Caesar cipher variants with single-byte shifts can be broken through frequency analysis or brute force (256 possibilities).'
    }
  ]
}