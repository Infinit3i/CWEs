import type { Exercise } from '@/data/exercises'

/**
 * CWE-326: Weak Encryption - Password Storage
 * Based on MITRE demonstrative examples showing XOR and reversible algorithms
 */
export const cwe326PasswordStorage: Exercise = {
  cweId: 'CWE-326',
  name: 'Weak Encryption - Password Storage System',

  vulnerableFunction: `function encryptPassword(password, userId) {
  // Simple XOR encryption with user ID as key
  let encrypted = '';
  const keyStr = userId.toString();
  for (let i = 0; i < password.length; i++) {
    const keyChar = keyStr.charCodeAt(i % keyStr.length);
    encrypted += String.fromCharCode(password.charCodeAt(i) ^ keyChar);
  }
  return btoa(encrypted); // Base64 encode
}`,

  vulnerableLine: `encrypted += String.fromCharCode(password.charCodeAt(i) ^ keyChar);`,

  options: [
    {
      code: `const bcrypt = require('bcrypt'); return bcrypt.hashSync(password, 12);`,
      correct: true,
      explanation: `Correct! bcrypt is a strong, adaptive hashing function designed for passwords. The salt rounds (12) make it computationally expensive for attackers to perform brute force attacks. Unlike encryption, bcrypt is one-way - passwords cannot be decrypted, only verified through comparison.`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `let encrypted = ''; for (let i = 0; i < password.length; i++) { encrypted += String.fromCharCode(password.charCodeAt(i) ^ 0x42); } return btoa(encrypted);`,
      correct: false,
      explanation: 'MITRE pattern: XOR with fixed key (0x42). XOR encryption is cryptographically weak and easily reversible by applying the same operation.'
    },
    {
      code: `return password.split('').reverse().join(''); // Reversible algorithm`,
      correct: false,
      explanation: 'MITRE pattern: Reversible algorithm. Simple string reversal provides no cryptographic security and is trivially undone.'
    },
    {
      code: `let result = ''; for (let i = 0; i < password.length; i++) { result += String.fromCharCode(((password.charCodeAt(i) - 65 + 13) % 26) + 65); } return result;`,
      correct: false,
      explanation: 'MITRE pattern: One-to-one mapping (ROT13). Substitution ciphers like ROT13 are easily broken through frequency analysis and provide no real security.'
    },
    {
      code: `const crypto = require('crypto'); return crypto.createHash('md5').update(password + 'fixedSalt').digest('hex');`,
      correct: false,
      explanation: 'MITRE pattern: Fixed salt with weak hash. MD5 is cryptographically broken, and using a fixed salt makes rainbow table attacks feasible.'
    },
    {
      code: `const key = 'simplekey123'; let result = ''; for (let i = 0; i < password.length; i++) { result += String.fromCharCode(password.charCodeAt(i) ^ key.charCodeAt(i % key.length)); } return result;`,
      correct: false,
      explanation: 'XOR with hard-coded key. This is easily reversible once the key is discovered, and provides no forward secrecy.'
    },
    {
      code: `return password.split('').map((c, i) => String.fromCharCode(c.charCodeAt(0) + (i % 10))).join('');`,
      correct: false,
      explanation: 'Simple character shifting based on position. This creates a predictable pattern that can be easily analyzed and reversed.'
    },
    {
      code: `const des = require('crypto').createCipher('des', 'mykey'); return des.update(password, 'utf8', 'hex') + des.final('hex');`,
      correct: false,
      explanation: 'MITRE pattern: DES encryption. DES is considered cryptographically broken due to its small key size (56 bits) and can be brute-forced.'
    },
    {
      code: `return Buffer.from(password).toString('base64'); // Base64 encoding`,
      correct: false,
      explanation: 'Base64 is encoding, not encryption. It provides no security and can be trivially decoded by anyone.'
    },
    {
      code: `const crypto = require('crypto'); return crypto.createHash('sha1').update(password).digest('hex');`,
      correct: false,
      explanation: 'SHA-1 without salt. SHA-1 is cryptographically weak (broken in 2017) and without salt, passwords are vulnerable to rainbow table attacks.'
    }
  ]
}