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
      explanation: `Use bcrypt for password hashing with salt`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `let encrypted = ''; for (let i = 0; i < password.length; i++) { encrypted += String.fromCharCode(password.charCodeAt(i) ^ 0x42); } return btoa(encrypted);`,
      correct: false,
      explanation: 'XOR encryption is easily reversible'
    },
    {
      code: `return password.split('').reverse().join(''); // Reversible algorithm`,
      correct: false,
      explanation: 'String reversal provides no security'
    },
    {
      code: `let result = ''; for (let i = 0; i < password.length; i++) { result += String.fromCharCode(((password.charCodeAt(i) - 65 + 13) % 26) + 65); } return result;`,
      correct: false,
      explanation: 'ROT13 substitution cipher is easily broken'
    },
    {
      code: `const crypto = require('crypto'); return crypto.createHash('md5').update(password + 'fixedSalt').digest('hex');`,
      correct: false,
      explanation: 'MD5 is broken, fixed salts enable rainbow table attacks'
    },
    {
      code: `const key = 'simplekey123'; let result = ''; for (let i = 0; i < password.length; i++) { result += String.fromCharCode(password.charCodeAt(i) ^ key.charCodeAt(i % key.length)); } return result;`,
      correct: false,
      explanation: 'XOR with hard-coded key is easily reversible'
    },
    {
      code: `return password.split('').map((c, i) => String.fromCharCode(c.charCodeAt(0) + (i % 10))).join('');`,
      correct: false,
      explanation: 'Character shifting creates predictable patterns'
    },
    {
      code: `const des = require('crypto').createCipher('des', 'mykey'); return des.update(password, 'utf8', 'hex') + des.final('hex');`,
      correct: false,
      explanation: 'DES has 56-bit keys, easily brute-forced'
    },
    {
      code: `return Buffer.from(password).toString('base64'); // Base64 encoding`,
      correct: false,
      explanation: 'Base64 is encoding, not encryption'
    },
    {
      code: `const crypto = require('crypto'); return crypto.createHash('sha1').update(password).digest('hex');`,
      correct: false,
      explanation: 'SHA-1 is broken, needs salt against rainbow tables'
    }
  ]
}