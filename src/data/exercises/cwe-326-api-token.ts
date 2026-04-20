import type { Exercise } from '@/data/exercises'

/**
 * CWE-326: Weak Encryption - API Token Encryption
 * Based on MITRE examples of insufficient encryption strength
 */
export const cwe326ApiToken: Exercise = {
  cweId: 'CWE-326',
  name: 'Weak Encryption - API Token Protection',
  language: 'Python',

  vulnerableFunction: `function encryptApiToken(token, clientId) {
  // Use client ID as encryption key
  const key = clientId.padEnd(16, '0'); // Pad to 16 chars
  let encrypted = '';
  for (let i = 0; i < token.length; i++) {
    encrypted += String.fromCharCode(
      token.charCodeAt(i) ^ key.charCodeAt(i % key.length)
    );
  }
  return Buffer.from(encrypted).toString('hex');
}`,

  vulnerableLine: `encrypted += String.fromCharCode(token.charCodeAt(i) ^ key.charCodeAt(i % key.length));`,

  options: [
    {
      code: `const crypto = require('crypto'); const key = crypto.randomBytes(32); const iv = crypto.randomBytes(16); const cipher = crypto.createCipherGCM('aes-256-gcm', key); cipher.setAAD(Buffer.from(clientId)); const encrypted = Buffer.concat([cipher.update(token, 'utf8'), cipher.final()]); return { encrypted: encrypted.toString('base64'), key: key.toString('base64'), iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64') };`,
      correct: true,
      explanation: `Use AES-256-GCM with random keys and IV`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `const crypto = require('crypto'); const cipher = crypto.createCipher('des-ecb', 'mykey'); return cipher.update(token, 'utf8', 'hex') + cipher.final('hex');`,
      correct: false,
      explanation: 'DES has weak 56-bit keys, ECB reveals patterns'
    },
    {
      code: `let result = ''; for (let i = 0; i < token.length; i++) { result += String.fromCharCode(token.charCodeAt(i) ^ 0xAA); } return result;`,
      correct: false,
      explanation: 'Single-byte XOR key easily discovered'
    },
    {
      code: `return token.split('').reverse().join('').split('').map(c => String.fromCharCode(c.charCodeAt(0) + 1)).join('');`,
      correct: false,
      explanation: 'String reversal and character shifting easily reversed'
    },
    {
      code: `const key = 'defaultsecretkey'; let encrypted = ''; for (let i = 0; i < token.length; i++) { encrypted += String.fromCharCode(token.charCodeAt(i) ^ key.charCodeAt(i % key.length)); } return encrypted;`,
      correct: false,
      explanation: 'Hard-coded XOR keys provide no security'
    },
    {
      code: `return Buffer.from(token.split('').map((c, i) => String.fromCharCode(c.charCodeAt(0) + (i * 2))).join('')).toString('base64');`,
      correct: false,
      explanation: 'Predictable character shifting easily reversed'
    },
    {
      code: `const substitution = 'zyxwvutsrqponmlkjihgfedcba'; return token.toLowerCase().split('').map(c => substitution[c.charCodeAt(0) - 97] || c).join('');`,
      correct: false,
      explanation: 'Substitution ciphers broken by frequency analysis'
    },
    {
      code: `const crypto = require('crypto'); return crypto.createHash('sha1').update(token + clientId).digest('hex');`,
      correct: false,
      explanation: 'SHA-1 hashing destroys token, not encryption'
    },
    {
      code: `const shift = clientId.length % 26; return token.split('').map(c => String.fromCharCode(((c.charCodeAt(0) - 65 + shift) % 26) + 65)).join('');`,
      correct: false,
      explanation: 'Caesar cipher has only 26 possible keys'
    },
    {
      code: `return token.split('').map((c, i) => (i % 2 === 0) ? c : String.fromCharCode(c.charCodeAt(0) ^ 0xFF)).join('');`,
      correct: false,
      explanation: 'Alternating XOR pattern easily reversed'
    }
  ]
}