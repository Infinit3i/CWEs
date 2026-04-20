import type { Exercise } from '@/data/exercises'

/**
 * CWE-326: Weak Encryption - API Token Encryption
 * Based on MITRE examples of insufficient encryption strength
 */
export const cwe326ApiToken: Exercise = {
  cweId: 'CWE-326',
  name: 'Weak Encryption - API Token Protection',

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
      explanation: `Correct! AES-256-GCM provides strong encryption with authenticated encryption. It uses a cryptographically secure random key, initialization vector, and includes authentication to detect tampering. The client ID is used as additional authenticated data.`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `const crypto = require('crypto'); const cipher = crypto.createCipher('des-ecb', 'mykey'); return cipher.update(token, 'utf8', 'hex') + cipher.final('hex');`,
      correct: false,
      explanation: 'MITRE pattern: DES in ECB mode. DES has an insufficient 56-bit key size and ECB mode reveals patterns in encrypted data.'
    },
    {
      code: `let result = ''; for (let i = 0; i < token.length; i++) { result += String.fromCharCode(token.charCodeAt(i) ^ 0xAA); } return result;`,
      correct: false,
      explanation: 'MITRE pattern: XOR with single byte key. This provides no cryptographic security as the key can be easily discovered through known plaintext attacks.'
    },
    {
      code: `return token.split('').reverse().join('').split('').map(c => String.fromCharCode(c.charCodeAt(0) + 1)).join('');`,
      correct: false,
      explanation: 'MITRE pattern: Reversible algorithm. String reversal combined with character shifting is easily reversed and provides no security.'
    },
    {
      code: `const key = 'defaultsecretkey'; let encrypted = ''; for (let i = 0; i < token.length; i++) { encrypted += String.fromCharCode(token.charCodeAt(i) ^ key.charCodeAt(i % key.length)); } return encrypted;`,
      correct: false,
      explanation: 'XOR with hard-coded key. Once the key is known, all encrypted tokens can be decrypted. Hard-coded keys provide no security.'
    },
    {
      code: `return Buffer.from(token.split('').map((c, i) => String.fromCharCode(c.charCodeAt(0) + (i * 2))).join('')).toString('base64');`,
      correct: false,
      explanation: 'Predictable character shifting pattern. The transformation is deterministic and easily reversible through analysis.'
    },
    {
      code: `const substitution = 'zyxwvutsrqponmlkjihgfedcba'; return token.toLowerCase().split('').map(c => substitution[c.charCodeAt(0) - 97] || c).join('');`,
      correct: false,
      explanation: 'MITRE pattern: One-to-one character mapping. Simple substitution ciphers are vulnerable to frequency analysis and pattern recognition.'
    },
    {
      code: `const crypto = require('crypto'); return crypto.createHash('sha1').update(token + clientId).digest('hex');`,
      correct: false,
      explanation: 'Hashing instead of encryption. SHA-1 is one-way and cryptographically weak - this destroys the token rather than protecting it.'
    },
    {
      code: `const shift = clientId.length % 26; return token.split('').map(c => String.fromCharCode(((c.charCodeAt(0) - 65 + shift) % 26) + 65)).join('');`,
      correct: false,
      explanation: 'Caesar cipher variant. This is a classical substitution cipher that can be broken through frequency analysis or brute force (only 26 possible keys).'
    },
    {
      code: `return token.split('').map((c, i) => (i % 2 === 0) ? c : String.fromCharCode(c.charCodeAt(0) ^ 0xFF)).join('');`,
      correct: false,
      explanation: 'Alternating XOR pattern. The predictable pattern makes this easy to reverse and provides minimal obfuscation rather than encryption.'
    }
  ]
}