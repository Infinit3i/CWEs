import type { Exercise } from '@/data/exercises'

/**
 * CWE-326: Weak Encryption - Private Message Encryption
 * Based on MITRE examples of fixed salt and weak key derivation
 */
export const cwe326MessageEncryption: Exercise = {
  cweId: 'CWE-326',
  name: 'Weak Encryption - Private Message System',
  language: 'Python',

  vulnerableFunction: `function encryptMessage(message, recipientId, senderId) {
  // Use fixed salt for key derivation
  const fixedSalt = 'SecureApp2023';
  const combinedId = recipientId + senderId;

  // Weak key derivation
  let key = 0;
  for (let i = 0; i < combinedId.length; i++) {
    key = ((key * 31) + combinedId.charCodeAt(i)) & 0xFFFFFF; // 24-bit key
  }

  const encrypted = message.split('').map((char, index) => {
    const keyByte = (key >> ((index % 3) * 8)) & 0xFF;
    return String.fromCharCode(char.charCodeAt(0) ^ keyByte);
  }).join('');

  return Buffer.from(encrypted).toString('base64');
}`,

  vulnerableLine: `const fixedSalt = 'SecureApp2023';`,

  options: [
    {
      code: `const crypto = require('crypto'); const salt = crypto.randomBytes(32); const masterKey = process.env.MESSAGE_MASTER_KEY; if (!masterKey) throw new Error('Master key required'); const derivedKey = crypto.pbkdf2Sync(masterKey + recipientId + senderId, salt, 100000, 32, 'sha256'); const iv = crypto.randomBytes(16); const cipher = crypto.createCipherGCM('aes-256-gcm', derivedKey); const encrypted = Buffer.concat([cipher.update(message, 'utf8'), cipher.final()]); return { encrypted: encrypted.toString('base64'), salt: salt.toString('base64'), iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64') };`,
      correct: true,
      explanation: `Use AES-256 with strong key derivation`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `const fixedSalt = 'MyAppSalt123'; const crypto = require('crypto'); const key = crypto.createHash('sha1').update(recipientId + senderId + fixedSalt).digest(); let encrypted = ''; for (let i = 0; i < message.length; i++) { encrypted += String.fromCharCode(message.charCodeAt(i) ^ key[i % key.length]); } return encrypted;`,
      correct: false,
      explanation: 'Fixed salt simplifying attacks. Using the same salt for all messages enables rainbow table attacks and makes brute force/dictionary attacks more efficient.'
    },
    {
      code: `let key = 0; for (let i = 0; i < (recipientId + senderId).length; i++) { key += (recipientId + senderId).charCodeAt(i); } key = key % 256; return message.split('').map(c => String.fromCharCode(c.charCodeAt(0) ^ key)).join('');`,
      correct: false,
      explanation: '8-bit key vulnerable to brute force. A single byte key provides only 256 possible values, making exhaustive key search trivial.'
    },
    {
      code: `const substitution = 'zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA'; return message.split('').map(c => { const index = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'.indexOf(c); return index !== -1 ? substitution[index] : c; }).join('');`,
      correct: false,
      explanation: 'One-to-one character mapping. Simple substitution ciphers are vulnerable to frequency analysis and can be broken through cryptanalysis.'
    },
    {
      code: `const keyStr = (recipientId + senderId).substring(0, 4) || 'XXXX'; return message.split('').map((c, i) => String.fromCharCode(c.charCodeAt(0) ^ keyStr.charCodeAt(i % keyStr.length))).join('');`,
      correct: false,
      explanation: 'Short key vulnerable to brute force. A 4-character key provides limited keyspace that can be exhaustively searched.'
    },
    {
      code: `return message.split('').reverse().join('').split('').map((c, i) => String.fromCharCode(((c.charCodeAt(0) - 32 + (i % 95)) % 95) + 32)).join('');`,
      correct: false,
      explanation: 'Reversible algorithm. String reversal combined with character shifting is deterministic and easily reversed.'
    },
    {
      code: `const seedVal = recipientId.charCodeAt(0) + senderId.charCodeAt(0); let prng = seedVal; return message.split('').map(c => { prng = (prng * 1103515245 + 12345) % Math.pow(2, 31); return String.fromCharCode(c.charCodeAt(0) ^ (prng % 256)); }).join('');`,
      correct: false,
      explanation: 'Predictable PRNG for encryption. Linear congruential generators produce deterministic sequences that can be predicted once the seed is known.'
    },
    {
      code: `const crypto = require('crypto'); const hash = crypto.createHash('md5').update(recipientId + senderId).digest('hex'); return message.split('').map((c, i) => String.fromCharCode(c.charCodeAt(0) ^ parseInt(hash[i % hash.length], 16))).join('');`,
      correct: false,
      explanation: 'MD5 without salt plus weak XOR scheme. MD5 is cryptographically broken, and XORing with individual hex digits provides weak encryption.'
    },
    {
      code: `const keyNum = parseInt(recipientId + senderId, 36) % 65536; return message.split('').map((c, i) => String.fromCharCode(c.charCodeAt(0) ^ ((keyNum >> (i % 2 * 8)) & 0xFF))).join('');`,
      correct: false,
      explanation: '16-bit key vulnerable to brute force. With only 65,536 possible keys, this keyspace can be exhaustively searched very quickly.'
    },
    {
      code: `const rotAmount = (recipientId.length + senderId.length) % 26; return message.replace(/[a-zA-Z]/g, c => String.fromCharCode(((c.charCodeAt(0) - (c < 'a' ? 65 : 97) + rotAmount) % 26) + (c < 'a' ? 65 : 97)));`,
      correct: false,
      explanation: 'ROT cipher (one-to-one mapping). Rotation ciphers can be easily broken through frequency analysis or by trying all possible rotation values.'
    }
  ]
}