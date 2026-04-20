import type { Exercise } from '@/data/exercises'

/**
 * CWE-326: Weak Encryption - Session Data Encryption
 * Based on MITRE patterns of theoretically sound but insufficient algorithms
 */
export const cwe326SessionEncryption: Exercise = {
  cweId: 'CWE-326',
  name: 'Weak Encryption - Session Data Protection',
  language: 'Python',

  vulnerableFunction: `function encryptSessionData(sessionData, sessionId) {
  // Use session ID first 4 chars as 32-bit key
  const keyStr = sessionId.substring(0, 4).padEnd(4, 'X');
  const key = keyStr.split('').reduce((acc, char, i) =>
    acc | (char.charCodeAt(0) << (i * 8)), 0
  );

  const data = JSON.stringify(sessionData);
  let encrypted = '';

  for (let i = 0; i < data.length; i++) {
    encrypted += String.fromCharCode(data.charCodeAt(i) ^ ((key >> (i % 4 * 8)) & 0xFF));
  }

  return Buffer.from(encrypted).toString('base64');
}`,

  vulnerableLine: `acc | (char.charCodeAt(0) << (i * 8)), 0`,

  options: [
    {
      code: `const crypto = require('crypto'); const secretKey = process.env.SESSION_ENCRYPTION_KEY; if (!secretKey) throw new Error('Missing encryption key'); const key = crypto.createHash('sha256').update(secretKey + sessionId).digest(); const iv = crypto.randomBytes(16); const cipher = crypto.createCipherGCM('aes-256-gcm', key); const encrypted = Buffer.concat([cipher.update(JSON.stringify(sessionData), 'utf8'), cipher.final()]); return { data: encrypted.toString('base64'), iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64') };`,
      correct: true,
      explanation: `Use AES-256 with strong key derivation`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `const key32 = sessionId.substring(0, 4); const data = JSON.stringify(sessionData); let result = ''; for (let i = 0; i < data.length; i++) { result += String.fromCharCode(data.charCodeAt(i) ^ key32.charCodeAt(i % 4)); } return result;`,
      correct: false,
      explanation: '32-bit key vulnerable to brute force. With only 2^32 possible keys, this can be brute-forced in reasonable time with modern computing resources.'
    },
    {
      code: `const rotValue = sessionId.length % 26; const data = JSON.stringify(sessionData); return data.replace(/[a-zA-Z]/g, char => String.fromCharCode(((char.charCodeAt(0) - (char < 'a' ? 65 : 97) + rotValue) % 26) + (char < 'a' ? 65 : 97)));`,
      correct: false,
      explanation: 'ROT cipher (one-to-one mapping). Rotation ciphers can be easily broken through frequency analysis or by trying all 26 possible rotations.'
    },
    {
      code: `const key = sessionId.split('').reduce((a, b) => a + b.charCodeAt(0), 0) & 0xFF; const data = JSON.stringify(sessionData); return data.split('').map(c => String.fromCharCode(c.charCodeAt(0) ^ key)).join('');`,
      correct: false,
      explanation: '8-bit key encryption. A single byte key provides only 256 possible values, making brute force trivial.'
    },
    {
      code: `const data = JSON.stringify(sessionData); return data.split('').reverse().join('').split('').map((c, i) => String.fromCharCode(c.charCodeAt(0) + (i % 10))).join('');`,
      correct: false,
      explanation: 'Reversible algorithm. String reversal combined with predictable character shifting provides no cryptographic security.'
    },
    {
      code: `const crypto = require('crypto'); const hash = crypto.createHash('md5').update(sessionId).digest('hex'); const data = JSON.stringify(sessionData); let result = ''; for (let i = 0; i < data.length; i++) { result += String.fromCharCode(data.charCodeAt(i) ^ parseInt(hash.substr(i % hash.length, 1), 16)); } return result;`,
      correct: false,
      explanation: 'MD5-based key derivation with nibble-level XOR. MD5 is cryptographically broken, and using individual hex digits as XOR keys provides weak encryption.'
    },
    {
      code: `const substitution = {'a':'z','b':'y','c':'x','d':'w','e':'v','f':'u','g':'t','h':'s','i':'r','j':'q','k':'p','l':'o','m':'n','n':'m','o':'l','p':'k','q':'j','r':'i','s':'h','t':'g','u':'f','v':'e','w':'d','x':'c','y':'b','z':'a'}; const data = JSON.stringify(sessionData).toLowerCase(); return data.split('').map(c => substitution[c] || c).join('');`,
      correct: false,
      explanation: 'Simple substitution cipher. Character-by-character substitution is vulnerable to frequency analysis and pattern recognition.'
    },
    {
      code: `const key = sessionId.charCodeAt(0) % 256; const data = JSON.stringify(sessionData); return Buffer.from(data).map((byte, i) => byte ^ ((key + i) % 256)).toString('base64');`,
      correct: false,
      explanation: 'Weak stream cipher. Starting with a single byte and incrementing creates a predictable keystream that can be analyzed.'
    },
    {
      code: `const crypto = require('crypto'); const cipher = crypto.createCipher('des-cbc', sessionId.substring(0, 8)); return cipher.update(JSON.stringify(sessionData), 'utf8', 'hex') + cipher.final('hex');`,
      correct: false,
      explanation: 'DES encryption. DES has insufficient key strength (56 bits) and can be brute-forced with dedicated hardware or cloud computing.'
    },
    {
      code: `const data = JSON.stringify(sessionData); const key = sessionId.split('').map(c => c.charCodeAt(0)).reduce((a, b) => a + b) % 65536; return data.split('').map((c, i) => String.fromCharCode(c.charCodeAt(0) ^ ((key >> (i % 2 * 8)) & 0xFF))).join('');`,
      correct: false,
      explanation: '16-bit key vulnerable to brute force. With only 65,536 possible keys, this can be exhaustively searched very quickly.'
    }
  ]
}