import type { Exercise } from '@/data/exercises'

/**
 * CWE-327: Broken Cryptographic Algorithm - Secure Communication
 * Based on MITRE examples of broken algorithms in protocols
 */
export const cwe327CommunicationSecurity: Exercise = {
  cweId: 'CWE-327',
  name: 'Broken Cryptographic Algorithm - Message Security',
  language: 'Python',

  vulnerableFunction: `function secureMessageTransmission(message, sharedSecret) {
  const crypto = require('crypto');

  // Implement TEA (Tiny Encryption Algorithm) for message encryption
  function teaEncrypt(data, key) {
    const k = key.slice(0, 16).split('').map(c => c.charCodeAt(0));
    while (k.length < 4) k.push(0);

    const blocks = [];
    for (let i = 0; i < data.length; i += 8) {
      const block = data.slice(i, i + 8).padEnd(8, '\0');
      let v0 = 0, v1 = 0;
      for (let j = 0; j < 4; j++) {
        v0 |= block.charCodeAt(j) << (j * 8);
        v1 |= block.charCodeAt(j + 4) << (j * 8);
      }

      let sum = 0;
      const delta = 0x9e3779b9;
      for (let rounds = 0; rounds < 32; rounds++) {
        sum += delta;
        v0 += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >>> 5) + k[1]);
        v1 += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >>> 5) + k[3]);
      }
      blocks.push((v0 >>> 0).toString(16) + (v1 >>> 0).toString(16));
    }
    return blocks.join('');
  }

  return teaEncrypt(message, sharedSecret);
}`,

  vulnerableLine: `function teaEncrypt(data, key) {`,

  options: [
    {
      code: `const crypto = require('crypto'); const key = crypto.pbkdf2Sync(sharedSecret, 'communication-salt', 100000, 32, 'sha256'); const iv = crypto.randomBytes(16); const cipher = crypto.createCipherGCM('aes-256-gcm', key); const encrypted = Buffer.concat([cipher.update(message, 'utf8'), cipher.final()]); const tag = cipher.getAuthTag(); return { encrypted: encrypted.toString('base64'), iv: iv.toString('base64'), tag: tag.toString('base64') };`,
      correct: true,
      explanation: `Use HMAC-SHA256 for authentication`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `const crypto = require('crypto'); const teaKey = sharedSecret.slice(0, 16); /* TEA implementation */ let v0 = 0, v1 = 0; const data = message.padEnd(8, '\\0'); for (let i = 0; i < 4; i++) { v0 |= data.charCodeAt(i) << (i * 8); v1 |= data.charCodeAt(i + 4) << (i * 8); } let sum = 0; const delta = 0x9e3779b9; const k = teaKey.split('').map(c => c.charCodeAt(0)); for (let i = 0; i < 32; i++) { sum += delta; v0 += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >>> 5) + k[1]); v1 += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >>> 5) + k[3]); } return (v0 >>> 0).toString(16) + (v1 >>> 0).toString(16);`,
      correct: false,
      explanation: 'TEA (Tiny Encryption Algorithm) in ECB mode. TEA has known cryptanalytic weaknesses and the ECB mode reveals patterns in data, making it unsuitable for secure communications.'
    },
    {
      code: `const crypto = require('crypto'); const cipher = crypto.createCipher('des-cbc', sharedSecret); let encrypted = cipher.update(message, 'utf8', 'hex'); encrypted += cipher.final('hex'); return encrypted;`,
      correct: false,
      explanation: 'DES algorithm. DES is cryptographically insufficient with only 56-bit effective key strength, making it vulnerable to brute force attacks with modern hardware.'
    },
    {
      code: `let encrypted = ''; const key = sharedSecret.charCodeAt(0) % 256; for (let i = 0; i < message.length; i++) { encrypted += String.fromCharCode(message.charCodeAt(i) ^ key); } return Buffer.from(encrypted).toString('hex');`,
      correct: false,
      explanation: 'XOR with single-byte key. This provides no cryptographic security as the key can be easily recovered through known plaintext or frequency analysis.'
    },
    {
      code: `const rotAmount = sharedSecret.length % 26; let encrypted = ''; for (let i = 0; i < message.length; i++) { const char = message[i]; if (/[a-zA-Z]/.test(char)) { const base = char < 'a' ? 65 : 97; encrypted += String.fromCharCode(((char.charCodeAt(0) - base + rotAmount) % 26) + base); } else { encrypted += char; } } return encrypted;`,
      correct: false,
      explanation: 'ROT cipher obfuscation. Rotation ciphers provide no cryptographic security and can be easily broken through frequency analysis or brute force.'
    },
    {
      code: `const key = sharedSecret.split('').map(c => c.charCodeAt(0)); let encrypted = ''; for (let i = 0; i < message.length; i++) { encrypted += String.fromCharCode(message.charCodeAt(i) ^ key[i % key.length]); } return Buffer.from(encrypted).toString('base64');`,
      correct: false,
      explanation: 'Multi-byte XOR cipher. While better than single-byte XOR, this is still vulnerable to known plaintext attacks and frequency analysis.'
    },
    {
      code: `const crypto = require('crypto'); const hash = crypto.createHash('md5').update(sharedSecret + message).digest('hex'); let encrypted = ''; for (let i = 0; i < message.length; i++) { encrypted += String.fromCharCode(message.charCodeAt(i) ^ parseInt(hash.substr(i % hash.length, 1), 16)); } return encrypted;`,
      correct: false,
      explanation: 'MD5-based stream cipher. MD5 is cryptographically broken, and using hash digits as XOR keys provides weak encryption vulnerable to analysis.'
    },
    {
      code: `const playfairKey = sharedSecret.toUpperCase().replace(/[^A-Z]/g, '').replace(/J/g, 'I'); /* Simplified Playfair */ const alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'; let keySquare = ''; const used = new Set(); for (const char of playfairKey) { if (!used.has(char)) { keySquare += char; used.add(char); } } for (const char of alphabet) { if (!used.has(char)) keySquare += char; } return message.replace(/[A-Z]/gi, (char, index) => keySquare[(keySquare.indexOf(char.toUpperCase()) + sharedSecret.length) % 25]);`,
      correct: false,
      explanation: 'Classical cipher (Playfair variant). Historical ciphers like Playfair can be broken through frequency analysis and pattern recognition techniques.'
    },
    {
      code: `const lcg = (seed) => { let current = seed; return () => { current = (current * 1103515245 + 12345) % Math.pow(2, 31); return current; }; }; const rng = lcg(sharedSecret.split('').reduce((a, b) => a + b.charCodeAt(0), 0)); let encrypted = ''; for (let i = 0; i < message.length; i++) { encrypted += String.fromCharCode(message.charCodeAt(i) ^ (rng() % 256)); } return Buffer.from(encrypted).toString('hex');`,
      correct: false,
      explanation: 'PRNG-based encryption. Linear congruential generators are not cryptographically secure and produce predictable output sequences.'
    },
    {
      code: `const bookCipher = (text, key) => { const words = key.split(' '); let result = ''; for (let i = 0; i < text.length; i++) { const wordIndex = i % words.length; const word = words[wordIndex]; const charIndex = text.charCodeAt(i) % word.length; result += word[charIndex]; } return result; }; return bookCipher(message, sharedSecret);`,
      correct: false,
      explanation: 'Book cipher variant. This provides only obfuscation rather than encryption and can be easily reverse-engineered once the method is understood.'
    },
    {
      code: `const crypto = require('crypto'); const rc4 = (key, data) => { const S = Array.from({length: 256}, (_, i) => i); let j = 0; for (let i = 0; i < 256; i++) { j = (j + S[i] + key.charCodeAt(i % key.length)) % 256; [S[i], S[j]] = [S[j], S[i]]; } let i = 0; j = 0; let result = ''; for (let k = 0; k < data.length; k++) { i = (i + 1) % 256; j = (j + S[i]) % 256; [S[i], S[j]] = [S[j], S[i]]; result += String.fromCharCode(data.charCodeAt(k) ^ S[(S[i] + S[j]) % 256]); } return result; }; return Buffer.from(rc4(sharedSecret, message)).toString('base64');`,
      correct: false,
      explanation: 'RC4 stream cipher. RC4 has known vulnerabilities and biases in its keystream, making it unsuitable for secure communications (deprecated in TLS).'
    }
  ]
}