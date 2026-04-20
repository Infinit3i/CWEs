import type { Exercise } from '@/data/exercises'

/**
 * CWE-327: Broken Cryptographic Algorithm - Password Database Encryption
 * Based on MITRE PHP DES example with weak encryption
 */
export const cwe327PasswordEncryption: Exercise = {
  cweId: 'CWE-327',
  name: 'Broken Cryptographic Algorithm - Password Database',
  language: 'Python',

  vulnerableFunction: `function encryptPasswordForStorage(password, userSalt) {
  const crypto = require('crypto');

  // Use DES encryption for password storage
  const iv = Buffer.alloc(8, 0); // Zero IV for DES
  const key = userSalt.substring(0, 8).padEnd(8, '0');

  const cipher = crypto.createCipheriv('des-ecb', key, null);
  let encrypted = cipher.update(password, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  return {
    algorithm: 'DES-ECB',
    encrypted: encrypted,
    salt: userSalt
  };
}`,

  vulnerableLine: `const cipher = crypto.createCipheriv('des-ecb', key, null);`,

  options: [
    {
      code: `const bcrypt = require('bcrypt'); const saltRounds = 12; const hashedPassword = bcrypt.hashSync(password, saltRounds); return { algorithm: 'bcrypt', hash: hashedPassword, rounds: saltRounds };`,
      correct: true,
      explanation: `Use HMAC-SHA256 for authentication`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `const crypto = require('crypto'); const key = userSalt.substring(0, 8); const cipher = crypto.createCipher('des', key); let encrypted = cipher.update(password, 'utf8', 'hex'); encrypted += cipher.final('hex'); return { algorithm: 'DES', encrypted, salt: userSalt };`,
      correct: false,
      explanation: 'DES encryption. DES is considered insufficient for modern applications with only 56-bit effective key strength, making it vulnerable to brute force attacks.'
    },
    {
      code: `const crypto = require('crypto'); const iv = crypto.randomBytes(8); const key = userSalt.substring(0, 8); const cipher = crypto.createCipheriv('des-cbc', key, iv); let encrypted = cipher.update(password, 'utf8', 'hex'); encrypted += cipher.final('hex'); return { algorithm: 'DES-CBC', encrypted, iv: iv.toString('hex'), salt: userSalt };`,
      correct: false,
      explanation: 'DES with CBC mode. While CBC is better than ECB, DES itself remains cryptographically weak regardless of the mode of operation.'
    },
    {
      code: `let xorResult = ''; const keyBytes = Buffer.from(userSalt.substring(0, 8), 'utf8'); for (let i = 0; i < password.length; i++) { xorResult += String.fromCharCode(password.charCodeAt(i) ^ keyBytes[i % keyBytes.length]); } return { algorithm: 'XOR', encrypted: Buffer.from(xorResult).toString('hex'), salt: userSalt };`,
      correct: false,
      explanation: 'XOR obfuscation. XOR with a short key provides no cryptographic security and can be easily broken through known plaintext attacks.'
    },
    {
      code: `const substitution = 'zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA0987654321'; const original = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'; let encrypted = ''; for (let i = 0; i < password.length; i++) { const index = original.indexOf(password[i]); encrypted += index !== -1 ? substitution[index] : password[i]; } return { algorithm: 'Substitution', encrypted, salt: userSalt };`,
      correct: false,
      explanation: 'Simple substitution cipher. Character-by-character substitution can be broken through frequency analysis and provides no real security.'
    },
    {
      code: `const rotAmount = userSalt.charCodeAt(0) % 26; let encrypted = ''; for (let i = 0; i < password.length; i++) { const char = password[i]; if (/[a-zA-Z]/.test(char)) { const base = char < 'a' ? 65 : 97; encrypted += String.fromCharCode(((char.charCodeAt(0) - base + rotAmount) % 26) + base); } else { encrypted += char; } } return { algorithm: 'ROT' + rotAmount, encrypted, salt: userSalt };`,
      correct: false,
      explanation: 'ROT cipher. Rotation ciphers are easily broken through frequency analysis or by trying all 26 possible rotation values.'
    },
    {
      code: `const crypto = require('crypto'); const hash = crypto.createHash('md5').update(password + userSalt).digest('hex'); return { algorithm: 'MD5+Salt', hash, salt: userSalt };`,
      correct: false,
      explanation: 'MD5 hash function. MD5 is cryptographically broken and is too fast for password hashing, enabling brute force attacks.'
    },
    {
      code: `const encrypted = password.split('').reverse().join('') + userSalt.charAt(0); return { algorithm: 'Reverse+Salt', encrypted, salt: userSalt };`,
      correct: false,
      explanation: 'Reversible transformation. String reversal with salt appending provides no cryptographic security and is trivially reversed.'
    },
    {
      code: `const vigenereEncrypt = (text, key) => { let result = ''; for (let i = 0; i < text.length; i++) { const textChar = text[i]; const keyChar = key[i % key.length]; if (/[a-zA-Z]/.test(textChar)) { const base = textChar < 'a' ? 65 : 97; result += String.fromCharCode(((textChar.charCodeAt(0) - base + keyChar.charCodeAt(0) - base) % 26) + base); } else { result += textChar; } } return result; }; const encrypted = vigenereEncrypt(password, userSalt); return { algorithm: 'Vigenere', encrypted, salt: userSalt };`,
      correct: false,
      explanation: 'Vigenère cipher. Classical polyalphabetic substitution ciphers can be broken through frequency analysis and Kasiski examination.'
    },
    {
      code: `const crypto = require('crypto'); const hash = crypto.createHash('sha1').update(password + userSalt).digest('hex'); return { algorithm: 'SHA1+Salt', hash, salt: userSalt };`,
      correct: false,
      explanation: 'SHA-1 hash function. SHA-1 is cryptographically broken (practical collision attacks since 2017) and is too fast for password hashing.'
    }
  ]
}