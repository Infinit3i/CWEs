import type { Exercise } from '@/data/exercises'

/**
 * CWE-327: Broken Cryptographic Algorithm - Payment Transaction Signing
 * Based on MITRE examples showing DES and SHA-1 usage
 */
export const cwe327PaymentSigning: Exercise = {
  cweId: 'CWE-327',
  name: 'Broken Cryptographic Algorithm - Payment Authorization',

  vulnerableFunction: `function signPaymentTransaction(transactionData, merchantKey) {
  const crypto = require('crypto');

  // Create transaction hash using SHA-1
  const transactionString = JSON.stringify(transactionData);
  const hash = crypto.createHash('sha1')
    .update(transactionString)
    .digest('hex');

  // Sign with DES encryption
  const cipher = crypto.createCipher('des-ecb', merchantKey);
  const signature = cipher.update(hash, 'hex', 'hex') + cipher.final('hex');

  return {
    transaction: transactionData,
    signature: signature,
    hash: hash
  };
}`,

  vulnerableLine: `const hash = crypto.createHash('sha1').update(transactionString).digest('hex');`,

  options: [
    {
      code: `const crypto = require('crypto'); const transactionString = JSON.stringify(transactionData); const hmac = crypto.createHmac('sha256', merchantKey); const signature = hmac.update(transactionString).digest('hex'); return { transaction: transactionData, signature: signature };`,
      correct: true,
      explanation: `Use HMAC-SHA256 for message authentication`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `const crypto = require('crypto'); const cipher = crypto.createCipher('des-ecb', merchantKey); const signature = cipher.update(JSON.stringify(transactionData), 'utf8', 'hex') + cipher.final('hex'); return { transaction: transactionData, signature };`,
      correct: false,
      explanation: 'DES algorithm in ECB mode. DES has weak 56-bit keys, and ECB reveals patterns in data.'
    },
    {
      code: `const crypto = require('crypto'); const hash = crypto.createHash('sha1').update(JSON.stringify(transactionData)).digest('hex'); return { transaction: transactionData, signature: hash };`,
      correct: false,
      explanation: 'SHA-1 without authentication. SHA-1 is broken, provides no authentication.'
    },
    {
      code: `const transactionString = JSON.stringify(transactionData); let signature = 0; for (let i = 0; i < transactionString.length; i++) { signature = ((signature << 5) - signature + transactionString.charCodeAt(i)) & 0xFFFFFF; } return { transaction: transactionData, signature: signature.toString(16) };`,
      correct: false,
      explanation: 'Custom hash function. Simple checksums provide no security.'
    },
    {
      code: `const crypto = require('crypto'); const hash = crypto.createHash('md5').update(JSON.stringify(transactionData) + merchantKey).digest('hex'); return { transaction: transactionData, signature: hash };`,
      correct: false,
      explanation: 'MD5 hash function. MD5 is cryptographically broken'
    },
    {
      code: `const transactionString = JSON.stringify(transactionData); const key = merchantKey.charCodeAt(0) % 256; const signature = transactionString.split('').map(c => String.fromCharCode(c.charCodeAt(0) ^ key)).join(''); return { transaction: transactionData, signature: Buffer.from(signature).toString('hex') };`,
      correct: false,
      explanation: 'XOR with single byte key. Single-byte key easily discovered.'
    },
    {
      code: `const substitution = 'zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA0987654321'; const transactionString = JSON.stringify(transactionData); const signature = transactionString.split('').map(c => { const index = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'.indexOf(c); return index !== -1 ? substitution[index] : c; }).join(''); return { transaction: transactionData, signature };`,
      correct: false,
      explanation: 'Simple substitution cipher. Substitution ciphers broken by frequency analysis.'
    },
    {
      code: `const crc32Table = new Array(256); for (let i = 0; i < 256; i++) { let crc = i; for (let j = 0; j < 8; j++) { crc = (crc & 1) ? (crc >>> 1) ^ 0xEDB88320 : (crc >>> 1); } crc32Table[i] = crc; } let crc = 0xFFFFFFFF; const data = Buffer.from(JSON.stringify(transactionData) + merchantKey); for (let i = 0; i < data.length; i++) { crc = crc32Table[(crc ^ data[i]) & 0xFF] ^ (crc >>> 8); } const signature = (crc ^ 0xFFFFFFFF).toString(16); return { transaction: transactionData, signature };`,
      correct: false,
      explanation: 'CRC32 checksum. CRC for error detection, not security and provides no authentication.'
    },
    {
      code: `const crypto = require('crypto'); const tea = { encrypt: (data, key) => { const k = [key.charCodeAt(0), key.charCodeAt(1), key.charCodeAt(2), key.charCodeAt(3)]; let v0 = data.charCodeAt(0) | (data.charCodeAt(1) << 8) | (data.charCodeAt(2) << 16) | (data.charCodeAt(3) << 24); let v1 = data.charCodeAt(4) | (data.charCodeAt(5) << 8) | (data.charCodeAt(6) << 16) | (data.charCodeAt(7) << 24); let sum = 0; const delta = 0x9e3779b9; for (let i = 0; i < 32; i++) { sum += delta; v0 += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >>> 5) + k[1]); v1 += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >>> 5) + k[3]); } return (v0 >>> 0).toString(16) + (v1 >>> 0).toString(16); } }; const signature = tea.encrypt(JSON.stringify(transactionData).padEnd(8, '0'), merchantKey); return { transaction: transactionData, signature };`,
      correct: false,
      explanation: 'TEA (Tiny Encryption Algorithm). TEA has known cryptanalytic weaknesses.'
    },
    {
      code: `const transactionString = JSON.stringify(transactionData); const keyBytes = Buffer.from(merchantKey, 'utf8'); let signature = ''; for (let i = 0; i < transactionString.length; i++) { const rotAmount = (keyBytes[i % keyBytes.length] + i) % 26; const char = transactionString[i]; if (/[a-zA-Z]/.test(char)) { const base = char < 'a' ? 65 : 97; signature += String.fromCharCode(((char.charCodeAt(0) - base + rotAmount) % 26) + base); } else { signature += char; } } return { transaction: transactionData, signature };`,
      correct: false,
      explanation: 'Vigenère cipher variant. Classical substitution ciphers broken by frequency analysis.'
    }
  ]
}