import type { Exercise } from '@/data/exercises'

/**
 * CWE-327: Broken Cryptographic Algorithm - Digital Certificate Validation
 * Based on MITRE examples showing broken signature algorithms
 */
export const cwe327CertificateValidation: Exercise = {
  cweId: 'CWE-327',
  name: 'Broken Cryptographic Algorithm - Certificate Signing',
  language: 'Python',

  vulnerableFunction: `function generateCertificateSignature(certificateData, privateKey) {
  const crypto = require('crypto');

  // Create certificate hash using MD5
  const certHash = crypto.createHash('md5')
    .update(JSON.stringify(certificateData))
    .digest();

  // Sign hash with RSA using MD5 padding (PKCS#1 v1.5)
  try {
    const signature = crypto.sign('md5', certHash, {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_PADDING
    });

    return {
      certificate: certificateData,
      signature: signature.toString('base64'),
      algorithm: 'MD5-RSA',
      hashAlgorithm: 'MD5'
    };
  } catch (error) {
    throw new Error('Certificate signing failed: ' + error.message);
  }
}`,

  vulnerableLine: `const certHash = crypto.createHash('md5').update(JSON.stringify(certificateData)).digest();`,

  options: [
    {
      code: `const crypto = require('crypto'); const certHash = crypto.createHash('sha256').update(JSON.stringify(certificateData)).digest(); const signature = crypto.sign('sha256', certHash, { key: privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST }); return { certificate: certificateData, signature: signature.toString('base64'), algorithm: 'SHA256-RSA-PSS', hashAlgorithm: 'SHA256' };`,
      correct: true,
      explanation: `Use HMAC-SHA256 for authentication`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `const crypto = require('crypto'); const certHash = crypto.createHash('md5').update(JSON.stringify(certificateData)).digest(); const signature = crypto.sign('md5', certHash, { key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING }); return { certificate: certificateData, signature: signature.toString('base64'), algorithm: 'MD5-RSA', hashAlgorithm: 'MD5' };`,
      correct: false,
      explanation: 'MD5 hash algorithm. MD5 has known collision vulnerabilities that allow attackers to create different certificates with the same signature, breaking certificate integrity.'
    },
    {
      code: `const crypto = require('crypto'); const certHash = crypto.createHash('sha1').update(JSON.stringify(certificateData)).digest(); const signature = crypto.sign('sha1', certHash, { key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING }); return { certificate: certificateData, signature: signature.toString('base64'), algorithm: 'SHA1-RSA', hashAlgorithm: 'SHA1' };`,
      correct: false,
      explanation: 'SHA-1 hash algorithm. SHA-1 is cryptographically broken with practical collision attacks demonstrated in 2017, making it unsuitable for certificate signing.'
    },
    {
      code: `let checksum = 0; const certString = JSON.stringify(certificateData); for (let i = 0; i < certString.length; i++) { checksum = (checksum + certString.charCodeAt(i)) % 65536; } const hash = Buffer.alloc(20); hash.writeUInt16BE(checksum, 0); const signature = crypto.sign('sha1', hash, privateKey); return { certificate: certificateData, signature: signature.toString('base64'), algorithm: 'Checksum-RSA', hashAlgorithm: 'Custom' };`,
      correct: false,
      explanation: 'Custom weak hash. Simple checksum algorithms provide no collision resistance and can be easily manipulated to produce the same hash for different certificate data.'
    },
    {
      code: `const crc32 = (str) => { let crc = 0xFFFFFFFF; for (let i = 0; i < str.length; i++) { crc = (crc >>> 8) ^ crc32Table[(crc ^ str.charCodeAt(i)) & 0xFF]; } return (crc ^ 0xFFFFFFFF) >>> 0; }; const hash = Buffer.alloc(4); hash.writeUInt32BE(crc32(JSON.stringify(certificateData))); const crypto = require('crypto'); const signature = crypto.sign('sha1', hash, privateKey); return { certificate: certificateData, signature: signature.toString('base64'), algorithm: 'CRC32-RSA', hashAlgorithm: 'CRC32' };`,
      correct: false,
      explanation: 'CRC32 checksum. CRC is designed for error detection, not cryptographic hashing. It can be easily manipulated to produce collisions for certificate forgery.'
    },
    {
      code: `const crypto = require('crypto'); const hmac = crypto.createHmac('md5', 'certificate-key'); const hash = hmac.update(JSON.stringify(certificateData)).digest(); const signature = crypto.sign('md5', hash, privateKey); return { certificate: certificateData, signature: signature.toString('base64'), algorithm: 'HMAC-MD5-RSA', hashAlgorithm: 'HMAC-MD5' };`,
      correct: false,
      explanation: 'HMAC-MD5. While HMAC provides authentication, the underlying MD5 hash function is broken, and using a fixed key defeats the purpose of certificate signing.'
    },
    {
      code: `let rotHash = ''; const certData = JSON.stringify(certificateData); for (let i = 0; i < certData.length; i++) { const char = certData[i]; if (/[a-zA-Z]/.test(char)) { const base = char < 'a' ? 65 : 97; rotHash += String.fromCharCode(((char.charCodeAt(0) - base + 13) % 26) + base); } else { rotHash += char; } } const hash = crypto.createHash('sha1').update(rotHash).digest(); const signature = crypto.sign('sha1', hash, privateKey); return { certificate: certificateData, signature: signature.toString('base64'), algorithm: 'ROT13-SHA1-RSA', hashAlgorithm: 'ROT13' };`,
      correct: false,
      explanation: 'ROT13 obfuscation with broken hash. ROT13 provides no cryptographic value, and SHA-1 is broken, making this combination unsuitable for certificate security.'
    },
    {
      code: `const adler32 = (data) => { let a = 1, b = 0; for (let i = 0; i < data.length; i++) { a = (a + data.charCodeAt(i)) % 65521; b = (b + a) % 65521; } return (b << 16) | a; }; const hash = Buffer.alloc(4); hash.writeUInt32BE(adler32(JSON.stringify(certificateData))); const signature = crypto.sign('sha1', hash, privateKey); return { certificate: certificateData, signature: signature.toString('base64'), algorithm: 'Adler32-RSA', hashAlgorithm: 'Adler32' };`,
      correct: false,
      explanation: 'Adler-32 checksum. Like other checksums, Adler-32 provides no cryptographic security and can be easily manipulated for certificate forgery.'
    },
    {
      code: `const djb2 = (str) => { let hash = 5381; for (let i = 0; i < str.length; i++) { hash = ((hash << 5) + hash + str.charCodeAt(i)) & 0xFFFFFFFF; } return hash; }; const hash = Buffer.alloc(4); hash.writeUInt32BE(djb2(JSON.stringify(certificateData))); const signature = crypto.sign('sha1', hash, privateKey); return { certificate: certificateData, signature: signature.toString('base64'), algorithm: 'DJB2-RSA', hashAlgorithm: 'DJB2' };`,
      correct: false,
      explanation: 'Non-cryptographic hash. DJB2 is designed for hash table performance, not cryptographic security, and provides no collision resistance for certificate integrity.'
    },
    {
      code: `let xorHash = 0; const certBytes = Buffer.from(JSON.stringify(certificateData)); for (let i = 0; i < certBytes.length; i++) { xorHash ^= certBytes[i]; } const hash = Buffer.alloc(20); hash[0] = xorHash; const signature = crypto.sign('sha1', hash, privateKey); return { certificate: certificateData, signature: signature.toString('base64'), algorithm: 'XOR-RSA', hashAlgorithm: 'XOR' };`,
      correct: false,
      explanation: 'XOR checksum. XOR provides no cryptographic security and can be trivially manipulated to produce the same result for different certificate data.'
    }
  ]
}