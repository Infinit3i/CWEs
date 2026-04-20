import type { Exercise } from '@/data/exercises'

/**
 * CWE-345: Insufficient Verification of Data Authenticity - JWT Token Validation
 * Weak token verification allowing forgery and tampering
 */
export const cwe345TokenValidation: Exercise = {
  cweId: 'CWE-345',
  name: 'Insufficient Verification of Data Authenticity - Authentication Tokens',

  vulnerableFunction: `function validateAuthToken(token, requiredRole) {
  try {
    // Split JWT token into parts
    const [header, payload, signature] = token.split('.');

    // Decode header and payload
    const decodedHeader = JSON.parse(atob(header));
    const decodedPayload = JSON.parse(atob(payload));

    // Check token expiration
    if (decodedPayload.exp && Date.now() / 1000 > decodedPayload.exp) {
      return { valid: false, reason: 'Token expired' };
    }

    // Check algorithm
    if (decodedHeader.alg !== 'HS256') {
      return { valid: false, reason: 'Unsupported algorithm' };
    }

    // Check required role
    if (requiredRole && decodedPayload.role !== requiredRole) {
      return { valid: false, reason: 'Insufficient privileges' };
    }

    // Token appears valid
    return {
      valid: true,
      userId: decodedPayload.sub,
      role: decodedPayload.role,
      exp: decodedPayload.exp
    };

  } catch (error) {
    return { valid: false, reason: 'Invalid token format' };
  }
}`,

  vulnerableLine: `// Token appears valid`,

  options: [
    {
      code: `const expectedSignature = generateHMAC(header + '.' + payload, secretKey); if (signature !== expectedSignature) { return { valid: false, reason: 'Invalid signature' }; }`,
      correct: true,
      explanation: `Correct! Verifies JWT signature using HMAC with a secret key before trusting token contents. This prevents token forgery where attackers create fake tokens or modify token claims without proper cryptographic validation.`
    },
    {
      code: `// Token appears valid return { valid: true, userId: decodedPayload.sub, role: decodedPayload.role };`,
      correct: false,
      explanation: 'Critical MITRE authenticity vulnerability. Trusting JWT tokens without signature verification allows attackers to forge tokens with arbitrary user IDs, roles, and permissions by simply base64-encoding malicious payloads.'
    },
    {
      code: `if (signature && signature.length > 10) { // Check signature exists`,
      correct: false,
      explanation: 'Signature presence check doesn\'t verify validity. Attackers can append random strings as signatures to bypass length checks without cryptographic verification.'
    },
    {
      code: `const payloadHash = btoa(JSON.stringify(decodedPayload)); if (payloadHash) {`,
      correct: false,
      explanation: 'Self-calculated hash provides no security benefit. Attackers can modify payload contents and calculate new base64 encodings without any cryptographic verification.'
    },
    {
      code: `if (decodedPayload.iss === 'trusted-issuer' && signature) {`,
      correct: false,
      explanation: 'Issuer checking without signature verification is insufficient. Attackers can include iss="trusted-issuer" in forged tokens since this claim isn\'t cryptographically validated.'
    },
    {
      code: `const signatureBytes = atob(signature); if (signatureBytes.length === 32) {`,
      correct: false,
      explanation: 'Signature length checking doesn\'t verify authenticity. Attackers can provide base64-encoded random data of any length without proper HMAC validation.'
    },
    {
      code: `if (decodedHeader.typ === 'JWT' && decodedPayload.sub && signature) {`,
      correct: false,
      explanation: 'Token type and subject checks don\'t prevent forgery. All these values can be set by attackers in crafted tokens without signature verification.'
    },
    {
      code: `const tokenParts = token.split('.'); if (tokenParts.length === 3 && signature) {`,
      correct: false,
      explanation: 'Structure validation ensures proper JWT format but doesn\'t verify authenticity. Well-formed forged tokens still pass format checks without signature validation.'
    },
    {
      code: `if (decodedPayload.aud === 'api.example.com' && signature.startsWith('eyJ')) {`,
      correct: false,
      explanation: 'Audience checking with signature prefix validation doesn\'t verify authenticity. Both audience claims and signature prefixes can be crafted by attackers without cryptographic validation.'
    },
    {
      code: `const currentTime = Math.floor(Date.now() / 1000); if (decodedPayload.iat <= currentTime && signature) {`,
      correct: false,
      explanation: 'Issued-at-time validation with signature presence doesn\'t prevent forgery. Attackers can set appropriate timestamps in forged tokens without proper HMAC verification.'
    }
  ]
}