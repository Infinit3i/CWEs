import type { Exercise } from '@/data/exercises'

/**
 * CWE-345: Insufficient Verification of Data Authenticity - Certificate Chain Validation
 * Weak certificate verification allowing man-in-the-middle attacks
 */
export const cwe345CertificateValidation: Exercise = {
  cweId: 'CWE-345',
  name: 'Insufficient Verification of Data Authenticity - SSL Certificate Validation',

  vulnerableFunction: `async function establishSecureConnection(hostname, port) {
  const options = {
    hostname: hostname,
    port: port,
    method: 'GET',
    headers: {
      'User-Agent': 'SecureClient/1.0'
    }
  };

  try {
    // Create HTTPS connection
    const response = await new Promise((resolve, reject) => {
      const req = https.request(options, (res) => {
        const cert = res.socket.getPeerCertificate();

        // Basic certificate validation
        if (cert.subject && cert.subject.CN === hostname) {
          console.log('Certificate subject matches hostname');
          resolve(res);
        } else {
          reject(new Error('Certificate hostname mismatch'));
        }
      });

      req.on('error', reject);
      req.end();
    });

    return {
      success: true,
      message: 'Secure connection established'
    };

  } catch (error) {
    return {
      success: false,
      error: error.message
    };
  }
}`,

  vulnerableLine: `if (cert.subject && cert.subject.CN === hostname) {`,

  options: [
    {
      code: `if (!cert.valid_from || !cert.valid_to || new Date() < new Date(cert.valid_from) || new Date() > new Date(cert.valid_to)) { throw new Error('Certificate expired or not yet valid'); } if (!verifyCertificateChain(cert, trustedCAs)) { throw new Error('Certificate chain validation failed'); }`,
      correct: true,
      explanation: `Verify certificate authenticity`
    },
    {
      code: `if (cert.subject && cert.subject.CN === hostname) { // Basic hostname check only`,
      correct: false,
      explanation: 'Insufficient verification from MITRE patterns. Only checking hostname allows attackers to use expired, self-signed, or revoked certificates that match the hostname but aren\'t trustworthy for secure connections.'
    },
    {
      code: `if (cert.subject.CN === hostname || cert.subject.CN === '*.' + hostname.split('.').slice(1).join('.')) {`,
      correct: false,
      explanation: 'Wildcard certificate support but no chain validation. Attackers can present self-signed certificates matching hostname patterns without proper certificate authority validation.'
    },
    {
      code: `if (cert.issuer && cert.issuer.CN && cert.subject.CN === hostname) {`,
      correct: false,
      explanation: 'Checks for issuer presence but doesn\'t validate the issuer\'s trustworthiness. Self-signed certificates or certificates from untrusted CAs can pass this superficial validation.'
    },
    {
      code: `const currentDate = new Date(); if (new Date(cert.valid_from) <= currentDate && currentDate <= new Date(cert.valid_to) && cert.subject.CN === hostname) {`,
      correct: false,
      explanation: 'Adds date validation but missing chain verification. Expired certificates are rejected, but self-signed or untrusted CA certificates within validity period are still accepted.'
    },
    {
      code: `if (cert.fingerprint && cert.subject.CN === hostname) {`,
      correct: false,
      explanation: 'Fingerprint presence check doesn\'t verify against trusted fingerprints. Any certificate with a fingerprint (all certificates have them) passes without validating it\'s from a trusted source.'
    },
    {
      code: `if (cert.serialNumber && cert.subject.CN === hostname && cert.issuer.CN !== cert.subject.CN) {`,
      correct: false,
      explanation: 'Prevents self-signed certificates but doesn\'t validate issuer trustworthiness. Certificates from untrusted or compromised CAs can still pass this validation.'
    },
    {
      code: `const allowedIssuers = ['DigiCert', 'Let\'s Encrypt', 'Comodo']; if (allowedIssuers.includes(cert.issuer.CN) && cert.subject.CN === hostname) {`,
      correct: false,
      explanation: 'Issuer allowlist is good but incomplete. Doesn\'t verify the certificate chain or that the issuer signature is valid - attackers can forge issuer names without proper cryptographic validation.'
    },
    {
      code: `if (cert.subject.CN === hostname && cert.version >= 3) {`,
      correct: false,
      explanation: 'Certificate version checking doesn\'t improve security validation. Version 3 certificates can still be self-signed, expired, or from untrusted sources without proper chain verification.'
    },
    {
      code: `if (cert.keysize >= 2048 && cert.subject.CN === hostname) {`,
      correct: false,
      explanation: 'Key size validation ensures strong cryptography but doesn\'t verify certificate authenticity. Strong self-signed or untrusted CA certificates still pose security risks.'
    }
  ]
}