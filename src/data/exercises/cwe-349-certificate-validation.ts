import type { Exercise } from '@/data/exercises'

/**
 * CWE-349 Exercise 2: Certificate Validation with Extra Data
 * Based on MITRE CVE-2006-5462 certificate signature forgery vulnerability
 */
export const cwe349CertificateValidation: Exercise = {
  cweId: 'CWE-349',
  name: 'Certificate Validation - Extra Data Acceptance',

  vulnerableFunction: `function validateCertificate(certificateData, trustedCASignature) {
  // Parse certificate and signature data
  const certInfo = parseCertificateData(certificateData);
  const signatureInfo = parseSignatureData(trustedCASignature);

  // Validate certificate using the CA signature
  if (signatureInfo.isValid && signatureInfo.caName === 'TrustedCA') {
    // Accept the certificate as trusted
    const validatedCert = {
      ...certInfo,
      ...signatureInfo.certData, // Include any additional cert data from signature
      trusted: true,
      validatedBy: signatureInfo.caName
    };

    return validatedCert;
  }

  return { trusted: false, error: 'Invalid signature' };
}`,

  vulnerableLine: `...signatureInfo.certData,`,

  options: [
    {
      code: `// Only use certificate data that was explicitly signed
const validatedFields = ['subject', 'issuer', 'validFrom', 'validTo', 'publicKey'];
const validatedCert = validatedFields.reduce((acc, field) => {
  if (certInfo[field] !== undefined) acc[field] = certInfo[field];
  return acc;
}, {});
validatedCert.trusted = true;
validatedCert.validatedBy = signatureInfo.caName;`,
      correct: true,
      explanation: `Correct! Only including explicitly validated certificate fields prevents injection of untrusted data. This blocks attackers from including extra malicious data in signatures that could override legitimate certificate properties.`
    },
    {
      code: `const validatedCert = {
  ...certInfo,
  ...signatureInfo.certData,
  trusted: true
};`,
      correct: false,
      explanation: 'Direct from MITRE: Accepting extraneous data from signature enables certificate forgery. Attackers can embed additional certificate properties in signatures to override legitimate certificate data (CVE-2006-5462).'
    },
    {
      code: `Object.assign(certInfo, signatureInfo.certData);
return { ...certInfo, trusted: true };`,
      correct: false,
      explanation: 'Direct assignment of signature data to certificate allows injection of untrusted properties that could modify security decisions.'
    },
    {
      code: `const validatedCert = Object.assign({},
  certInfo,
  signatureInfo.certData,
  { trusted: true }
);`,
      correct: false,
      explanation: 'Object.assign with signature data still allows untrusted certificate properties to override legitimate ones.'
    },
    {
      code: `if (signatureInfo.certData && Object.keys(signatureInfo.certData).length > 0) {
  return { ...certInfo, ...signatureInfo.certData, trusted: true };
}`,
      correct: false,
      explanation: 'Conditional merging based on presence of extra data does not prevent the security issue - untrusted data still gets included.'
    },
    {
      code: `const filtered = Object.keys(signatureInfo.certData).filter(key =>
  !['trusted', 'validatedBy'].includes(key)
);
const extraData = filtered.reduce((acc, key) => {
  acc[key] = signatureInfo.certData[key];
  return acc;
}, {});
return { ...certInfo, ...extraData, trusted: true };`,
      correct: false,
      explanation: 'Blacklisting specific security fields is insufficient. Other certificate properties could be maliciously overridden to affect validation logic.'
    },
    {
      code: `try {
  const validatedCert = {
    ...certInfo,
    ...JSON.parse(JSON.stringify(signatureInfo.certData)),
    trusted: true
  };
  return validatedCert;
} catch {}`,
      correct: false,
      explanation: 'Deep cloning and error handling do not address the fundamental issue of accepting untrusted extra data from signatures.'
    },
    {
      code: `const commonFields = Object.keys(certInfo).filter(key =>
  key in signatureInfo.certData
);
const validatedCert = commonFields.reduce((acc, key) => {
  acc[key] = certInfo[key];
  return acc;
}, {});`,
      correct: false,
      explanation: 'Intersecting fields approach is incomplete and may miss important certificate properties while still potentially including untrusted data.'
    },
    {
      code: `if (typeof signatureInfo.certData === 'object') {
  return {
    certificate: certInfo,
    signatureData: signatureInfo.certData,
    trusted: true
  };
}`,
      correct: false,
      explanation: 'Separating data structures does not prevent the issue if both are used for security decisions. The untrusted signature data could still influence validation.'
    },
    {
      code: `const safeData = Object.freeze(signatureInfo.certData);
return { ...certInfo, ...safeData, trusted: true };`,
      correct: false,
      explanation: 'Freezing objects does not prevent the security issue of accepting untrusted data - the malicious properties are already included.'
    }
  ]
}