import type { Exercise } from '@/data/exercises'

/**
 * CWE-345: Insufficient Verification of Data Authenticity - Data Package Integrity
 * Insufficient verification of downloaded data packages and updates
 */
export const cwe345DataIntegrity: Exercise = {
  cweId: 'CWE-345',
  name: 'Insufficient Verification of Data Authenticity - Package Downloads',

  vulnerableFunction: `async function downloadAndInstallPackage(packageInfo) {
  const { downloadUrl, packageName, expectedSize, checksum } = packageInfo;

  try {
    console.log(\`Downloading package: \${packageName}\`);

    // Download package data
    const response = await fetch(downloadUrl);
    const packageData = await response.arrayBuffer();

    // Verify package size
    if (packageData.byteLength !== expectedSize) {
      throw new Error(\`Size mismatch: expected \${expectedSize}, got \${packageData.byteLength}\`);
    }

    // Verify package checksum
    const calculatedChecksum = await calculateSHA1(packageData);
    if (calculatedChecksum !== checksum) {
      throw new Error('Package checksum verification failed');
    }

    // Install package
    await extractAndInstall(packageData, packageName);

    return {
      success: true,
      message: \`Package \${packageName} installed successfully\`
    };

  } catch (error) {
    return {
      success: false,
      error: error.message
    };
  }
}`,

  vulnerableLine: `const calculatedChecksum = await calculateSHA1(packageData);`,

  options: [
    {
      code: `if (!verifyPackageSignature(packageData, packageInfo.signature, trustedPublicKeys)) { throw new Error('Package signature verification failed'); }`,
      correct: true,
      explanation: `Correct! Uses cryptographic signature verification with trusted public keys instead of checksums. This ensures package authenticity and prevents attackers from distributing malicious packages with matching checksums.`
    },
    {
      code: `const calculatedChecksum = await calculateSHA1(packageData); // SHA1 checksum only`,
      correct: false,
      explanation: 'SHA1 checksum provides integrity checking but not authenticity verification. Attackers can distribute malicious packages with their own SHA1 checksums, bypassing this validation method.'
    },
    {
      code: `const calculatedChecksum = await calculateMD5(packageData);`,
      correct: false,
      explanation: 'MD5 is cryptographically weak and only detects accidental corruption. Attackers can easily create malicious packages with matching MD5 checksums using collision attacks.'
    },
    {
      code: `const calculatedChecksum = await calculateSHA256(packageData);`,
      correct: false,
      explanation: 'SHA256 prevents collision attacks but doesn\'t verify package origin. Attackers can provide malicious packages with their own SHA256 checksums that pass integrity checks.'
    },
    {
      code: `const calculatedCRC = await calculateCRC32(packageData); if (calculatedCRC === checksum) {`,
      correct: false,
      explanation: 'CRC32 is designed for error detection, not security. It\'s extremely weak against malicious modification and provides no authenticity verification.'
    },
    {
      code: `const primaryChecksum = await calculateSHA1(packageData); const secondaryChecksum = await calculateMD5(packageData); if (primaryChecksum === checksum && secondaryChecksum) {`,
      correct: false,
      explanation: 'Multiple weak checksums don\'t improve security. Both SHA1 and MD5 can be manipulated by attackers, and having multiple checksums doesn\'t verify the package source\'s authenticity.'
    },
    {
      code: `if (downloadUrl.startsWith('https://')) { const calculatedChecksum = await calculateSHA1(packageData); }`,
      correct: false,
      explanation: 'HTTPS validation ensures secure transport but doesn\'t verify package authenticity. Compromised HTTPS sites can still serve malicious packages with matching checksums.'
    },
    {
      code: `const packageHash = await calculateSHA1(packageData.slice(0, 1024)); if (packageHash === checksum) {`,
      correct: false,
      explanation: 'Partial checksums are weaker than full checksums. Attackers can manipulate package contents while keeping the first 1KB matching the expected partial checksum.'
    },
    {
      code: `const timestamp = Date.now(); const saltedData = timestamp + packageData; const calculatedChecksum = await calculateSHA1(saltedData);`,
      correct: false,
      explanation: 'Time-based salting doesn\'t improve authenticity verification. The timestamp isn\'t cryptographically signed, and attackers can still manipulate both package content and timing.'
    },
    {
      code: `if (packageName.endsWith('.trusted') && calculatedChecksum === checksum) {`,
      correct: false,
      explanation: 'File extension checking is superficial and doesn\'t verify authenticity. Attackers can name malicious packages with .trusted extensions while providing matching checksums.'
    }
  ]
}