import type { Exercise } from '@/data/exercises'

/**
 * CWE-345: Insufficient Verification of Data Authenticity - Firmware Update Verification
 * Based on MITRE OT:ICEFALL examples with weak checksum validation
 */
export const cwe345FirmwareVerification: Exercise = {
  cweId: 'CWE-345',
  name: 'Insufficient Verification of Data Authenticity - Firmware Updates',

  vulnerableFunction: `async function updateFirmware(firmwareFile, updateMetadata) {
  const { expectedChecksum, expectedSize, version } = updateMetadata;

  try {
    // Read firmware file
    const firmwareData = await readFile(firmwareFile);

    // Verify file size
    if (firmwareData.length !== expectedSize) {
      throw new Error('Firmware size mismatch');
    }

    // Verify checksum
    const actualChecksum = calculateMD5(firmwareData);
    if (actualChecksum !== expectedChecksum) {
      throw new Error('Firmware checksum mismatch');
    }

    // Apply firmware update
    await flashFirmware(firmwareData);
    await updateFirmwareVersion(version);

    return { success: true, message: 'Firmware updated successfully' };

  } catch (error) {
    return { success: false, error: error.message };
  }
}`,

  vulnerableLine: `const actualChecksum = calculateMD5(firmwareData);`,

  options: [
    {
      code: `if (!verifyDigitalSignature(firmwareData, updateMetadata.signature, trustedPublicKey)) { throw new Error('Invalid firmware signature'); }`,
      correct: true,
      explanation: `Verify firmware signatures`
    },
    {
      code: `const actualChecksum = calculateMD5(firmwareData); // Use MD5 checksum`,
      correct: false,
      explanation: 'Direct MITRE OT:ICEFALL vulnerability pattern. MD5 checksums only detect accidental corruption, not malicious modification. Attackers can easily create malicious firmware with matching MD5 checksums.'
    },
    {
      code: `const actualChecksum = calculateSHA1(firmwareData);`,
      correct: false,
      explanation: 'SHA1 is stronger than MD5 but still cryptographically weak and doesn\'t provide authenticity. Attackers can generate malicious firmware with matching SHA1 checksums using collision attacks.'
    },
    {
      code: `const actualChecksum = calculateSHA256(firmwareData);`,
      correct: false,
      explanation: 'SHA256 prevents collision attacks but doesn\'t verify authenticity or origin. Attackers can provide malicious firmware with its own SHA256 checksum, bypassing integrity checks without signature verification.'
    },
    {
      code: `const actualChecksum = calculateCRC32(firmwareData);`,
      correct: false,
      explanation: 'CRC32 is weaker than MD5 and only suitable for error detection, not security. Attackers can easily manipulate firmware while maintaining matching CRC32 values.'
    },
    {
      code: `const actualChecksum = calculateMD5(firmwareData); const backupChecksum = calculateSHA256(firmwareData); if (actualChecksum !== expectedChecksum || !backupChecksum) {`,
      correct: false,
      explanation: 'Multiple checksums don\'t solve the authenticity problem. Both MD5 and SHA256 checksums can be calculated by attackers for malicious firmware, providing no verification of trusted origin.'
    },
    {
      code: `if (firmwareData.length > 1000000) { throw new Error('Firmware too large'); } const actualChecksum = calculateMD5(firmwareData);`,
      correct: false,
      explanation: 'Size validation doesn\'t address authenticity verification. Malicious firmware within size limits can still pass MD5 checksum validation when checksums are attacker-controlled.'
    },
    {
      code: `const actualChecksum = calculateMD5(firmwareData.slice(0, 1000)); // Partial checksum`,
      correct: false,
      explanation: 'Partial checksums are even weaker than full checksums. Attackers can craft malicious firmware where the first 1KB matches the expected partial checksum while the rest contains malicious code.'
    },
    {
      code: `const salt = 'firmware_salt_2024'; const actualChecksum = calculateMD5(salt + firmwareData);`,
      correct: false,
      explanation: 'Salted MD5 doesn\'t provide authenticity verification. Attackers who know the salt can calculate matching checksums for malicious firmware, and MD5 remains cryptographically weak.'
    },
    {
      code: `const actualChecksum = calculateMD5(firmwareData); if (actualChecksum === expectedChecksum && version.startsWith('v2.')) {`,
      correct: false,
      explanation: 'Version checking combined with MD5 doesn\'t improve authenticity. Attackers can create malicious firmware for any version with matching MD5 checksums, bypassing both validations.'
    }
  ]
}