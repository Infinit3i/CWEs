import type { Exercise } from '@/data/exercises'

/**
 * CWE-349 Exercise 1: Mixed Trusted and Untrusted Data Sources
 * Based on MITRE examples of accepting extraneous untrusted data with trusted data
 */
export const cwe349MixedDataSources: Exercise = {
  cweId: 'CWE-349',
  name: 'Mixed Data Sources - API Response Handler',

  vulnerableFunction: `function processApiResponse(trustedServerResponse, userProvidedMetadata) {
  // Merge trusted API response with user-provided metadata
  const combinedData = {
    ...trustedServerResponse,
    ...userProvidedMetadata
  };

  // Process the combined data as if it's all trusted
  if (combinedData.isAdmin) {
    return {
      ...combinedData,
      adminAccess: true,
      sensitiveOperations: ['deleteUser', 'modifyRoles', 'accessLogs']
    };
  }

  return combinedData;
}`,

  vulnerableLine: `...userProvidedMetadata`,

  options: [
    {
      code: `// Only use trusted server data for security decisions
if (trustedServerResponse.isAdmin) {
  return {
    ...trustedServerResponse,
    userMetadata: userProvidedMetadata,
    adminAccess: true,
    sensitiveOperations: ['deleteUser', 'modifyRoles', 'accessLogs']
  };
}
return {
  ...trustedServerResponse,
  userMetadata: userProvidedMetadata
};`,
      correct: true,
      explanation: `Separate trusted from untrusted data`
    },
    {
      code: `const combinedData = {
  ...trustedServerResponse,
  ...userProvidedMetadata
};`,
      correct: false,
      explanation: 'Merging untrusted data with trusted data allows attackers to override security-critical properties. Users can include {"isAdmin": true} to gain unauthorized privileges.'
    },
    {
      code: `Object.assign(trustedServerResponse, userProvidedMetadata);`,
      correct: false,
      explanation: 'Object.assign directly modifies the trusted object with untrusted data, allowing complete override of security properties.'
    },
    {
      code: `const combinedData = Object.assign({}, userProvidedMetadata, trustedServerResponse);`,
      correct: false,
      explanation: 'Reversing merge order does not solve the issue. Trusted data can still be influenced by untrusted properties during processing.'
    },
    {
      code: `const combinedData = {
  ...trustedServerResponse,
  metadata: userProvidedMetadata
};
if (combinedData.isAdmin || combinedData.metadata.isAdmin) {
  return { ...combinedData, adminAccess: true };
}`,
      correct: false,
      explanation: 'Checking both trusted and untrusted sources for security decisions defeats the security boundary and allows privilege escalation.'
    },
    {
      code: `if (Object.keys(userProvidedMetadata).length > 0) {
  const combinedData = { ...trustedServerResponse, ...userProvidedMetadata };
  return combinedData;
}`,
      correct: false,
      explanation: 'Conditional merging based on metadata presence does not prevent the security issue - untrusted data still overrides trusted data.'
    },
    {
      code: `const filteredMetadata = Object.keys(userProvidedMetadata).reduce((acc, key) => {
  if (key !== 'isAdmin') acc[key] = userProvidedMetadata[key];
  return acc;
}, {});
const combinedData = { ...trustedServerResponse, ...filteredMetadata };`,
      correct: false,
      explanation: 'Blacklisting specific properties is insufficient. Many other security-critical properties may exist beyond just "isAdmin".'
    },
    {
      code: `const combinedData = JSON.parse(JSON.stringify({
  ...trustedServerResponse,
  ...userProvidedMetadata
}));`,
      correct: false,
      explanation: 'Deep cloning does not prevent the fundamental issue of untrusted data overriding trusted security properties.'
    },
    {
      code: `const combinedData = {
  trusted: trustedServerResponse,
  untrusted: userProvidedMetadata
};
if (combinedData.trusted.isAdmin || combinedData.untrusted.isAdmin) {
  return { ...combinedData, adminAccess: true };
}`,
      correct: false,
      explanation: 'Even with namespace separation, checking both trusted and untrusted sources for security decisions allows privilege escalation.'
    },
    {
      code: `try {
  const combinedData = { ...trustedServerResponse, ...userProvidedMetadata };
  return combinedData;
} catch (e) {
  return trustedServerResponse;
}`,
      correct: false,
      explanation: 'Error handling does not prevent the security vulnerability. The dangerous merge typically succeeds without throwing exceptions.'
    }
  ]
}