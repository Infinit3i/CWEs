import type { Exercise } from '@/data/exercises'

export const cwe787HostnameCopy: Exercise = {
  cweId: 'CWE-787',
  name: 'Out-of-bounds Write - Hostname Resolution',

  vulnerableFunction: `function lookupHostname(userAddress) {
  const hostname = new Array(64).fill(0);

  // Validate address format
  if (!isValidIPFormat(userAddress)) {
    throw new Error('Invalid IP format');
  }

  // Simulate hostname lookup
  const resolvedName = performHostLookup(userAddress);

  // Copy hostname to buffer
  for (let i = 0; i < resolvedName.length; i++) {
    hostname[i] = resolvedName.charCodeAt(i);
  }

  return hostname;
}`,

  vulnerableLine: `hostname[i] = resolvedName.charCodeAt(i);`,

  options: [
    {
      code: `if (i < hostname.length) { hostname[i] = resolvedName.charCodeAt(i); } else { break; }`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `hostname[i] = resolvedName.charCodeAt(i);`,
      correct: false,
      explanation: 'MITRE hostname buffer pattern: No length validation on resolved hostname. Long hostnames (>64 chars) write beyond buffer bounds, potentially corrupting adjacent memory or causing crashes.'
    },
    {
      code: `hostname[i % hostname.length] = resolvedName.charCodeAt(i);`,
      correct: false,
      explanation: 'Modulo operation prevents crashes but causes data corruption by wrapping around and overwriting earlier hostname characters, producing invalid hostname data.'
    },
    {
      code: `hostname[Math.min(i, 63)] = resolvedName.charCodeAt(i);`,
      correct: false,
      explanation: 'This prevents out-of-bounds writes but repeatedly overwrites hostname[63] with different characters, losing data and creating malformed hostnames.'
    },
    {
      code: `if (resolvedName.length <= 64) { hostname[i] = resolvedName.charCodeAt(i); }`,
      correct: false,
      explanation: 'Pre-check is insufficient - the vulnerability occurs during iteration. Need per-iteration bounds checking to prevent writes past buffer end.'
    },
    {
      code: `try { hostname[i] = resolvedName.charCodeAt(i); } catch(e) { return hostname; }`,
      correct: false,
      explanation: 'Exception handling after memory corruption is too late. Out-of-bounds writes occur before exceptions are thrown, potentially damaging system stability.'
    },
    {
      code: `hostname[i] = resolvedName.charCodeAt(i) & 0xFF;`,
      correct: false,
      explanation: 'Byte masking does not address bounds checking. This still writes past buffer boundaries when resolvedName exceeds 64 characters.'
    },
    {
      code: `if (i >= 0 && i <= 64) { hostname[i] = resolvedName.charCodeAt(i); }`,
      correct: false,
      explanation: 'Off-by-one error: valid array indices are [0, 63] for 64-element array. Index 64 is out-of-bounds and causes buffer overflow.'
    },
    {
      code: `hostname.push(resolvedName.charCodeAt(i));`,
      correct: false,
      explanation: 'Push() avoids out-of-bounds writes but changes fixed-size Array(64) to dynamic array, breaking expected memory layout and buffer size constraints.'
    },
    {
      code: `Object.assign(hostname, {[i]: resolvedName.charCodeAt(i)});`,
      correct: false,
      explanation: 'Object.assign does not prevent out-of-bounds array access. This still attempts to write past allocated buffer boundaries when i >= 64.'
    }
  ]
}