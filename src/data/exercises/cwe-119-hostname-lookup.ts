import type { Exercise } from '@/data/exercises'

/**
 * CWE-119 exercise: Hostname lookup buffer overflow
 * Based on MITRE demonstrative examples showing buffer overflow vulnerabilities
 */
export const cwe119HostnameLookup: Exercise = {
  cweId: 'CWE-119',
  name: 'Memory Buffer Bounds - Network Hostname Lookup',

  vulnerableFunction: `// Note: This is a simulated C-style function in JavaScript for educational purposes
function host_lookup(userSuppliedAddr) {
  // Simulated C-style fixed buffer allocation
  const HOSTNAME_SIZE = 64;
  let hostname = new Array(HOSTNAME_SIZE);

  // Validate address format (basic check)
  if (!isValidIPFormat(userSuppliedAddr)) {
    throw new Error('Invalid IP address format');
  }

  // Simulated DNS lookup that could return long hostname
  const resolvedHostname = performDNSLookup(userSuppliedAddr);

  // Copy hostname to fixed buffer (VULNERABLE - no bounds checking)
  for (let i = 0; i < resolvedHostname.length; i++) {
    hostname[i] = resolvedHostname[i];
  }

  return hostname.join('').replace(/\\0/g, '');
}

function performDNSLookup(addr) {
  // Simulated function that might return very long hostnames
  // Could return something like: "very-long-subdomain.example-with-many-parts.com..."
  return mockDNSResponse(addr);
}`,

  vulnerableLine: `for (let i = 0; i < resolvedHostname.length; i++) {`,

  options: [
    {
      code: `function host_lookup(userSuppliedAddr) {
  const MAX_HOSTNAME_SIZE = 253; // RFC compliant max hostname length

  if (!isValidIPFormat(userSuppliedAddr)) {
    throw new Error('Invalid IP address format');
  }

  const resolvedHostname = performDNSLookup(userSuppliedAddr);

  if (resolvedHostname.length > MAX_HOSTNAME_SIZE) {
    throw new Error('Hostname too long');
  }

  // Safe copying with bounds checking
  const hostname = resolvedHostname.substring(0, MAX_HOSTNAME_SIZE);
  return hostname;
}`,
      correct: true,
      explanation: `Correct! Proper bounds checking validates hostname length before copying. This prevents buffer overflow by ensuring the resolved hostname fits within safe limits, following MITRE recommendations for input validation.`
    },
    // Buffer overflow vulnerabilities from MITRE
    {
      code: `const HOSTNAME_SIZE = 64;
let hostname = new Array(HOSTNAME_SIZE);
for (let i = 0; i < resolvedHostname.length; i++) {
    hostname[i] = resolvedHostname[i];
}`,
      correct: false,
      explanation: 'Direct from MITRE: Unchecked copy loop allows buffer overflow. A hostname longer than 64 characters will overwrite memory beyond the allocated buffer, potentially corrupting adjacent data structures.'
    },
    {
      code: `const hostname = new Array(64);
resolvedHostname.split('').forEach((char, index) => {
    hostname[index] = char;
});`,
      correct: false,
      explanation: 'forEach without bounds checking creates the same vulnerability. Long hostnames will write beyond the 64-character buffer boundary, causing memory corruption.'
    },
    {
      code: `let hostname = '';
for (let i = 0; i < resolvedHostname.length && i < 64; i++) {
    hostname += resolvedHostname[i];
}
// But then copy to fixed buffer unsafely
const buffer = new Array(32);
for (let i = 0; i < hostname.length; i++) {
    buffer[i] = hostname[i];
}`,
      correct: false,
      explanation: 'Safe initial copy followed by unsafe secondary copy. The second loop can still overflow the 32-character buffer if the hostname is longer than the destination buffer.'
    },
    {
      code: `const hostname = new Array(64);
let index = 0;
while (index < resolvedHostname.length) {
    hostname[index] = resolvedHostname[index];
    index++;
}`,
      correct: false,
      explanation: 'While loop without bounds checking on destination buffer. This creates the same overflow vulnerability as the for loop, writing past the 64-character boundary.'
    },
    {
      code: `const maxLen = Math.min(resolvedHostname.length, 63);
const hostname = new Array(64);
for (let i = 0; i <= maxLen; i++) {
    hostname[i] = resolvedHostname[i];
}`,
      correct: false,
      explanation: 'Off-by-one error in bounds checking. Using <= instead of < means the loop runs one iteration too many, potentially writing past the buffer boundary at index 64.'
    },
    {
      code: `const hostname = new Array(64);
if (resolvedHostname.length < 100) {
    for (let i = 0; i < resolvedHostname.length; i++) {
        hostname[i] = resolvedHostname[i];
    }
}`,
      correct: false,
      explanation: 'Insufficient bounds checking allows overflow. Checking for length < 100 when the buffer is only 64 characters still allows overflows for hostnames between 64-99 characters.'
    },
    {
      code: `const hostname = Buffer.alloc(64);
resolvedHostname.split('').forEach((char, index) => {
    if (index < hostname.length) {
        hostname[index] = char.charCodeAt(0);
    }
});`,
      correct: false,
      explanation: 'While this has bounds checking, it silently truncates without error handling. Silent truncation can lead to incomplete hostnames and application logic errors.'
    },
    {
      code: `const hostname = new Array(64);
const safeCopy = resolvedHostname.substring(0, 64);
for (let i = 0; i < 64; i++) {
    hostname[i] = safeCopy[i] || '';
}`,
      correct: false,
      explanation: 'Fixed-size loop ignores actual data length. This can copy undefined values or empty strings when the hostname is shorter than 64 characters, corrupting buffer contents.'
    },
    {
      code: `try {
    const hostname = new Array(64);
    for (let i = 0; i < resolvedHostname.length; i++) {
        hostname[i] = resolvedHostname[i];
    }
} catch (e) {
    console.log('Buffer overflow detected');
}`,
      correct: false,
      explanation: 'Try-catch does not prevent JavaScript array bounds violations. JavaScript arrays automatically expand, so this will not throw an exception but will create an oversized array.'
    },
    {
      code: `const hostname = new Array(64);
const chunkSize = Math.floor(resolvedHostname.length / 64);
for (let i = 0; i < 64; i++) {
    hostname[i] = resolvedHostname[i * chunkSize] || '';
}`,
      correct: false,
      explanation: 'Sampling/chunking strategy corrupts data integrity. This approach loses hostname characters and creates invalid hostnames that may break network operations.'
    }
  ]
}