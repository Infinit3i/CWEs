import type { Exercise } from '@/data/exercises'

/**
 * CWE-331: Insufficient Entropy - Random Number Seed Generation
 * Based on MITRE patterns showing inadequate entropy for random seeds
 */
export const cwe331RandomSeed: Exercise = {
  cweId: 'CWE-331',
  name: 'Insufficient Entropy - Cryptographic Seed Generation',
  language: 'JavaScript',

  vulnerableFunction: `function generateCryptographicSeed(applicationId) {
  // Use application ID as primary entropy source
  const appNumber = parseInt(applicationId) || 12345;

  // Add some time-based entropy (but limited)
  const hours = new Date().getHours();
  const minutes = new Date().getMinutes();

  // Combine low-entropy sources
  const combinedEntropy = appNumber + (hours * 60) + minutes;

  // Generate seed from low entropy
  const seed = combinedEntropy.toString().padStart(16, '0');

  return {
    seed: seed,
    applicationId: applicationId,
    algorithm: 'Time-App-Combined',
    entropyBits: Math.log2(appNumber * 24 * 60), // Very low
    components: {
      appId: appNumber,
      hours: hours,
      minutes: minutes,
      combined: combinedEntropy
    }
  };
}`,

  vulnerableLine: `const combinedEntropy = appNumber + (hours * 60) + minutes;`,

  options: [
    {
      code: `const crypto = require('crypto'); const seedBytes = crypto.randomBytes(32); const seed = seedBytes.toString('hex'); return { seed: seed, applicationId: applicationId, algorithm: 'crypto.randomBytes', entropyBits: 256, components: { randomBytes: 'High entropy from OS CSPRNG' } };`,
      correct: true,
      explanation: `Use crypto.randomBytes for secure randomness`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `const appNumber = parseInt(applicationId) || 12345; const hours = new Date().getHours(); const minutes = new Date().getMinutes(); const combinedEntropy = appNumber + (hours * 60) + minutes; const seed = combinedEntropy.toString().padStart(16, '0'); return { seed, applicationId, algorithm: 'Time-App-Combined', entropyBits: Math.log2(appNumber * 24 * 60), components: { appId: appNumber, hours, minutes, combined: combinedEntropy } };`,
      correct: false,
      explanation: 'Insufficient entropy from predictable sources. Application ID, hours, and minutes provide very limited entropy (typically < 20 bits total), making seeds easily guessable.'
    },
    {
      code: `const timestamp = Date.now(); const seed = (timestamp % 1000000).toString().padStart(16, '0'); return { seed, applicationId, algorithm: 'Timestamp-Modulo', entropyBits: Math.log2(1000000), components: { timestamp: timestamp, modulo: timestamp % 1000000 } };`,
      correct: false,
      explanation: 'Low entropy from timestamp modulo. Using timestamp % 1000000 provides only ~20 bits of entropy and creates predictable cycles in seed generation.'
    },
    {
      code: `const pid = process.pid || 1234; const uid = parseInt(applicationId) || 1; const seed = (pid * 1000 + uid).toString().padStart(16, '0'); return { seed, applicationId, algorithm: 'PID-UID', entropyBits: Math.log2(pid * 1000), components: { processId: pid, userId: uid, combined: pid * 1000 + uid } };`,
      correct: false,
      explanation: 'Process and user IDs as entropy. PIDs and UIDs provide limited entropy and can be observed or predicted by attackers, especially in containerized environments.'
    },
    {
      code: `const dayOfYear = Math.floor((Date.now() - new Date(new Date().getFullYear(), 0, 0)) / 86400000); const secondOfDay = Math.floor((Date.now() % 86400000) / 1000); const seed = (dayOfYear * 86400 + secondOfDay).toString().padStart(16, '0'); return { seed, applicationId, algorithm: 'Calendar-Second', entropyBits: Math.log2(365 * 86400), components: { dayOfYear, secondOfDay } };`,
      correct: false,
      explanation: 'Calendar-based entropy. Day of year and second of day provide limited entropy (~25 bits) and are highly predictable within known timeframes.'
    },
    {
      code: `let charSum = 0; const appIdStr = applicationId.toString(); for (let i = 0; i < appIdStr.length; i++) { charSum += appIdStr.charCodeAt(i); } const seed = charSum.toString().padStart(16, '0'); return { seed, applicationId, algorithm: 'Character-Sum', entropyBits: Math.log2(charSum || 1), components: { characterSum: charSum } };`,
      correct: false,
      explanation: 'Character sum entropy. Summing character codes drastically reduces entropy to a small number range, making seeds highly predictable.'
    },
    {
      code: `const fibonacci = [1, 1]; for (let i = 2; i < 20; i++) { fibonacci[i] = fibonacci[i-1] + fibonacci[i-2]; } const appIndex = parseInt(applicationId) % fibonacci.length; const seed = fibonacci[appIndex].toString().padStart(16, '0'); return { seed, applicationId, algorithm: 'Fibonacci-Index', entropyBits: Math.log2(fibonacci.length), components: { fibonacciValue: fibonacci[appIndex], index: appIndex } };`,
      correct: false,
      explanation: 'Mathematical sequence entropy. Fibonacci numbers are deterministic and provide minimal entropy based only on the index selection.'
    },
    {
      code: `const primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]; const appMod = parseInt(applicationId) % primes.length; const timeMod = Date.now() % primes.length; const seed = (primes[appMod] * primes[timeMod]).toString().padStart(16, '0'); return { seed, applicationId, algorithm: 'Prime-Product', entropyBits: Math.log2(primes.length * primes.length), components: { prime1: primes[appMod], prime2: primes[timeMod] } };`,
      correct: false,
      explanation: 'Prime number entropy. Using a small set of primes provides very limited entropy (~8 bits) regardless of how they are combined.'
    },
    {
      code: `const memStats = process.memoryUsage(); const memEntropy = (memStats.heapUsed + memStats.external) % 100000; const seed = memEntropy.toString().padStart(16, '0'); return { seed, applicationId, algorithm: 'Memory-State', entropyBits: Math.log2(100000), components: { memoryEntropy: memEntropy, heapUsed: memStats.heapUsed } };`,
      correct: false,
      explanation: 'System memory state entropy. Memory usage provides limited entropy (~17 bits) and can be influenced or observed by attackers sharing the same system.'
    },
    {
      code: `const userAgent = 'Mozilla/5.0'; let hash = 0; for (let i = 0; i < userAgent.length; i++) { hash = ((hash << 5) - hash + userAgent.charCodeAt(i)) & 0xFFFF; } const appHash = parseInt(applicationId) & 0xFFFF; const seed = (hash ^ appHash).toString().padStart(16, '0'); return { seed, applicationId, algorithm: 'UserAgent-XOR', entropyBits: 16, components: { userAgentHash: hash, appHash: appHash } };`,
      correct: false,
      explanation: 'Fixed string hash entropy. User agent strings are known constants that provide no real entropy, limiting seed strength to application ID variation only.'
    }
  ]
}