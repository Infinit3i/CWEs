import type { Exercise } from '@/data/exercises'

/**
 * CWE-331: Insufficient Entropy - Cryptographic Nonce Generation
 * Based on MITRE patterns showing inadequate nonce randomness for security
 */
export const cwe331NonceGeneration: Exercise = {
  cweId: 'CWE-331',
  name: 'Insufficient Entropy - Cryptographic Nonce Generation',
  language: 'JavaScript',

  vulnerableFunction: `function generateCryptographicNonce(transactionId, clientId) {
  // Use transaction ID as base entropy
  const txNumber = parseInt(transactionId) || 1;

  // Add client ID as secondary entropy
  const clientNumber = parseInt(clientId) || 1;

  // Use current millisecond for "randomness"
  const millisecond = Date.now() % 1000;

  // Combine all entropy sources with limited range
  const nonceValue = (txNumber + clientNumber + millisecond) % 1000000;

  // Convert to hex nonce
  const nonce = nonceValue.toString(16).padStart(12, '0');

  return {
    nonce: nonce,
    transactionId: transactionId,
    clientId: clientId,
    algorithm: 'TX-Client-Time',
    entropy: {
      transaction: txNumber,
      client: clientNumber,
      millisecond: millisecond,
      combined: nonceValue
    },
    entropyBits: Math.log2(1000000), // ~20 bits
    maxValue: 1000000
  };
}`,

  vulnerableLine: `const nonceValue = (txNumber + clientNumber + millisecond) % 1000000;`,

  options: [
    {
      code: `const crypto = require('crypto'); const nonceBytes = crypto.randomBytes(16); const nonce = nonceBytes.toString('hex'); return { nonce: nonce, transactionId: transactionId, clientId: clientId, algorithm: 'crypto.randomBytes', entropy: { source: 'Cryptographic random number generator' }, entropyBits: 128, maxValue: 'N/A - cryptographically random' };`,
      correct: true,
      explanation: `Use crypto.randomBytes for secure randomness`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `const txNumber = parseInt(transactionId) || 1; const clientNumber = parseInt(clientId) || 1; const millisecond = Date.now() % 1000; const nonceValue = (txNumber + clientNumber + millisecond) % 1000000; const nonce = nonceValue.toString(16).padStart(12, '0'); return { nonce, transactionId, clientId, algorithm: 'TX-Client-Time', entropy: { transaction: txNumber, client: clientNumber, millisecond, combined: nonceValue }, entropyBits: Math.log2(1000000), maxValue: 1000000 };`,
      correct: false,
      explanation: 'Insufficient entropy from predictable IDs. Transaction and client IDs are known values, and millisecond timing provides minimal entropy (~20 bits total), making nonces predictable.'
    },
    {
      code: `const timestamp = Date.now(); const nonce = (timestamp % 10000000).toString(16).padStart(12, '0'); return { nonce, transactionId, clientId, algorithm: 'Timestamp-Modulo', entropy: { timestamp, modulo: timestamp % 10000000 }, entropyBits: Math.log2(10000000), maxValue: 10000000 };`,
      correct: false,
      explanation: 'Timestamp modulo entropy. Using timestamp % 10000000 provides limited entropy (~23 bits) and creates predictable cycles in nonce generation within time windows.'
    },
    {
      code: `const sequenceNumber = (parseInt(transactionId) + parseInt(clientId)) % 100000; const nonce = sequenceNumber.toString(16).padStart(12, '0'); return { nonce, transactionId, clientId, algorithm: 'Sequential-Sum', entropy: { sequenceNumber }, entropyBits: Math.log2(100000), maxValue: 100000 };`,
      correct: false,
      explanation: 'Sequential nonce generation. Adding known transaction and client IDs creates predictable sequences that allow nonce prediction and potential replay attacks.'
    },
    {
      code: `const hash = require('crypto').createHash('md5').update(transactionId + clientId).digest('hex'); const nonce = hash.substring(0, 12); return { nonce, transactionId, clientId, algorithm: 'MD5-Hash', entropy: { hash }, entropyBits: 0, maxValue: 'Deterministic' };`,
      correct: false,
      explanation: 'Deterministic hash of known inputs. MD5 hash of known transaction and client IDs provides zero entropy - the same inputs always produce the same nonce.'
    },
    {
      code: `const dayOfWeek = new Date().getDay(); const hourOfDay = new Date().getHours(); const combinedTime = dayOfWeek * 24 + hourOfDay; const nonce = (combinedTime + parseInt(transactionId || '1')).toString(16).padStart(12, '0'); return { nonce, transactionId, clientId, algorithm: 'Calendar-TX', entropy: { dayOfWeek, hourOfDay, combinedTime }, entropyBits: Math.log2(7 * 24), maxValue: 7 * 24 };`,
      correct: false,
      explanation: 'Calendar-based entropy. Day of week and hour provide only ~8 bits of entropy, and combined with known transaction IDs, create highly predictable nonces.'
    },
    {
      code: `const charCodes = (transactionId + clientId).split('').map(c => c.charCodeAt(0)); const sum = charCodes.reduce((a, b) => a + b, 0); const nonce = (sum % 1000000).toString(16).padStart(12, '0'); return { nonce, transactionId, clientId, algorithm: 'CharCode-Sum', entropy: { charCodes, sum }, entropyBits: Math.log2(sum || 1), maxValue: 1000000 };`,
      correct: false,
      explanation: 'Character code sum entropy. Summing character codes of known strings provides minimal entropy and many different ID combinations can produce the same sum.'
    },
    {
      code: `const fibonacci = [0, 1]; for (let i = 2; i < 20; i++) { fibonacci[i] = fibonacci[i-1] + fibonacci[i-2]; } const fibIndex = (parseInt(transactionId) + parseInt(clientId)) % fibonacci.length; const nonce = fibonacci[fibIndex].toString(16).padStart(12, '0'); return { nonce, transactionId, clientId, algorithm: 'Fibonacci-Index', entropy: { fibIndex, fibValue: fibonacci[fibIndex] }, entropyBits: Math.log2(fibonacci.length), maxValue: fibonacci[fibonacci.length-1] };`,
      correct: false,
      explanation: 'Mathematical sequence entropy. Fibonacci numbers are deterministic and provide entropy only based on index selection from known inputs.'
    },
    {
      code: `const processStats = { pid: process.pid || 1234, uptime: Math.floor(process.uptime() || 1) }; const nonce = (processStats.pid + processStats.uptime).toString(16).padStart(12, '0'); return { nonce, transactionId, clientId, algorithm: 'Process-Stats', entropy: { pid: processStats.pid, uptime: processStats.uptime }, entropyBits: Math.log2(processStats.pid + processStats.uptime), maxValue: processStats.pid + processStats.uptime };`,
      correct: false,
      explanation: 'Process statistics entropy. Process ID and uptime can be observed or predicted, providing limited entropy that varies slowly over time.'
    },
    {
      code: `const memoryPercent = Math.floor((process.memoryUsage().heapUsed / process.memoryUsage().heapTotal) * 100); const nonce = (memoryPercent + parseInt(transactionId || '0')).toString(16).padStart(12, '0'); return { nonce, transactionId, clientId, algorithm: 'Memory-Percent', entropy: { memoryPercent }, entropyBits: Math.log2(100), maxValue: 100 };`,
      correct: false,
      explanation: 'System state percentage. Memory usage percentage provides very limited entropy (~7 bits) and can be influenced by attackers or observed through monitoring.'
    }
  ]
}