import type { Exercise } from '@/data/exercises'

/**
 * CWE-330: Insufficient Randomness - Receipt URL Generation
 * Based on MITRE demonstrative example showing timestamp seeding
 */
export const cwe330ReceiptGeneration: Exercise = {
  cweId: 'CWE-330',
  name: 'Insufficient Randomness - Purchase Receipt URLs',

  vulnerableFunction: `function generateReceiptURL(baseUrl, orderTotal) {
  // Seed PRNG with current timestamp
  const seed = Date.now();

  // Simple linear congruential generator
  let randomState = seed;
  function nextRandom() {
    randomState = (randomState * 1103515245 + 12345) % Math.pow(2, 31);
    return randomState;
  }

  // Generate receipt identifier
  const receiptId = nextRandom() % 400000000;
  const receiptUrl = baseUrl + receiptId + '.html';

  return {
    receiptUrl: receiptUrl,
    receiptId: receiptId,
    orderTotal: orderTotal,
    algorithm: 'Timestamp-LCG',
    generatedAt: new Date().toISOString()
  };
}`,

  vulnerableLine: `const seed = Date.now();`,

  options: [
    {
      code: `const crypto = require('crypto'); const receiptBytes = crypto.randomBytes(16); const receiptId = receiptBytes.toString('hex'); const receiptUrl = baseUrl + receiptId + '.html'; return { receiptUrl, receiptId, orderTotal, algorithm: 'CSPRNG', generatedAt: new Date().toISOString() };`,
      correct: true,
      explanation: `Use crypto.randomBytes for secure randomness`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `const seed = Date.now(); let randomState = seed; function nextRandom() { randomState = (randomState * 1103515245 + 12345) % Math.pow(2, 31); return randomState; } const receiptId = nextRandom() % 400000000; const receiptUrl = baseUrl + receiptId + '.html'; return { receiptUrl, receiptId, orderTotal, algorithm: 'Timestamp-LCG', generatedAt: new Date().toISOString() };`,
      correct: false,
      explanation: 'Timestamp seeding of PRNG. Using current time as seed creates predictable receipt URLs since timestamps are sequential and can be guessed within reasonable timeframes.'
    },
    {
      code: `const receiptId = Math.floor(Math.random() * 400000000); const receiptUrl = baseUrl + receiptId + '.html'; return { receiptUrl, receiptId, orderTotal, algorithm: 'Math.random', generatedAt: new Date().toISOString() };`,
      correct: false,
      explanation: 'Statistical PRNG for security-sensitive identifiers. Math.random() produces predictable outputs unsuitable for creating secure URLs that protect customer privacy.'
    },
    {
      code: `const receiptId = Date.now() % 400000000; const receiptUrl = baseUrl + receiptId + '.html'; return { receiptUrl, receiptId, orderTotal, algorithm: 'Direct-Timestamp', generatedAt: new Date().toISOString() };`,
      correct: false,
      explanation: 'Direct timestamp usage. Using timestamp directly makes receipt URLs highly predictable - attackers can easily guess URLs generated around the same time period.'
    },
    {
      code: `const orderSequence = parseInt(orderTotal * 100) % 1000000; const timeComponent = Date.now() % 100000; const receiptId = orderSequence * 1000 + timeComponent; const receiptUrl = baseUrl + receiptId + '.html'; return { receiptUrl, receiptId, orderTotal, algorithm: 'Order-Timestamp', generatedAt: new Date().toISOString() };`,
      correct: false,
      explanation: 'Predictable combination. Combining order total with timestamp creates predictable patterns that allow attackers to systematically guess receipt URLs.'
    },
    {
      code: `let counter = Date.now() % 1000000; const receiptId = counter++; const receiptUrl = baseUrl + receiptId.toString().padStart(8, '0') + '.html'; return { receiptUrl, receiptId, orderTotal, algorithm: 'Sequential', generatedAt: new Date().toISOString() };`,
      correct: false,
      explanation: 'Sequential identifiers. Using incrementing counters makes receipt URLs trivially predictable - attackers can access all receipts by iterating through numbers.'
    },
    {
      code: `const pid = process.pid || 1234; const tid = Date.now() % 10000; const receiptId = (pid * 10000 + tid) % 400000000; const receiptUrl = baseUrl + receiptId + '.html'; return { receiptUrl, receiptId, orderTotal, algorithm: 'PID-Time', generatedAt: new Date().toISOString() };`,
      correct: false,
      explanation: 'Process ID with timestamp. Process IDs and timestamps are both predictable values that can be enumerated, making receipt URL guessing feasible.'
    },
    {
      code: `const hash = require('crypto').createHash('md5').update(Date.now().toString() + orderTotal.toString()).digest('hex'); const receiptId = parseInt(hash.substring(0, 8), 16) % 400000000; const receiptUrl = baseUrl + receiptId + '.html'; return { receiptUrl, receiptId, orderTotal, algorithm: 'MD5-Hash', generatedAt: new Date().toISOString() };`,
      correct: false,
      explanation: 'Hash of predictable inputs. While MD5 is deterministic, using predictable inputs (timestamp + order total) makes the output guessable within reasonable ranges.'
    },
    {
      code: `const fibA = Date.now() % 10000; const fibB = (Date.now() + 1) % 10000; let receiptId = 0; for (let i = 0; i < 10; i++) { receiptId = (fibA + fibB + i * 1234) % 400000000; } const receiptUrl = baseUrl + receiptId + '.html'; return { receiptUrl, receiptId, orderTotal, algorithm: 'Fibonacci-Time', generatedAt: new Date().toISOString() };`,
      correct: false,
      explanation: 'Mathematical sequence based on time. Fibonacci-like sequences initialized with timestamps are predictable and can be computed by attackers.'
    },
    {
      code: `const memUsage = process.memoryUsage().heapUsed || 12345678; const receiptId = (memUsage + Date.now()) % 400000000; const receiptUrl = baseUrl + receiptId + '.html'; return { receiptUrl, receiptId, orderTotal, algorithm: 'Memory-Time', generatedAt: new Date().toISOString() };`,
      correct: false,
      explanation: 'System state with timestamp. Memory usage and timestamps are both observable or predictable system states that can be estimated by attackers for URL guessing.'
    }
  ]
}