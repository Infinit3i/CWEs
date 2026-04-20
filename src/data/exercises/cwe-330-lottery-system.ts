import type { Exercise } from '@/data/exercises'

/**
 * CWE-330: Insufficient Randomness - Lottery Number Generation
 * Based on MITRE patterns showing predictable randomness in fair systems
 */
export const cwe330LotterySystem: Exercise = {
  cweId: 'CWE-330',
  name: 'Insufficient Randomness - Digital Lottery System',
  language: 'JavaScript',

  vulnerableFunction: `function generateLotteryNumbers(drawId, participantCount) {
  // Seed based on draw ID and participant count
  const seed = parseInt(drawId) * 1000 + participantCount;

  // Use simple LCG for "random" number generation
  let randomState = seed;
  function simpleLCG() {
    randomState = (randomState * 1664525 + 1013904223) % Math.pow(2, 32);
    return randomState / Math.pow(2, 32);
  }

  // Generate 6 lottery numbers (1-49)
  const lotteryNumbers = [];
  const usedNumbers = new Set();

  while (lotteryNumbers.length < 6) {
    const number = Math.floor(simpleLCG() * 49) + 1;
    if (!usedNumbers.has(number)) {
      lotteryNumbers.push(number);
      usedNumbers.add(number);
    }
  }

  return {
    drawId: drawId,
    numbers: lotteryNumbers.sort((a, b) => a - b),
    participantCount: participantCount,
    algorithm: 'LCG-Seeded',
    drawnAt: new Date().toISOString(),
    seed: seed // This would typically not be exposed!
  };
}`,

  vulnerableLine: `const seed = parseInt(drawId) * 1000 + participantCount;`,

  options: [
    {
      code: `const crypto = require('crypto'); const lotteryNumbers = []; const usedNumbers = new Set(); while (lotteryNumbers.length < 6) { const randomBytes = crypto.randomBytes(1); const number = (randomBytes[0] % 49) + 1; if (!usedNumbers.has(number)) { lotteryNumbers.push(number); usedNumbers.add(number); } } return { drawId: drawId, numbers: lotteryNumbers.sort((a, b) => a - b), participantCount: participantCount, algorithm: 'crypto.randomBytes', drawnAt: new Date().toISOString() };`,
      correct: true,
      explanation: `Use crypto.randomBytes for secure randomness`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `const seed = parseInt(drawId) * 1000 + participantCount; let randomState = seed; function simpleLCG() { randomState = (randomState * 1664525 + 1013904223) % Math.pow(2, 32); return randomState / Math.pow(2, 32); } const lotteryNumbers = []; const usedNumbers = new Set(); while (lotteryNumbers.length < 6) { const number = Math.floor(simpleLCG() * 49) + 1; if (!usedNumbers.has(number)) { lotteryNumbers.push(number); usedNumbers.add(number); } } return { drawId, numbers: lotteryNumbers.sort((a, b) => a - b), participantCount, algorithm: 'LCG-Seeded', drawnAt: new Date().toISOString() };`,
      correct: false,
      explanation: 'Predictable seeding with known values. Since draw ID and participant count are known, anyone can reproduce the exact same lottery numbers, compromising fairness completely.'
    },
    {
      code: `const timeSeed = Date.now(); Math.seedrandom = (s) => { let state = s; return function() { state = (state * 9301 + 49297) % 233280; return state / 233280; }; }; const rng = Math.seedrandom(timeSeed); const lotteryNumbers = []; const usedNumbers = new Set(); while (lotteryNumbers.length < 6) { const number = Math.floor(rng() * 49) + 1; if (!usedNumbers.has(number)) { lotteryNumbers.push(number); usedNumbers.add(number); } } return { drawId, numbers: lotteryNumbers.sort((a, b) => a - b), participantCount, algorithm: 'Timestamp-Seeded', drawnAt: new Date().toISOString() };`,
      correct: false,
      explanation: 'Timestamp seeding. Using current time as seed makes lottery outcomes predictable within time windows, allowing manipulation of drawing timing to influence results.'
    },
    {
      code: `const lotteryNumbers = []; const usedNumbers = new Set(); while (lotteryNumbers.length < 6) { const number = Math.floor(Math.random() * 49) + 1; if (!usedNumbers.has(number)) { lotteryNumbers.push(number); usedNumbers.add(number); } } return { drawId, numbers: lotteryNumbers.sort((a, b) => a - b), participantCount, algorithm: 'Math.random', drawnAt: new Date().toISOString() };`,
      correct: false,
      explanation: 'Statistical PRNG for security/fairness-critical applications. Math.random() produces predictable sequences that can be analyzed and potentially manipulated.'
    },
    {
      code: `const baseNumbers = [1, 7, 14, 21, 28, 35]; const dayOfYear = Math.floor((Date.now() - new Date(new Date().getFullYear(), 0, 0)) / (1000 * 60 * 60 * 24)); const lotteryNumbers = baseNumbers.map((base, index) => ((base + dayOfYear + index) % 49) + 1); return { drawId, numbers: lotteryNumbers.sort((a, b) => a - b), participantCount, algorithm: 'Calendar-Based', drawnAt: new Date().toISOString() };`,
      correct: false,
      explanation: 'Calendar-based generation. Using day of year with fixed patterns creates predictable lottery numbers that can be calculated in advance.'
    },
    {
      code: `const sequentialSeed = parseInt(drawId) + participantCount; const lotteryNumbers = []; for (let i = 0; i < 6; i++) { const number = ((sequentialSeed + i * 7) % 49) + 1; lotteryNumbers.push(number); } return { drawId, numbers: [...new Set(lotteryNumbers)].sort((a, b) => a - b).slice(0, 6), participantCount, algorithm: 'Sequential', drawnAt: new Date().toISOString() };`,
      correct: false,
      explanation: 'Sequential generation from predictable base. Using known values with simple arithmetic creates highly predictable lottery outcomes.'
    },
    {
      code: `const hash = require('crypto').createHash('md5').update(drawId + participantCount.toString()).digest('hex'); const lotteryNumbers = []; for (let i = 0; i < 6; i++) { const hexPair = hash.substring(i * 2, i * 2 + 2); const number = (parseInt(hexPair, 16) % 49) + 1; lotteryNumbers.push(number); } return { drawId, numbers: [...new Set(lotteryNumbers)].sort((a, b) => a - b).slice(0, 6), participantCount, algorithm: 'MD5-Hash', drawnAt: new Date().toISOString() };`,
      correct: false,
      explanation: 'Hash of predictable inputs. While MD5 is deterministic, using known inputs makes lottery numbers calculable by anyone with the draw parameters.'
    },
    {
      code: `const fibonacci = (n) => n <= 1 ? n : fibonacci(n - 1) + fibonacci(n - 2); const fibSeed = fibonacci(parseInt(drawId) % 20); let state = fibSeed; const lotteryNumbers = []; const usedNumbers = new Set(); while (lotteryNumbers.length < 6) { state = (state * 1103515245 + 12345) % Math.pow(2, 31); const number = (state % 49) + 1; if (!usedNumbers.has(number)) { lotteryNumbers.push(number); usedNumbers.add(number); } } return { drawId, numbers: lotteryNumbers.sort((a, b) => a - b), participantCount, algorithm: 'Fibonacci-LCG', drawnAt: new Date().toISOString() };`,
      correct: false,
      explanation: 'Mathematical sequence with LCG. Fibonacci numbers are deterministic, and combined with predictable draw IDs, create reproducible lottery outcomes.'
    },
    {
      code: `const primeNumbers = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]; const primeIndex = parseInt(drawId) % primeNumbers.length; const basePrime = primeNumbers[primeIndex]; const lotteryNumbers = []; for (let i = 1; i <= 6; i++) { const number = ((basePrime * i + participantCount) % 49) + 1; lotteryNumbers.push(number); } return { drawId, numbers: [...new Set(lotteryNumbers)].sort((a, b) => a - b).slice(0, 6), participantCount, algorithm: 'Prime-Based', drawnAt: new Date().toISOString() };`,
      correct: false,
      explanation: 'Prime number patterns. Using known primes with predictable multipliers creates systematic patterns that can be calculated by participants.'
    },
    {
      code: `const memoryUsage = process.memoryUsage().heapUsed % 1000000; const cpuUsage = Date.now() % 1000; const systemSeed = memoryUsage + cpuUsage + parseInt(drawId); let state = systemSeed; const lotteryNumbers = []; const usedNumbers = new Set(); while (lotteryNumbers.length < 6) { state = (state * 16807) % 2147483647; const number = (state % 49) + 1; if (!usedNumbers.has(number)) { lotteryNumbers.push(number); usedNumbers.add(number); } } return { drawId, numbers: lotteryNumbers.sort((a, b) => a - b), participantCount, algorithm: 'System-State', drawnAt: new Date().toISOString() };`,
      correct: false,
      explanation: 'System state as randomness source. Memory usage and CPU timing can be observed or influenced, and combined with known draw ID, creates manipulable outcomes.'
    }
  ]
}