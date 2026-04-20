import type { Exercise } from '@/data/exercises'

/**
 * CWE-330: Insufficient Randomness - Session ID Generation
 * Based on MITRE demonstrative examples showing predictable seeds
 */
export const cwe330SessionGeneration: Exercise = {
  cweId: 'CWE-330',
  name: 'Insufficient Randomness - Session ID Generation',

  vulnerableFunction: `function generateSessionID(userID) {
  // Seed with user ID for consistent session generation
  const seed = parseInt(userID) || 12345;

  // Use Math.random() with predictable seed
  let randomState = seed;
  function seededRandom() {
    randomState = (randomState * 1103515245 + 12345) % Math.pow(2, 31);
    return randomState / Math.pow(2, 31);
  }

  // Generate session ID
  let sessionID = '';
  for (let i = 0; i < 32; i++) {
    const randomValue = Math.floor(seededRandom() * 16);
    sessionID += randomValue.toString(16);
  }

  return {
    sessionID: sessionID,
    userID: userID,
    algorithm: 'Seeded-PRNG',
    timestamp: Date.now()
  };
}`,

  vulnerableLine: `const seed = parseInt(userID) || 12345;`,

  options: [
    {
      code: `const crypto = require('crypto'); const sessionBytes = crypto.randomBytes(32); const sessionID = sessionBytes.toString('hex'); return { sessionID: sessionID, userID: userID, algorithm: 'crypto.randomBytes', timestamp: Date.now() };`,
      correct: true,
      explanation: `Use crypto.randomBytes for secure randomness`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `const seed = parseInt(userID) || 12345; let randomState = seed; function seededRandom() { randomState = (randomState * 1103515245 + 12345) % Math.pow(2, 31); return randomState / Math.pow(2, 31); } let sessionID = ''; for (let i = 0; i < 32; i++) { sessionID += Math.floor(seededRandom() * 16).toString(16); } return { sessionID, userID, algorithm: 'Seeded-PRNG', timestamp: Date.now() };`,
      correct: false,
      explanation: 'User ID as PRNG seed. Because the seed is always the user ID, the session ID will always be the same for each user, enabling session prediction and hijacking.'
    },
    {
      code: `const seed = Date.now(); Math.seedrandom = (s) => { let m_w = 123456789; let m_z = 987654321; let mask = 0xffffffff; if (s) { m_w = s; m_z = s * 2; } return function() { m_z = (36969 * (m_z & 65535) + (m_z >> 16)) & mask; m_w = (18000 * (m_w & 65535) + (m_w >> 16)) & mask; return (((m_z << 16) + m_w) & mask) / 4294967296; }; }; const rng = Math.seedrandom(seed); let sessionID = ''; for (let i = 0; i < 32; i++) { sessionID += Math.floor(rng() * 16).toString(16); } return { sessionID, userID, algorithm: 'Timestamp-Seeded', timestamp: Date.now() };`,
      correct: false,
      explanation: 'Timestamp as seed. Using current time as seed creates predictable patterns since timestamps are sequential and can be guessed within reasonable ranges.'
    },
    {
      code: `let sessionID = ''; for (let i = 0; i < 32; i++) { sessionID += Math.floor(Math.random() * 16).toString(16); } return { sessionID, userID, algorithm: 'Math.random', timestamp: Date.now() };`,
      correct: false,
      explanation: 'Statistical PRNG for security purposes. Math.random() is designed for statistical applications, not cryptographic security. It produces predictable sequences unsuitable for session IDs.'
    },
    {
      code: `const pid = process.pid || 1234; const seed = parseInt(userID) + pid + Date.now(); let state = seed; function lcg() { state = (state * 1664525 + 1013904223) % Math.pow(2, 32); return state / Math.pow(2, 32); } let sessionID = ''; for (let i = 0; i < 32; i++) { sessionID += Math.floor(lcg() * 16).toString(16); } return { sessionID, userID, algorithm: 'LCG', timestamp: Date.now() };`,
      correct: false,
      explanation: 'Linear Congruential Generator. Even with multiple seed sources, LCGs are not cryptographically secure and produce predictable sequences that can be analyzed.'
    },
    {
      code: `const baseSession = 'SESSION_' + userID + '_'; let sessionID = baseSession; for (let i = 0; i < 16; i++) { sessionID += String.fromCharCode(65 + (i % 26)); } return { sessionID, userID, algorithm: 'Deterministic', timestamp: Date.now() };`,
      correct: false,
      explanation: 'Deterministic generation. Creating session IDs with predictable patterns based on user ID makes session hijacking trivial through pattern recognition.'
    },
    {
      code: `const counter = Date.now() % 100000; let sessionID = ''; for (let i = 0; i < 32; i++) { sessionID += ((counter + i) % 16).toString(16); } return { sessionID, userID, algorithm: 'Counter-Based', timestamp: Date.now() };`,
      correct: false,
      explanation: 'Counter-based generation. Sequential or counter-based session IDs are highly predictable and allow attackers to easily guess valid session identifiers.'
    },
    {
      code: `const hash = require('crypto').createHash('md5').update(userID + Date.now().toString()).digest('hex'); const sessionID = hash.substring(0, 32); return { sessionID, userID, algorithm: 'Hash-Based', timestamp: Date.now() };`,
      correct: false,
      explanation: 'Hash of predictable inputs. While MD5 is deterministic, using predictable inputs (user ID + timestamp) makes the output guessable and MD5 has known vulnerabilities.'
    },
    {
      code: `const fibSeeds = [parseInt(userID) % 1000, (parseInt(userID) + 1) % 1000]; let sessionID = ''; for (let i = 0; i < 16; i++) { const next = (fibSeeds[0] + fibSeeds[1]) % 1000; sessionID += (next % 16).toString(16) + ((next >> 4) % 16).toString(16); fibSeeds[0] = fibSeeds[1]; fibSeeds[1] = next; } return { sessionID, userID, algorithm: 'Fibonacci', timestamp: Date.now() };`,
      correct: false,
      explanation: 'Fibonacci sequence generation. Mathematical sequences like Fibonacci are deterministic and predictable, making them unsuitable for security-critical random values.'
    },
    {
      code: `const chars = 'abcdef0123456789'; let sessionID = ''; const userHash = userID.split('').reduce((a, b) => a + b.charCodeAt(0), 0); for (let i = 0; i < 32; i++) { sessionID += chars[(userHash + i) % chars.length]; } return { sessionID, userID, algorithm: 'UserID-Based', timestamp: Date.now() };`,
      correct: false,
      explanation: 'User ID derived sequence. Generating session IDs based on user ID creates predictable patterns that allow attackers to compute session IDs for any user.'
    }
  ]
}