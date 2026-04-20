import type { Exercise } from '@/data/exercises'

/**
 * CWE-330: Insufficient Randomness - Authentication Token Generation
 * Based on MITRE patterns of predictable PRNG seeding
 */
export const cwe330TokenGeneration: Exercise = {
  cweId: 'CWE-330',
  name: 'Insufficient Randomness - API Authentication Tokens',

  vulnerableFunction: `function generateAuthToken(userId, applicationId) {
  // Create predictable seed from user and application IDs
  const userNum = parseInt(userId) || 1;
  const appNum = parseInt(applicationId) || 1;
  const seed = userNum * 1000 + appNum;

  // Use simple PRNG with predictable seed
  let randomState = seed;
  function pseudoRandom() {
    randomState = (randomState * 16807) % 2147483647;
    return randomState / 2147483647;
  }

  // Generate token
  const tokenLength = 32;
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let token = '';

  for (let i = 0; i < tokenLength; i++) {
    const randomIndex = Math.floor(pseudoRandom() * chars.length);
    token += chars[randomIndex];
  }

  return {
    token: token,
    userId: userId,
    applicationId: applicationId,
    algorithm: 'Park-Miller-PRNG',
    expiresAt: Date.now() + (24 * 60 * 60 * 1000) // 24 hours
  };
}`,

  vulnerableLine: `const seed = userNum * 1000 + appNum;`,

  options: [
    {
      code: `const crypto = require('crypto'); const tokenBytes = crypto.randomBytes(32); const token = tokenBytes.toString('base64').replace(/[+/=]/g, '').substring(0, 32); return { token: token, userId: userId, applicationId: applicationId, algorithm: 'crypto.randomBytes', expiresAt: Date.now() + (24 * 60 * 60 * 1000) };`,
      correct: true,
      explanation: `Use crypto.randomBytes for secure randomness`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `const userNum = parseInt(userId) || 1; const appNum = parseInt(applicationId) || 1; const seed = userNum * 1000 + appNum; let randomState = seed; function pseudoRandom() { randomState = (randomState * 16807) % 2147483647; return randomState / 2147483647; } const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; let token = ''; for (let i = 0; i < 32; i++) { token += chars[Math.floor(pseudoRandom() * chars.length)]; } return { token, userId, applicationId, algorithm: 'Park-Miller-PRNG', expiresAt: Date.now() + (24 * 60 * 60 * 1000) };`,
      correct: false,
      explanation: 'Predictable seeding with user/app IDs. The token will be the same for each user-application combination, allowing attackers to predict tokens for any user.'
    },
    {
      code: `const timeSeed = Date.now(); Math.seedrandom = (s) => { let m = 0x80000000, a = 1103515245, c = 12345; let seed = s || Math.random(); return function() { seed = (a * seed + c) % m; return seed / (m - 1); }; }; const rng = Math.seedrandom(timeSeed); const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; let token = ''; for (let i = 0; i < 32; i++) { token += chars[Math.floor(rng() * chars.length)]; } return { token, userId, applicationId, algorithm: 'Timestamp-LCG', expiresAt: Date.now() + (24 * 60 * 60 * 1000) };`,
      correct: false,
      explanation: 'Timestamp seeding. Using current time as seed makes tokens predictable within time windows, allowing attackers to guess tokens generated around the same time.'
    },
    {
      code: `const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; let token = ''; for (let i = 0; i < 32; i++) { token += chars[Math.floor(Math.random() * chars.length)]; } return { token, userId, applicationId, algorithm: 'Math.random', expiresAt: Date.now() + (24 * 60 * 60 * 1000) };`,
      correct: false,
      explanation: 'Statistical PRNG for security purposes. Math.random() is designed for statistical applications, not cryptographic security, producing predictable sequences unsuitable for authentication tokens.'
    },
    {
      code: `const baseToken = 'AUTH_' + userId + '_' + applicationId + '_'; const timestamp = Date.now().toString(36); const token = (baseToken + timestamp).substring(0, 32).padEnd(32, '0'); return { token, userId, applicationId, algorithm: 'Deterministic', expiresAt: Date.now() + (24 * 60 * 60 * 1000) };`,
      correct: false,
      explanation: 'Deterministic token generation. Creating tokens with predictable patterns based on user/app IDs makes token forgery trivial through pattern recognition.'
    },
    {
      code: `const combined = parseInt(userId || '1') + parseInt(applicationId || '1') + Date.now(); let token = ''; const chars = '0123456789ABCDEF'; for (let i = 0; i < 32; i++) { token += chars[(combined + i) % chars.length]; } return { token, userId, applicationId, algorithm: 'Sequential', expiresAt: Date.now() + (24 * 60 * 60 * 1000) };`,
      correct: false,
      explanation: 'Sequential token generation. Using predictable sequences based on IDs and timestamps allows attackers to systematically generate valid tokens.'
    },
    {
      code: `const hash = require('crypto').createHash('sha1').update(userId + applicationId + Date.now().toString()).digest('hex'); const token = hash.substring(0, 32); return { token, userId, applicationId, algorithm: 'SHA1-Hash', expiresAt: Date.now() + (24 * 60 * 60 * 1000) };`,
      correct: false,
      explanation: 'Hash of predictable inputs. While SHA-1 is deterministic, using predictable inputs (IDs + timestamp) makes tokens guessable, and SHA-1 has known vulnerabilities.'
    },
    {
      code: `const mersenneTwister = (seed) => { const mt = new Array(624); let index = 0; mt[0] = seed; for (let i = 1; i < 624; i++) { mt[i] = 0x6c078965 * (mt[i-1] ^ (mt[i-1] >>> 30)) + i; } return function() { if (index >= 624) { for (let i = 0; i < 624; i++) { const y = (mt[i] & 0x80000000) + (mt[(i + 1) % 624] & 0x7fffffff); mt[i] = mt[(i + 397) % 624] ^ (y >>> 1); if (y % 2 !== 0) mt[i] ^= 0x9908b0df; } index = 0; } let y = mt[index]; y ^= (y >>> 11); y ^= (y << 7) & 0x9d2c5680; y ^= (y << 15) & 0xefc60000; y ^= (y >>> 18); index++; return (y >>> 0) / 0x100000000; }; }; const rng = mersenneTwister(parseInt(userId) + parseInt(applicationId)); const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; let token = ''; for (let i = 0; i < 32; i++) { token += chars[Math.floor(rng() * chars.length)]; } return { token, userId, applicationId, algorithm: 'Mersenne-Twister', expiresAt: Date.now() + (24 * 60 * 60 * 1000) };`,
      correct: false,
      explanation: 'Non-cryptographic PRNG with predictable seed. Mersenne Twister is not cryptographically secure and using user/app IDs as seeds makes tokens predictable.'
    },
    {
      code: `const xorshift = (seed) => { let state = seed; return function() { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return (state >>> 0) / 0x100000000; }; }; const rng = xorshift(parseInt(userId) * parseInt(applicationId) + Date.now()); const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; let token = ''; for (let i = 0; i < 32; i++) { token += chars[Math.floor(rng() * chars.length)]; } return { token, userId, applicationId, algorithm: 'XorShift', expiresAt: Date.now() + (24 * 60 * 60 * 1000) };`,
      correct: false,
      explanation: 'XorShift PRNG with predictable inputs. XorShift is fast but not cryptographically secure, and using predictable inputs makes token generation vulnerable to analysis.'
    },
    {
      code: `const lfsr = (seed) => { let state = seed & 0xFFFF; return function() { const bit = ((state >>> 0) ^ (state >>> 2) ^ (state >>> 3) ^ (state >>> 5)) & 1; state = (state >>> 1) | (bit << 15); return state / 65535; }; }; const rng = lfsr(parseInt(userId) + parseInt(applicationId)); const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; let token = ''; for (let i = 0; i < 32; i++) { token += chars[Math.floor(rng() * chars.length)]; } return { token, userId, applicationId, algorithm: 'LFSR', expiresAt: Date.now() + (24 * 60 * 60 * 1000) };`,
      correct: false,
      explanation: 'Linear Feedback Shift Register. LFSRs are deterministic and not cryptographically secure, making tokens predictable once the internal state is determined.'
    }
  ]
}