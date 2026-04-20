import type { Exercise } from '@/data/exercises'

/**
 * CWE-330: Insufficient Randomness - Password Reset Token Generation
 * Based on MITRE examples showing weak randomness in security contexts
 */
export const cwe330PasswordReset: Exercise = {
  cweId: 'CWE-330',
  name: 'Insufficient Randomness - Password Reset Security',
  language: 'JavaScript',

  vulnerableFunction: `function generatePasswordResetToken(email, userId) {
  // Create seed from email hash and user ID
  let emailHash = 0;
  for (let i = 0; i < email.length; i++) {
    emailHash = ((emailHash << 5) - emailHash + email.charCodeAt(i)) & 0xFFFFFF;
  }

  const seed = emailHash + parseInt(userId);

  // Use Park-Miller PRNG
  let randomState = seed;
  function parkMillerRandom() {
    randomState = (randomState * 16807) % 2147483647;
    return randomState / 2147483647;
  }

  // Generate 6-digit reset code
  const resetCode = Math.floor(parkMillerRandom() * 900000) + 100000;

  return {
    resetCode: resetCode.toString(),
    email: email,
    userId: userId,
    algorithm: 'Park-Miller-PRNG',
    expiresAt: Date.now() + (15 * 60 * 1000), // 15 minutes
    validUntil: new Date(Date.now() + 15 * 60 * 1000).toISOString()
  };
}`,

  vulnerableLine: `const seed = emailHash + parseInt(userId);`,

  options: [
    {
      code: `const crypto = require('crypto'); const tokenBytes = crypto.randomBytes(3); const resetCode = (parseInt(tokenBytes.toString('hex'), 16) % 900000) + 100000; return { resetCode: resetCode.toString(), email: email, userId: userId, algorithm: 'crypto.randomBytes', expiresAt: Date.now() + (15 * 60 * 1000), validUntil: new Date(Date.now() + 15 * 60 * 1000).toISOString() };`,
      correct: true,
      explanation: `Use crypto.randomBytes for secure randomness`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `let emailHash = 0; for (let i = 0; i < email.length; i++) { emailHash = ((emailHash << 5) - emailHash + email.charCodeAt(i)) & 0xFFFFFF; } const seed = emailHash + parseInt(userId); let randomState = seed; function parkMillerRandom() { randomState = (randomState * 16807) % 2147483647; return randomState / 2147483647; } const resetCode = Math.floor(parkMillerRandom() * 900000) + 100000; return { resetCode: resetCode.toString(), email, userId, algorithm: 'Park-Miller-PRNG', expiresAt: Date.now() + (15 * 60 * 1000), validUntil: new Date(Date.now() + 15 * 60 * 1000).toISOString() };`,
      correct: false,
      explanation: 'Predictable seeding with email hash + user ID. Since email and user ID are known or guessable, attackers can compute the same reset codes, compromising password reset security.'
    },
    {
      code: `const timeSeed = Date.now(); const resetCode = Math.floor((timeSeed % 900000)) + 100000; return { resetCode: resetCode.toString(), email, userId, algorithm: 'Timestamp-Direct', expiresAt: Date.now() + (15 * 60 * 1000), validUntil: new Date(Date.now() + 15 * 60 * 1000).toISOString() };`,
      correct: false,
      explanation: 'Direct timestamp usage. Using timestamp directly makes reset codes highly predictable within narrow time windows, enabling account takeover attacks.'
    },
    {
      code: `const resetCode = Math.floor(Math.random() * 900000) + 100000; return { resetCode: resetCode.toString(), email, userId, algorithm: 'Math.random', expiresAt: Date.now() + (15 * 60 * 1000), validUntil: new Date(Date.now() + 15 * 60 * 1000).toISOString() };`,
      correct: false,
      explanation: 'Statistical PRNG for security purposes. Math.random() produces predictable sequences unsuitable for password reset codes that protect account access.'
    },
    {
      code: `const sequentialBase = Date.now() % 100000; const resetCode = (sequentialBase + parseInt(userId)) % 900000 + 100000; return { resetCode: resetCode.toString(), email, userId, algorithm: 'Sequential', expiresAt: Date.now() + (15 * 60 * 1000), validUntil: new Date(Date.now() + 15 * 60 * 1000).toISOString() };`,
      correct: false,
      explanation: 'Sequential generation based on predictable inputs. Using timestamp and user ID creates predictable patterns that allow systematic code guessing.'
    },
    {
      code: `const emailLength = email.length; const userIdDigits = userId.toString().length; const resetCode = ((emailLength * 1000) + (userIdDigits * 100) + (Date.now() % 100)) % 900000 + 100000; return { resetCode: resetCode.toString(), email, userId, algorithm: 'Deterministic', expiresAt: Date.now() + (15 * 60 * 1000), validUntil: new Date(Date.now() + 15 * 60 * 1000).toISOString() };`,
      correct: false,
      explanation: 'Deterministic calculation from known values. Email length and user ID digits are observable or guessable, making reset codes predictable.'
    },
    {
      code: `const hash = require('crypto').createHash('md5').update(email + userId + Math.floor(Date.now() / 60000).toString()).digest('hex'); const resetCode = (parseInt(hash.substring(0, 6), 16) % 900000) + 100000; return { resetCode: resetCode.toString(), email, userId, algorithm: 'MD5-Minute', expiresAt: Date.now() + (15 * 60 * 1000), validUntil: new Date(Date.now() + 15 * 60 * 1000).toISOString() };`,
      correct: false,
      explanation: 'Hash of predictable inputs with time rounding. Using minute-level timestamps with known email/user ID makes codes guessable within minute windows.'
    },
    {
      code: `const primeSeeds = [2, 3, 5, 7, 11, 13, 17, 19]; const emailIndex = email.length % primeSeeds.length; const seed = primeSeeds[emailIndex] * parseInt(userId); let state = seed; for (let i = 0; i < 5; i++) { state = (state * 1103515245 + 12345) % Math.pow(2, 31); } const resetCode = (state % 900000) + 100000; return { resetCode: resetCode.toString(), email, userId, algorithm: 'Prime-LCG', expiresAt: Date.now() + (15 * 60 * 1000), validUntil: new Date(Date.now() + 15 * 60 * 1000).toISOString() };`,
      correct: false,
      explanation: 'Prime-based seeding with LCG. Using known primes with user ID creates predictable seeds, and LCGs are not cryptographically secure.'
    },
    {
      code: `const dayOfYear = Math.floor((Date.now() - new Date(new Date().getFullYear(), 0, 0)) / (1000 * 60 * 60 * 24)); const hourOfDay = new Date().getHours(); const resetCode = ((dayOfYear * 24 + hourOfDay + parseInt(userId)) % 900000) + 100000; return { resetCode: resetCode.toString(), email, userId, algorithm: 'Calendar-Based', expiresAt: Date.now() + (15 * 60 * 1000), validUntil: new Date(Date.now() + 15 * 60 * 1000).toISOString() };`,
      correct: false,
      explanation: 'Calendar-based generation. Day of year and hour are predictable time components that create systematic patterns allowing code prediction.'
    },
    {
      code: `const memUsage = process.memoryUsage().heapUsed || 12345678; const resetCode = ((memUsage + parseInt(userId) + Date.now()) % 900000) + 100000; return { resetCode: resetCode.toString(), email, userId, algorithm: 'Memory-Based', expiresAt: Date.now() + (15 * 60 * 1000), validUntil: new Date(Date.now() + 15 * 60 * 1000).toISOString() };`,
      correct: false,
      explanation: 'System state with predictable components. Memory usage may vary but combined with timestamp and user ID creates patterns that can be estimated or observed.'
    }
  ]
}