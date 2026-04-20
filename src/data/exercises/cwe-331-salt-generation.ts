import type { Exercise } from '@/data/exercises'

/**
 * CWE-331: Insufficient Entropy - Cryptographic Salt Generation
 * Based on MITRE patterns showing inadequate salt randomness
 */
export const cwe331SaltGeneration: Exercise = {
  cweId: 'CWE-331',
  name: 'Insufficient Entropy - Password Salt Generation',
  language: 'JavaScript',

  vulnerableFunction: `function generatePasswordSalt(username, registrationTime) {
  // Use username as primary entropy source
  let usernameHash = 0;
  for (let i = 0; i < username.length; i++) {
    usernameHash = ((usernameHash << 5) - usernameHash + username.charCodeAt(i)) & 0xFFFFFF;
  }

  // Add registration time (to the hour) for "uniqueness"
  const hoursSinceEpoch = Math.floor(registrationTime / (1000 * 60 * 60));

  // Combine limited entropy sources
  const saltValue = usernameHash + hoursSinceEpoch;

  // Convert to hex salt
  const salt = saltValue.toString(16).padStart(16, '0');

  return {
    salt: salt,
    username: username,
    algorithm: 'Username-Time-Hash',
    entropy: {
      usernameHash: usernameHash,
      hoursSinceEpoch: hoursSinceEpoch,
      combined: saltValue
    },
    entropyBits: Math.log2(0xFFFFFF * hoursSinceEpoch)
  };
}`,

  vulnerableLine: `const saltValue = usernameHash + hoursSinceEpoch;`,

  options: [
    {
      code: `const crypto = require('crypto'); const salt = crypto.randomBytes(32).toString('hex'); return { salt: salt, username: username, algorithm: 'crypto.randomBytes', entropy: { source: 'Cryptographic random number generator' }, entropyBits: 256 };`,
      correct: true,
      explanation: `Use crypto.randomBytes for secure randomness`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `let usernameHash = 0; for (let i = 0; i < username.length; i++) { usernameHash = ((usernameHash << 5) - usernameHash + username.charCodeAt(i)) & 0xFFFFFF; } const hoursSinceEpoch = Math.floor(registrationTime / (1000 * 60 * 60)); const saltValue = usernameHash + hoursSinceEpoch; const salt = saltValue.toString(16).padStart(16, '0'); return { salt, username, algorithm: 'Username-Time-Hash', entropy: { usernameHash, hoursSinceEpoch, combined: saltValue }, entropyBits: Math.log2(0xFFFFFF * hoursSinceEpoch) };`,
      correct: false,
      explanation: 'Username hash plus time. Using username as primary entropy means identical usernames get similar salts, and hourly time granularity provides minimal additional entropy.'
    },
    {
      code: `const timestamp = Math.floor(registrationTime / 1000); const salt = timestamp.toString(16).padStart(16, '0'); return { salt, username, algorithm: 'Timestamp-Direct', entropy: { timestamp }, entropyBits: Math.log2(timestamp) };`,
      correct: false,
      explanation: 'Direct timestamp usage. Timestamps provide minimal entropy and create predictable patterns - users registering around the same time get similar salts.'
    },
    {
      code: `const userLength = username.length; const firstChar = username.charCodeAt(0) || 65; const salt = (userLength * firstChar).toString(16).padStart(16, '0'); return { salt, username, algorithm: 'Length-Character', entropy: { userLength, firstChar, product: userLength * firstChar }, entropyBits: Math.log2(userLength * firstChar) };`,
      correct: false,
      explanation: 'String length and character entropy. Username length and first character provide very limited entropy (typically < 10 bits), making salts highly predictable.'
    },
    {
      code: `const dayOfYear = Math.floor((registrationTime - new Date(new Date(registrationTime).getFullYear(), 0, 0)) / 86400000); const salt = dayOfYear.toString(16).padStart(16, '0'); return { salt, username, algorithm: 'Day-Of-Year', entropy: { dayOfYear }, entropyBits: Math.log2(365) };`,
      correct: false,
      explanation: 'Calendar-based entropy. Day of year provides only ~9 bits of entropy and creates patterns where all users registering on the same day get identical salts.'
    },
    {
      code: `let charSum = 0; for (let i = 0; i < username.length; i++) { charSum += username.charCodeAt(i); } const salt = charSum.toString(16).padStart(16, '0'); return { salt, username, algorithm: 'Character-Sum', entropy: { charSum }, entropyBits: Math.log2(charSum || 1) };`,
      correct: false,
      explanation: 'Character code sum. Summing character codes provides very limited entropy and many different usernames can produce the same sum, leading to salt collisions.'
    },
    {
      code: `const usernameReversed = username.split('').reverse().join(''); const hash = usernameReversed.split('').reduce((a, b) => ((a << 5) - a + b.charCodeAt(0)) & 0xFFFF, 0); const salt = hash.toString(16).padStart(16, '0'); return { salt, username, algorithm: 'Reversed-Hash', entropy: { usernameReversed, hash }, entropyBits: 16 };`,
      correct: false,
      explanation: 'Deterministic transformation. Reversing the username and hashing provides no additional entropy beyond the username itself, and limits output to 16 bits.'
    },
    {
      code: `const consonants = username.replace(/[aeiouAEIOU]/g, '').length; const vowels = username.length - consonants; const salt = (consonants * 1000 + vowels).toString(16).padStart(16, '0'); return { salt, username, algorithm: 'Vowel-Consonant', entropy: { consonants, vowels, combined: consonants * 1000 + vowels }, entropyBits: Math.log2(consonants * 1000 + vowels) };`,
      correct: false,
      explanation: 'Linguistic pattern entropy. Vowel and consonant counts provide very limited entropy and many usernames will have similar character distributions.'
    },
    {
      code: `const processInfo = { pid: process.pid || 1234, ppid: process.ppid || 1 }; const salt = (processInfo.pid + processInfo.ppid).toString(16).padStart(16, '0'); return { salt, username, algorithm: 'Process-IDs', entropy: { pid: processInfo.pid, ppid: processInfo.ppid }, entropyBits: Math.log2(processInfo.pid + processInfo.ppid) };`,
      correct: false,
      explanation: 'Process ID entropy. Process IDs provide limited entropy and can be observed or predicted, especially in containerized environments where PIDs are often sequential.'
    },
    {
      code: `const memoryUsage = process.memoryUsage().heapUsed % 65536; const salt = memoryUsage.toString(16).padStart(16, '0'); return { salt, username, algorithm: 'Memory-Usage', entropy: { memoryUsage }, entropyBits: 16 };`,
      correct: false,
      explanation: 'System memory entropy. Memory usage provides limited entropy (16 bits with modulo) and can be influenced by attackers or observed through system monitoring.'
    }
  ]
}