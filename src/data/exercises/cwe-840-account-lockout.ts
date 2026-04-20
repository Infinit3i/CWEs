import type { Exercise } from '@/data/exercises'

/**
 * CWE-840: Business Logic Errors - Account Lockout Bypass
 * Failed attempt tracking logic that can be circumvented
 */
export const cwe840AccountLockout: Exercise = {
  cweId: 'CWE-840',
  name: 'Business Logic Errors - Account Lockout Mechanism',

  vulnerableFunction: `function authenticateUser(username, password) {
  const user = getUserRecord(username);
  if (!user) return null;

  const isValidPassword = verifyPassword(password, user.hashedPassword);

  if (!isValidPassword) {
    user.failedAttempts = (user.failedAttempts || 0) + 1;
    updateUserRecord(user);

    if (user.failedAttempts >= 5) {
      user.locked = true;
      user.lockoutTime = Date.now();
      updateUserRecord(user);
    }
    return null;
  }

  return user;
}`,

  vulnerableLine: `if (!isValidPassword) {`,

  options: [
    {
      code: `if (!isValidPassword) { user.failedAttempts = (user.failedAttempts || 0) + 1; updateUserRecord(user); if (user.failedAttempts >= 5) { user.locked = true; user.lockoutTime = Date.now(); updateUserRecord(user); } return null; } user.failedAttempts = 0; updateUserRecord(user);`,
      correct: true,
      explanation: `Correct! This resets failed attempts on successful login, preventing attackers from accumulating failed attempts over time. The business logic properly tracks consecutive failures rather than total lifetime failures.`
    },
    {
      code: `if (!isValidPassword) { user.failedAttempts = (user.failedAttempts || 0) + 1; // No reset on success`,
      correct: false,
      explanation: 'Classic business logic error from MITRE patterns. Failed attempts accumulate indefinitely, so even legitimate users will eventually get locked out after enough password changes or forgotten passwords over time.'
    },
    {
      code: `if (!isValidPassword && user.failedAttempts < 10) { user.failedAttempts += 1;`,
      correct: false,
      explanation: 'Stops incrementing at 10 but never resets, creating permanent lockout vulnerability. Also doubles the lockout threshold, weakening the security mechanism intended business logic.'
    },
    {
      code: `if (!isValidPassword) { user.failedAttempts++; if (user.failedAttempts >= 5 && !user.isAdmin) {`,
      correct: false,
      explanation: 'Admin bypass creates inconsistent business rules and never resets counters. Admins become immune to brute force protections while regular users face permanent lockout accumulation.'
    },
    {
      code: `const today = new Date().toDateString(); if (!isValidPassword && user.lastFailDate !== today) { user.failedAttempts = 1; user.lastFailDate = today; }`,
      correct: false,
      explanation: 'Daily reset logic but insufficient for security. Attackers get fresh attempts every day, and successful logins within the same day don\'t reset the counter, violating proper lockout business logic.'
    },
    {
      code: `if (!isValidPassword) { user.failedAttempts = Math.min((user.failedAttempts || 0) + 1, 5);`,
      correct: false,
      explanation: 'Caps the counter at 5 but never decrements, creating a permanent lockout state once reached. The business logic becomes a one-way trap for legitimate users.'
    },
    {
      code: `if (!isValidPassword && Date.now() - user.lastFailTime > 300000) { user.failedAttempts = 1; } else if (!isValidPassword) { user.failedAttempts++; }`,
      correct: false,
      explanation: '5-minute reset window but no reset on success. Creates a sliding window vulnerability where attackers can spread attempts and legitimate users still face accumulation over time.'
    },
    {
      code: `if (!isValidPassword) { user.failedAttempts = (user.failedAttempts || 0) + 1; if (user.accountType === "premium") user.failedAttempts = Math.max(0, user.failedAttempts - 1);`,
      correct: false,
      explanation: 'Account type discrimination violates consistent security policy. Premium users get attempt forgiveness while still having no success-based reset, creating unfair and inconsistent business logic.'
    },
    {
      code: `if (!isValidPassword) { const increment = user.isFirstLogin ? 0.5 : 1; user.failedAttempts = (user.failedAttempts || 0) + increment;`,
      correct: false,
      explanation: 'First login grace logic is complex but misses the fundamental issue. Without success-based reset, all users eventually accumulate enough failures for permanent lockout regardless of login history.'
    },
    {
      code: `if (!isValidPassword) { user.failedAttempts = (user.failedAttempts || 0) + 1; if (user.failedAttempts % 10 === 0) user.failedAttempts = 0;`,
      correct: false,
      explanation: 'Arbitrary reset every 10 failures weakens security significantly. Attackers get unlimited attempts in groups of 10, completely undermining the lockout mechanism\'s business purpose.'
    }
  ]
}