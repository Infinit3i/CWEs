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
      explanation: `Reset failed attempts after successful login`
    },
    {
      code: `if (!isValidPassword) { user.failedAttempts = (user.failedAttempts || 0) + 1; // No reset on success`,
      correct: false,
      explanation: 'Failed attempts accumulate forever locking legitimate users'
    },
    {
      code: `if (!isValidPassword && user.failedAttempts < 10) { user.failedAttempts += 1;`,
      correct: false,
      explanation: 'Caps at 10 attempts but creates permanent lockout'
    },
    {
      code: `if (!isValidPassword) { user.failedAttempts++; if (user.failedAttempts >= 5 && !user.isAdmin) {`,
      correct: false,
      explanation: 'Admin bypass with permanent lockout for others'
    },
    {
      code: `const today = new Date().toDateString(); if (!isValidPassword && user.lastFailDate !== today) { user.failedAttempts = 1; user.lastFailDate = today; }`,
      correct: false,
      explanation: 'Daily reset gives attackers fresh attempts'
    },
    {
      code: `if (!isValidPassword) { user.failedAttempts = Math.min((user.failedAttempts || 0) + 1, 5);`,
      correct: false,
      explanation: 'Counter caps at 5 creating permanent lockout'
    },
    {
      code: `if (!isValidPassword && Date.now() - user.lastFailTime > 300000) { user.failedAttempts = 1; } else if (!isValidPassword) { user.failedAttempts++; }`,
      correct: false,
      explanation: 'Time window reset but attacks can spread attempts'
    },
    {
      code: `if (!isValidPassword) { user.failedAttempts = (user.failedAttempts || 0) + 1; if (user.accountType === "premium") user.failedAttempts = Math.max(0, user.failedAttempts - 1);`,
      correct: false,
      explanation: 'Premium users get attempt forgiveness'
    },
    {
      code: `if (!isValidPassword) { const increment = user.isFirstLogin ? 0.5 : 1; user.failedAttempts = (user.failedAttempts || 0) + increment;`,
      correct: false,
      explanation: 'First login grace but permanent accumulation remains'
    },
    {
      code: `if (!isValidPassword) { user.failedAttempts = (user.failedAttempts || 0) + 1; if (user.failedAttempts % 10 === 0) user.failedAttempts = 0;`,
      correct: false,
      explanation: 'Resets every 10 failures giving unlimited attempts'
    }
  ]
}