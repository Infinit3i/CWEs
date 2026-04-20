import type { Exercise } from '@/data/exercises'

/**
 * CWE-190 exercise: Timestamp calculation overflow
 * Based on time-based vulnerabilities in date/time processing
 */
export const cwe190TimestampCalculation: Exercise = {
  cweId: 'CWE-190',
  name: 'Integer Overflow - Session Timeout Calculation',

  vulnerableFunction: `function calculateSessionTimeout(baseTimeout, extensionMinutes, userActivity) {
  // Base timeout in milliseconds
  let timeoutMs = baseTimeout * 1000;

  // Add extensions for user activity
  for (const activity of userActivity) {
    const extensionMs = extensionMinutes * 60 * 1000;
    timeoutMs += extensionMs;

    // Bonus time for premium users
    if (activity.isPremium) {
      timeoutMs += extensionMs * 2;
    }
  }

  // Calculate absolute expiration time
  const currentTime = Date.now();
  const expirationTime = currentTime + timeoutMs;

  return {
    timeoutDuration: timeoutMs,
    expiresAt: new Date(expirationTime),
    isValid: expirationTime > currentTime
  };
}`,

  vulnerableLine: `const expirationTime = currentTime + timeoutMs;`,

  options: [
    {
      code: `function calculateSessionTimeout(baseTimeout, extensionMinutes, userActivity) {
  let timeoutMs = baseTimeout * 1000;
  const MAX_TIMEOUT = Number.MAX_SAFE_INTEGER / 2;

  for (const activity of userActivity) {
    const extensionMs = extensionMinutes * 60 * 1000;
    if (timeoutMs > MAX_TIMEOUT - extensionMs) {
      throw new Error('Session timeout would overflow');
    }
    timeoutMs += extensionMs;
  }

  const currentTime = Date.now();
  if (currentTime > Number.MAX_SAFE_INTEGER - timeoutMs) {
    throw new Error('Expiration time would overflow');
  }

  return { expiresAt: new Date(currentTime + timeoutMs) };
}`,
      correct: true,
      explanation: `Correct! Checking for overflow before each addition prevents timestamp wraparound. This ensures session expiration times remain valid and don't wrap to past dates due to integer overflow.`
    },
    // Timestamp calculation overflow vulnerabilities
    {
      code: `const expirationTime = currentTime + timeoutMs;
return { expiresAt: new Date(expirationTime) };`,
      correct: false,
      explanation: 'Timestamp addition without overflow checking. Large timeout values can cause expirationTime to wrap around, creating sessions that appear to expire in the past or far future.'
    },
    {
      code: `let totalTimeout = 0;
for (const extension of extensions) {
    totalTimeout += extension * 1000 * 60; // Convert minutes to ms
}`,
      correct: false,
      explanation: 'MITRE-style accumulation with multiplication. Each extension calculation can overflow, and the accumulation can wrap to negative values, creating invalid timeout durations.'
    },
    {
      code: `const futureTime = Date.now() + (days * 24 * 60 * 60 * 1000);
return new Date(futureTime);`,
      correct: false,
      explanation: 'Chained multiplication for time calculations creates overflow risk. Large day values can cause the millisecond calculation to overflow before addition.'
    },
    {
      code: `if (expirationTime > Date.now()) {
    return { valid: true, expiresAt: new Date(expirationTime) };
}`,
      correct: false,
      explanation: 'Checking validity after overflow has occurred. Overflowed expiration times can wrap to past dates, incorrectly failing this validation.'
    },
    {
      code: `const safeExpiration = Math.min(currentTime + timeoutMs, 8640000000000000);
return new Date(safeExpiration);`,
      correct: false,
      explanation: 'Clamping to Date maximum after addition is too late. The overflow may have already occurred in the addition operation.'
    },
    {
      code: `try {
    const expiration = currentTime + timeoutMs;
    return new Date(expiration);
} catch (e) {
    return new Date(currentTime + 3600000); // Default 1 hour
}`,
      correct: false,
      explanation: 'JavaScript integer overflow does not throw exceptions. Date constructor may create invalid dates but will not trigger catch blocks.'
    },
    {
      code: `const timeoutSeconds = Math.floor(timeoutMs / 1000);
const expirationTime = currentTime + (timeoutSeconds * 1000);`,
      correct: false,
      explanation: 'Converting units does not prevent overflow. The multiplication timeoutSeconds * 1000 can still overflow, and the addition remains vulnerable.'
    },
    {
      code: `if (timeoutMs.toString().length < 12) {
    const expirationTime = currentTime + timeoutMs;
    return new Date(expirationTime);
}`,
      correct: false,
      explanation: 'String length checking cannot detect overflow in addition. The currentTime + timeoutMs calculation can still overflow even with validated input.'
    },
    {
      code: `const timeoutHours = timeoutMs / (1000 * 60 * 60);
if (timeoutHours < 100) {
    return new Date(currentTime + timeoutMs);
}`,
      correct: false,
      explanation: 'Hour-based validation does not account for currentTime magnitude. Even small timeouts can cause overflow when added to large current timestamp values.'
    }
  ]
}