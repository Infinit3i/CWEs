import type { Exercise } from '@/data/exercises'

export const cwe617PasswordLength: Exercise = {
  cweId: 'CWE-617',
  name: 'Reachable Assertion - Password Strength Validation',

  vulnerableFunction: `function validatePasswordStrength(password) {
  // Assert minimum password requirements
  assert(password.length >= 8, 'Password must be at least 8 characters');
  assert(/[A-Z]/.test(password), 'Password must contain uppercase letter');
  assert(/[0-9]/.test(password), 'Password must contain number');

  return {
    valid: true,
    strength: calculatePasswordStrength(password)
  };
}`,

  vulnerableLine: `assert(password.length >= 8, 'Password must be at least 8 characters');`,

  options: [
    {
      code: `const errors = []; if (password.length < 8) errors.push('Password must be at least 8 characters'); if (!/[A-Z]/.test(password)) errors.push('Password must contain uppercase letter'); if (errors.length > 0) throw new ValidationError(errors);`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `assert(password.length >= 8, 'Password must be at least 8 characters');`,
      correct: false,
      explanation: 'Short passwords provided by users trigger this assertion, causing application crashes. Password validation should use proper error handling, not assertions.'
    },
    {
      code: `assert(password && password.length >= 8, 'Valid password required');`,
      correct: false,
      explanation: 'Adding null checks to assertions does not solve the core issue. Users can still provide short passwords to trigger the length assertion and crash the application.'
    },
    {
      code: `if (password) { assert(password.length >= 8); assert(/[A-Z]/.test(password)); }`,
      correct: false,
      explanation: 'Conditional assertions still allow user input to control assertion execution. Valid but weak passwords will trigger the strength assertions.'
    },
    {
      code: `assert(typeof password === 'string' && password.length >= 8);`,
      correct: false,
      explanation: 'Combining type and length checks in assertions creates multiple ways for user input to cause crashes. Both type violations and short passwords trigger failures.'
    },
    {
      code: `try { assert(password.length >= 8); } catch (AssertionError) { return { valid: false }; }`,
      correct: false,
      explanation: 'Catching assertion errors after they execute is inefficient and maintains the anti-pattern of using assertions for input validation instead of proper checks.'
    },
    {
      code: `const meetsLength = password.length >= 8; const hasUpper = /[A-Z]/.test(password); assert(meetsLength && hasUpper);`,
      correct: false,
      explanation: 'Separating validation logic into variables does not prevent user input from ultimately controlling the assertion. The assertion remains reachable through weak passwords.'
    },
    {
      code: `console.assert(password.length >= 8, 'Password too short'); // Non-fatal`,
      correct: false,
      explanation: 'console.assert behavior varies by environment and should not be relied upon for input validation. Use explicit validation with proper error responses.'
    }
  ]
}