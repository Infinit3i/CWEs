import type { Exercise } from '@/data/exercises'

export const cwe617EmailValidation: Exercise = {
  cweId: 'CWE-617',
  name: 'Reachable Assertion - Email Parameter Validation',

  vulnerableFunction: `function processUserRegistration(req, res) {
  const email = req.body.email_address;
  const username = req.body.username;

  // Ensure email is provided
  assert(email != null, 'Email address is required');

  const user = createUserAccount(email, username);
  res.json({ success: true, userId: user.id });
}`,

  vulnerableLine: `assert(email != null, 'Email address is required');`,

  options: [
    {
      code: `if (!email) { return res.status(400).json({ error: 'Email address is required' }); }`,
      correct: true,
      explanation: `Correct! Using proper HTTP error response instead of assertions prevents application crashes. This returns a meaningful error to the client without terminating the server process.`
    },
    {
      code: `assert(email != null, 'Email address is required');`,
      correct: false,
      explanation: 'Direct from MITRE: Assertion triggered by missing email parameter causes AssertionError, crashing the application. External input should never reach assertions.'
    },
    {
      code: `assert(email && email.length > 0, 'Valid email required');`,
      correct: false,
      explanation: 'Still uses assertion with user input. From MITRE examples, any user-controllable condition in assertions creates denial of service vulnerabilities.'
    },
    {
      code: `if (email) assert(email.includes('@'), 'Invalid email format');`,
      correct: false,
      explanation: 'Conditional assertion still allows external input to control assertion execution. Users can trigger the assertion by providing email without @ symbol.'
    },
    {
      code: `console.assert(email, 'Email missing'); // Non-fatal assertion`,
      correct: false,
      explanation: 'While console.assert may not crash in some environments, relying on implementation-specific behavior is unreliable. Use explicit validation instead.'
    },
    {
      code: `try { assert(email != null); } catch (e) { throw new Error('Invalid email'); }`,
      correct: false,
      explanation: 'Catching assertion errors still allows the assertion to execute. The pattern of using assertions for input validation remains problematic and inefficient.'
    },
    {
      code: `const isValid = email != null; assert(isValid, 'Email required');`,
      correct: false,
      explanation: 'Moving the condition to a variable does not change that user input ultimately controls the assertion. The assertion can still be triggered by omitting email.'
    },
    {
      code: `assert(typeof email === 'string', 'Email must be string');`,
      correct: false,
      explanation: 'Type checking in assertions remains vulnerable. Users can trigger this by sending non-string email values (null, undefined, numbers), causing application crashes.'
    }
  ]
}