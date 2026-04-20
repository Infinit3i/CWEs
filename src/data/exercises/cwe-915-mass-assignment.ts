import type { Exercise } from '@/data/exercises'

/**
 * CWE-915 Exercise 2: Mass Assignment in User Profile Update
 * Based on Rails mass assignment vulnerabilities from MITRE examples
 */
export const cwe915MassAssignment: Exercise = {
  cweId: 'CWE-915',
  name: 'Mass Assignment - User Profile Update',

  vulnerableFunction: `function updateUserProfile(userId, updateData) {
  const user = users[userId];
  if (!user) throw new Error('User not found');

  // Update all provided fields
  for (const [key, value] of Object.entries(updateData)) {
    user[key] = value;
  }

  return user;
}`,

  vulnerableLine: `user[key] = value;`,

  options: [
    {
      code: `const ALLOWED_FIELDS = ['name', 'email', 'bio', 'avatar'];
if (ALLOWED_FIELDS.includes(key)) user[key] = value;`,
      correct: true,
      explanation: `Correct! Allowlisting specific updatable fields prevents mass assignment attacks. This blocks attempts to modify sensitive fields like 'isAdmin', 'role', or 'accountBalance' that should not be user-controllable.`
    },
    {
      code: `user[key] = value;`,
      correct: false,
      explanation: 'Direct from MITRE: Mass assignment allows modification of unintended object attributes. Attackers can include {"isAdmin": true} to escalate privileges.'
    },
    {
      code: `if (key !== 'isAdmin') user[key] = value;`,
      correct: false,
      explanation: 'Blacklisting single fields is insufficient. Many sensitive fields exist (role, permissions, accountBalance, etc.) that could be exploited.'
    },
    {
      code: `if (!key.startsWith('_')) user[key] = value;`,
      correct: false,
      explanation: 'Convention-based filtering is unreliable. Sensitive fields may not follow underscore conventions and could still be modified.'
    },
    {
      code: `if (typeof value === 'string') user[key] = value;`,
      correct: false,
      explanation: 'Type checking does not prevent mass assignment. String-type sensitive fields like "role" or "status" can still be modified.'
    },
    {
      code: `if (key in user) user[key] = value;`,
      correct: false,
      explanation: 'Checking property existence does not restrict modification. Existing sensitive properties like isAdmin are still vulnerable.'
    },
    {
      code: `Object.assign(user, updateData);`,
      correct: false,
      explanation: 'Object.assign performs mass assignment of all properties, making the vulnerability even more direct and dangerous.'
    },
    {
      code: `for (const key in updateData) user[key] = updateData[key];`,
      correct: false,
      explanation: 'Using for...in loop is equivalent to the vulnerable pattern - all provided properties are assigned without validation.'
    },
    {
      code: `if (Object.keys(updateData).length < 10) Object.assign(user, updateData);`,
      correct: false,
      explanation: 'Limiting update size does not prevent mass assignment. A single {"isAdmin": true} field is enough for privilege escalation.'
    },
    {
      code: `const filtered = Object.fromEntries(Object.entries(updateData).filter(([k,v]) => v));
Object.assign(user, filtered);`,
      correct: false,
      explanation: 'Filtering truthy values does not prevent mass assignment. Dangerous values like {"isAdmin": true} are truthy and pass through.'
    }
  ]
}