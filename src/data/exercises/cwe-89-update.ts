import type { Exercise } from '@/data/exercises'

export const cwe89Update: Exercise = {
  cweId: 'CWE-89',
  name: 'SQL Injection - User Profile Update',
  vulnerableFunction: `function updateUserProfile(userId, name, email) {
  const nameQuery = "UPDATE users SET name = '" + name + "' WHERE id = " + userId;
  const emailQuery = "UPDATE users SET email = '" + email + "' WHERE id = " + userId;
  database.query(nameQuery);
  database.query(emailQuery);
  return { success: true };
}`,
  vulnerableLine: `const nameQuery = "UPDATE users SET name = '" + name + "' WHERE id = " + userId;
  const emailQuery = "UPDATE users SET email = '" + email + "' WHERE id = " + userId;`,
  options: [
    {
      code: `const nameQuery = "UPDATE users SET name = ? WHERE id = ?";
  const emailQuery = "UPDATE users SET email = ? WHERE id = ?";`,
      correct: true,
      explanation: `Use ? placeholders - database treats input as data, not code`
    },
    {
      code: `const nameQuery = "UPDATE users SET name = '" + name.replace(/'/g, "\\'") + "' WHERE id = " + userId;
  const emailQuery = "UPDATE users SET email = '" + email + "' WHERE id = " + userId;`,
      correct: false,
      explanation: 'Escaping quotes is incomplete - other injection techniques work'
    },
    {
      code: `const nameQuery = "UPDATE users SET name = '" + sanitize(name) + "' WHERE id = " + userId;
  const emailQuery = "UPDATE users SET email = '" + email + "' WHERE id = " + userId;`,
      correct: false,
      explanation: 'Custom sanitization is error-prone - use parameterized queries'
    },
    {
      code: `const nameQuery = "UPDATE users SET name = '" + name + "' WHERE id = '" + userId + "'";
  const emailQuery = "UPDATE users SET email = '" + email + "' WHERE id = '" + userId + "'";`,
      correct: false,
      explanation: 'Adding quotes doesn\'t prevent injection - still concatenating input'
    },
    {
      code: `const nameQuery = "UPDATE users SET name = " + JSON.stringify(name) + " WHERE id = " + userId;
  const emailQuery = "UPDATE users SET email = '" + email + "' WHERE id = " + userId;`,
      correct: false,
      explanation: 'JSON.stringify doesn\'t prevent all SQL injection forms'
    },
    {
      code: `const nameQuery = \`UPDATE users SET name = '\${name}' WHERE id = \${userId}\`;
  const emailQuery = \`UPDATE users SET email = '\${email}' WHERE id = \${userId}\`;`,
      correct: false,
      explanation: 'Template literals are still string concatenation - vulnerable'
    },
    {
      code: `const nameQuery = "UPDATE users SET name = '" + encodeURIComponent(name) + "' WHERE id = " + userId;
  const emailQuery = "UPDATE users SET email = '" + email + "' WHERE id = " + userId;`,
      correct: false,
      explanation: 'URL encoding is for HTTP, not SQL protection'
    },
    {
      code: `const nameQuery = "UPDATE users SET name = '" + name.substring(0, 100) + "' WHERE id = " + userId;
  const emailQuery = "UPDATE users SET email = '" + email + "' WHERE id = " + userId;`,
      correct: false,
      explanation: 'Truncating input doesn\'t prevent injection - short payloads work'
    },
    {
      code: `const nameQuery = "UPDATE users SET name = '" + name.toLowerCase() + "' WHERE id = " + userId;
  const emailQuery = "UPDATE users SET email = '" + email + "' WHERE id = " + userId;`,
      correct: false,
      explanation: 'toLowerCase() doesn\'t prevent SQL injection attacks'
    },
    {
      code: `const nameQuery = "UPDATE users SET name = '" + name.replace(/[<>]/g, '') + "' WHERE id = " + userId;
  const emailQuery = "UPDATE users SET email = '" + email + "' WHERE id = " + userId;`,
      correct: false,
      explanation: 'Removing HTML chars doesn\'t prevent SQL injection'
    }
  ]
}