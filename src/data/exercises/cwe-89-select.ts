import type { Exercise } from '@/data/exercises'

export const cwe89Select: Exercise = {
  cweId: 'CWE-89',
  name: 'SQL Injection - User Data Query',
  vulnerableFunction: `function getUserData(userId) {
  const query = "SELECT * FROM users WHERE id = " + userId;
  return database.query(query);
}`,
  vulnerableLine: `const query = "SELECT * FROM users WHERE id = " + userId;`,
  options: [
    {
      code: `const query = "SELECT * FROM users WHERE id = ?";`,
      correct: true,
      explanation: `Correct! Parameterized queries use placeholders (?) that tell the database to treat user input as pure data, never as executable SQL code. When you use string concatenation like "+ userId", the database parser sees the entire string as one SQL command and attempts to parse user input as potential SQL syntax. With parameterized queries, the database engine first compiles the SQL structure with placeholders, then separately binds the user data to those placeholders. This separation ensures that user input cannot alter the SQL command structure, even if it contains malicious SQL syntax like "1 OR 1=1" or "'; DROP TABLE users;--". The database treats the parameter as a literal value to search for, not as code to execute.`
    },
    {
      code: `const query = "SELECT * FROM users WHERE id = '" + userId + "'";`,
      correct: false,
      explanation: 'Still vulnerable! Adding quotes around the concatenation doesn\'t prevent SQL injection.'
    },
    {
      code: `const query = "SELECT * FROM users WHERE id = " + parseInt(userId);`,
      correct: false,
      explanation: 'Better but not secure enough. parseInt helps but doesn\'t prevent all injection attacks.'
    },
    {
      code: `const query = "SELECT * FROM users WHERE id = " + userId.replace(/['"]/g, '');`,
      correct: false,
      explanation: 'Wrong approach. Trying to sanitize by removing characters is error-prone and incomplete.'
    },
    {
      code: `const query = "SELECT * FROM users WHERE id = " + escape(userId);`,
      correct: false,
      explanation: 'JavaScript\'s escape() is for URL encoding, not SQL. This doesn\'t prevent SQL injection.'
    },
    {
      code: `const query = "SELECT * FROM users WHERE id = " + userId.toString();`,
      correct: false,
      explanation: 'toString() doesn\'t sanitize input. Still vulnerable to injection attacks.'
    },
    {
      code: `const query = \`SELECT * FROM users WHERE id = \${userId}\`;`,
      correct: false,
      explanation: 'Template literals are still string concatenation. This is equally vulnerable.'
    },
    {
      code: `const query = "SELECT * FROM users WHERE id = " + JSON.stringify(userId);`,
      correct: false,
      explanation: 'JSON.stringify adds quotes but doesn\'t prevent injection. Still vulnerable.'
    },
    {
      code: `const query = "SELECT * FROM users WHERE id = " + encodeURIComponent(userId);`,
      correct: false,
      explanation: 'URL encoding is for web requests, not SQL queries. This doesn\'t prevent SQL injection.'
    },
    {
      code: `const query = "SELECT * FROM users WHERE id = " + userId.slice(0, 10);`,
      correct: false,
      explanation: 'Limiting length doesn\'t prevent injection. Short malicious payloads can still work.'
    }
  ]
}