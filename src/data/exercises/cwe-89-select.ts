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
      explanation: `Use ? placeholders - database treats input as data, not code`
    },
    {
      code: `const query = "SELECT * FROM users WHERE id = '" + userId + "'";`,
      correct: false,
      explanation: 'Adding quotes doesn\'t prevent SQL injection'
    },
    {
      code: `const query = "SELECT * FROM users WHERE id = " + parseInt(userId);`,
      correct: false,
      explanation: 'parseInt helps but doesn\'t prevent all injection attacks'
    },
    {
      code: `const query = "SELECT * FROM users WHERE id = " + userId.replace(/'/g, '');`,
      correct: false,
      explanation: 'Removing characters is error-prone - use parameterized queries'
    },
    {
      code: `const query = "SELECT * FROM users WHERE id = " + escape(userId);`,
      correct: false,
      explanation: 'escape() is for URLs, not SQL queries'
    },
    {
      code: `const query = "SELECT * FROM users WHERE id = " + userId.toString();`,
      correct: false,
      explanation: 'toString() doesn\'t sanitize - still vulnerable'
    },
    {
      code: `const query = \`SELECT * FROM users WHERE id = \${userId}\`;`,
      correct: false,
      explanation: 'Template literals are still string concatenation - vulnerable'
    },
    {
      code: `const query = "SELECT * FROM users WHERE id = " + JSON.stringify(userId);`,
      correct: false,
      explanation: 'JSON.stringify doesn\'t prevent SQL injection'
    },
    {
      code: `const query = "SELECT * FROM users WHERE id = " + encodeURIComponent(userId);`,
      correct: false,
      explanation: 'URL encoding is for HTTP, not SQL protection'
    },
    {
      code: `const query = "SELECT * FROM users WHERE id = " + userId.slice(0, 10);`,
      correct: false,
      explanation: 'Limiting length doesn\'t prevent injection - short payloads work'
    }
  ]
}