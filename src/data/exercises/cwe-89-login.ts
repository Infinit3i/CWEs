import type { Exercise } from '@/data/exercises'

export const cwe89Login: Exercise = {
  cweId: 'CWE-89',
  name: 'SQL Injection - Login Authentication',
  language: 'JavaScript',
  vulnerableFunction: `function login(user, pass) {
  const query = "SELECT * FROM users WHERE name = '" + user + "'";
  return database.query(query);
}`,
  vulnerableLine: `const query = "SELECT * FROM users WHERE name = '" + user + "'";`,
  options: [
    {
      code: `const query = "SELECT * FROM users WHERE name = ?";`,
      correct: true,
      explanation: `Parameterized queries treat input as data, not code`
    },
    {
      code: `const escaped = user.replace(/'/g, "''");
const query = "SELECT * FROM users WHERE name = '" + escaped + "'";`,
      correct: false,
      explanation: 'Quote escaping is incomplete - UNION attacks still work'
    },
    {
      code: `const query = "SELECT * FROM users WHERE name = '" + user.toLowerCase() + "'";`,
      correct: false,
      explanation: 'toLowerCase() doesn\'t prevent SQL injection'
    },
    {
      code: `const short = user.substring(0, 20);
const query = "SELECT * FROM users WHERE name = '" + short + "'";`,
      correct: false,
      explanation: 'Length limits don\'t prevent injection - short payloads work'
    },
    {
      code: `const trimmed = user.trim();
const query = "SELECT * FROM users WHERE name = '" + trimmed + "'";`,
      correct: false,
      explanation: 'trim() only removes whitespace - still injectable'
    },
    {
      code: `const encoded = encodeURIComponent(user);
const query = "SELECT * FROM users WHERE name = '" + encoded + "'";`,
      correct: false,
      explanation: 'URL encoding is for HTTP, not SQL'
    },
    {
      code: `const filtered = user.replace(/[^a-zA-Z0-9]/g, '');
const query = "SELECT * FROM users WHERE name = '" + filtered + "'";`,
      correct: false,
      explanation: 'Character filtering is error-prone and incomplete'
    },
    {
      code: `const upper = user.toUpperCase();
const query = "SELECT * FROM users WHERE UPPER(name) = '" + upper + "'";`,
      correct: false,
      explanation: 'UPPER() doesn\'t prevent injection - still concatenating'
    },
    {
      code: `const query = "SELECT * FROM users WHERE name LIKE '" + user + "%'";`,
      correct: false,
      explanation: 'LIKE makes injection easier, not safer'
    },
    {
      code: `if (user.includes('\'')) throw new Error('Invalid');
const query = "SELECT * FROM users WHERE name = '" + user + "'";`,
      correct: false,
      explanation: 'Quote detection misses many injection techniques'
    }
  ]
}