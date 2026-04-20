import type { Exercise } from '@/data/exercises'

export const cwe89Login: Exercise = {
  cweId: 'CWE-89',
  name: 'SQL Injection - Login Authentication',
  language: 'JavaScript',
  vulnerableFunction: `function authenticateUser(username, password) {
  const query = "SELECT id FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
  const result = database.query(query);
  return result.length > 0;
}`,
  vulnerableLine: `const query = "SELECT id FROM users WHERE username = '" + username + "' AND password = '" + password + "'";`,
  options: [
    {
      code: `const query = "SELECT id FROM users WHERE username = ? AND password = ?";`,
      correct: true,
      explanation: `Use ? placeholders - database treats input as data, not code`
    },
    {
      code: `const query = "SELECT id FROM users WHERE username = '" + username.replace(/'/g, "''") + "' AND password = '" + password + "'";`,
      correct: false,
      explanation: 'Escaping quotes is incomplete - other injection techniques work'
    },
    {
      code: `const query = "SELECT id FROM users WHERE username = '" + username + "' AND password = MD5('" + password + "')";`,
      correct: false,
      explanation: 'MD5 only affects password - username still injectable'
    },
    {
      code: `const query = "SELECT id FROM users WHERE username = '" + username.toLowerCase() + "' AND password = '" + password + "'";`,
      correct: false,
      explanation: 'toLowerCase() doesn\'t prevent SQL injection attacks'
    },
    {
      code: `const query = "SELECT id FROM users WHERE username = '" + username.substring(0, 50) + "' AND password = '" + password + "'";`,
      correct: false,
      explanation: 'Truncating input doesn\'t prevent injection - short payloads work'
    },
    {
      code: `const query = "SELECT id FROM users WHERE username = '" + username.trim() + "' AND password = '" + password + "'";`,
      correct: false,
      explanation: 'trim() only removes whitespace - still vulnerable'
    },
    {
      code: `const query = "SELECT id FROM users WHERE username = '" + encodeURIComponent(username) + "' AND password = '" + password + "'";`,
      correct: false,
      explanation: 'URL encoding is for HTTP, not SQL protection'
    },
    {
      code: `const query = "SELECT id FROM users WHERE username = '" + username.replace(/[^a-zA-Z0-9]/g, '') + "' AND password = '" + password + "'";`,
      correct: false,
      explanation: 'Input filtering is error-prone - use parameterized queries'
    },
    {
      code: `const query = "SELECT id FROM users WHERE UPPER(username) = '" + username.toUpperCase() + "' AND password = '" + password + "'";`,
      correct: false,
      explanation: 'UPPER() doesn\'t prevent injection - still concatenating input'
    },
    {
      code: `const query = "SELECT id FROM users WHERE username LIKE '" + username + "%' AND password = '" + password + "'";`,
      correct: false,
      explanation: 'LIKE doesn\'t prevent injection - makes it easier'
    }
  ]
}