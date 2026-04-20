import type { Exercise } from '@/data/exercises'

export const cwe89Login: Exercise = {
  cweId: 'CWE-89',
  name: 'SQL Injection - Login Authentication',
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
      explanation: `Correct! This approach uses two parameter placeholders (?) which fundamentally changes how the database processes the query. Instead of concatenating strings like "+ username + " and "+ password +" directly into the SQL command, parameterized queries separate the SQL logic from the data. The database engine first parses and compiles the SQL structure "SELECT id FROM users WHERE username = ? AND password = ?" as a prepared statement. Then it binds the actual username and password values to the placeholders using a completely separate mechanism. This prevents injection because even if a user enters malicious input like "admin' OR '1'='1", the database treats this entire string as a literal username to search for, not as SQL code containing an OR condition. The parameter binding process automatically handles escaping and ensures data type safety.`
    },
    {
      code: `const query = "SELECT id FROM users WHERE username = '" + username.replace(/'/g, "''") + "' AND password = '" + password.replace(/'/g, "''") + "'";`,
      correct: false,
      explanation: 'Wrong approach! Escaping quotes is incomplete - many other injection techniques still work.'
    },
    {
      code: `const query = "SELECT id FROM users WHERE username = '" + username + "' AND password = MD5('" + password + "')";`,
      correct: false,
      explanation: 'Still vulnerable! Adding MD5 doesn\'t prevent injection in the username parameter.'
    },
    {
      code: `const query = "SELECT id FROM users WHERE username = '" + username.toLowerCase() + "' AND password = '" + password.toLowerCase() + "'";`,
      correct: false,
      explanation: 'toLowerCase() doesn\'t prevent SQL injection - still vulnerable to all injection attacks.'
    },
    {
      code: `const query = "SELECT id FROM users WHERE username = '" + username.substring(0, 50) + "' AND password = '" + password.substring(0, 50) + "'";`,
      correct: false,
      explanation: 'Truncating input doesn\'t prevent injection. Short malicious payloads can still work.'
    },
    {
      code: `const query = "SELECT id FROM users WHERE username = '" + username.trim() + "' AND password = '" + password.trim() + "'";`,
      correct: false,
      explanation: 'trim() only removes whitespace. This is still completely vulnerable to SQL injection.'
    },
    {
      code: `const query = "SELECT id FROM users WHERE username = '" + encodeURIComponent(username) + "' AND password = '" + encodeURIComponent(password) + "'";`,
      correct: false,
      explanation: 'URL encoding is for HTTP, not SQL. This doesn\'t prevent SQL injection attacks.'
    },
    {
      code: `const query = "SELECT id FROM users WHERE username = '" + username.replace(/[^a-zA-Z0-9]/g, '') + "' AND password = '" + password.replace(/[^a-zA-Z0-9]/g, '') + "'";`,
      correct: false,
      explanation: 'Better but still wrong approach. Input sanitization is error-prone compared to parameterized queries.'
    },
    {
      code: `const query = "SELECT id FROM users WHERE UPPER(username) = '" + username.toUpperCase() + "' AND UPPER(password) = '" + password.toUpperCase() + "'";`,
      correct: false,
      explanation: 'Adding UPPER() functions doesn\'t prevent injection - still concatenating user input directly.'
    },
    {
      code: `const query = "SELECT id FROM users WHERE username LIKE '" + username + "%' AND password = '" + password + "'";`,
      correct: false,
      explanation: 'Using LIKE instead of = doesn\'t prevent injection and makes it even easier to exploit.'
    }
  ]
}