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
      explanation: `Correct! This solution demonstrates parameterized queries for multiple UPDATE statements, each using two placeholders (?). The critical difference is that instead of concatenating user input like "+ name +" and "+ userId" directly into the SQL string, each query uses placeholders that separate the SQL command structure from the data values. When executed, you would pass the parameters separately: database.query(nameQuery, [name, userId]) and database.query(emailQuery, [email, userId]). The database engine processes this by first parsing the SQL structure, then binding the parameter values in a type-safe manner. This prevents injection because malicious input like "John'; DROP TABLE users; --" in the name field gets treated as a literal string value to store in the name column, not as additional SQL commands to execute. The two-step process (parse structure, then bind data) is what makes parameterized queries secure.`
    },
    {
      code: `const nameQuery = "UPDATE users SET name = '" + name.replace(/'/g, "\\'") + "' WHERE id = " + userId;
  const emailQuery = "UPDATE users SET email = '" + email.replace(/'/g, "\\'") + "' WHERE id = " + userId;`,
      correct: false,
      explanation: 'Escaping quotes is insufficient. Many other SQL injection techniques still work.'
    },
    {
      code: `const nameQuery = "UPDATE users SET name = '" + sanitize(name) + "' WHERE id = " + userId;
  const emailQuery = "UPDATE users SET email = '" + sanitize(email) + "' WHERE id = " + userId;`,
      correct: false,
      explanation: 'Custom sanitization functions are error-prone and often incomplete.'
    },
    {
      code: `const nameQuery = "UPDATE users SET name = '" + name + "' WHERE id = '" + userId + "'";
  const emailQuery = "UPDATE users SET email = '" + email + "' WHERE id = '" + userId + "'";`,
      correct: false,
      explanation: 'Adding quotes around numeric IDs doesn\'t prevent injection - still concatenating user input.'
    },
    {
      code: `const nameQuery = "UPDATE users SET name = " + JSON.stringify(name) + " WHERE id = " + userId;
  const emailQuery = "UPDATE users SET email = " + JSON.stringify(email) + " WHERE id = " + userId;`,
      correct: false,
      explanation: 'JSON.stringify adds quotes but doesn\'t prevent all forms of SQL injection.'
    },
    {
      code: `const nameQuery = \`UPDATE users SET name = '\${name}' WHERE id = \${userId}\`;
  const emailQuery = \`UPDATE users SET email = '\${email}' WHERE id = \${userId}\`;`,
      correct: false,
      explanation: 'Template literals are still string concatenation - equally vulnerable to injection.'
    },
    {
      code: `const nameQuery = "UPDATE users SET name = '" + encodeURIComponent(name) + "' WHERE id = " + userId;
  const emailQuery = "UPDATE users SET email = '" + encodeURIComponent(email) + "' WHERE id = " + userId;`,
      correct: false,
      explanation: 'URL encoding is for HTTP, not SQL databases. This doesn\'t prevent SQL injection.'
    },
    {
      code: `const nameQuery = "UPDATE users SET name = '" + name.substring(0, 100) + "' WHERE id = " + userId;
  const emailQuery = "UPDATE users SET email = '" + email.substring(0, 100) + "' WHERE id = " + userId;`,
      correct: false,
      explanation: 'Truncating input doesn\'t prevent injection - malicious payloads can be very short.'
    },
    {
      code: `const nameQuery = "UPDATE users SET name = '" + name.toLowerCase() + "' WHERE id = " + userId;
  const emailQuery = "UPDATE users SET email = '" + email.toLowerCase() + "' WHERE id = " + userId;`,
      correct: false,
      explanation: 'toLowerCase() only changes case - it doesn\'t prevent any SQL injection attacks.'
    },
    {
      code: `const nameQuery = "UPDATE users SET name = '" + name.replace(/[<>]/g, '') + "' WHERE id = " + userId;
  const emailQuery = "UPDATE users SET email = '" + email.replace(/[<>]/g, '') + "' WHERE id = " + userId;`,
      correct: false,
      explanation: 'Removing HTML characters doesn\'t prevent SQL injection - wrong type of filtering.'
    }
  ]
}