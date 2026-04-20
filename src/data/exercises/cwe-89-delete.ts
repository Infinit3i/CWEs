import type { Exercise } from '@/data/exercises'

export const cwe89Delete: Exercise = {
  cweId: 'CWE-89',
  name: 'SQL Injection - Data Deletion',
  vulnerableFunction: `function deleteUserPosts(userId, category) {
  const query = "DELETE FROM posts WHERE user_id = " + userId + " AND category = '" + category + "'";
  const result = database.query(query);
  return { deleted: result.affectedRows };
}`,
  vulnerableLine: `const query = "DELETE FROM posts WHERE user_id = " + userId + " AND category = '" + category + "'";`,
  options: [
    {
      code: `const query = "DELETE FROM posts WHERE user_id = ? AND category = ?";`,
      correct: true,
      explanation: `Correct! This parameterized query uses two placeholders (?) to handle both a numeric parameter (userId) and a string parameter (category) safely. The key insight is that when you concatenate with "+ userId +" and "+ category +", the database receives one large string and must parse the entire thing as SQL, making it vulnerable to injection in either parameter. With parameterized queries, the database first compiles the DELETE command structure with placeholders, then separately binds the actual values using database.query(query, [userId, category]). The database engine knows the first ? expects an integer for user_id and the second ? expects a string for category. Even if the category contains malicious SQL like "' OR 1=1; DROP TABLE posts; --", the database treats this entire string as a literal category value to match against, not as executable SQL code. This parameter binding happens at a lower level than SQL parsing, making injection impossible.`
    },
    {
      code: `const query = "DELETE FROM posts WHERE user_id = " + parseInt(userId) + " AND category = '" + category + "'";`,
      correct: false,
      explanation: 'parseInt helps with userId but category parameter is still vulnerable to injection.'
    },
    {
      code: `const query = "DELETE FROM posts WHERE user_id = " + userId + " AND category = '" + category.replace(/'/g, "''") + "'";`,
      correct: false,
      explanation: 'Quote escaping is incomplete - other injection techniques like UNION attacks still work.'
    },
    {
      code: `const query = "DELETE FROM posts WHERE user_id = '" + userId + "' AND category = '" + category + "'";`,
      correct: false,
      explanation: 'Adding quotes around numbers doesn\'t help - still concatenating user input directly.'
    },
    {
      code: `const query = \`DELETE FROM posts WHERE user_id = \${userId} AND category = '\${category}'\`;`,
      correct: false,
      explanation: 'Template literals are still string concatenation - equally vulnerable to injection.'
    },
    {
      code: `const query = "DELETE FROM posts WHERE user_id = " + userId + " AND category LIKE '" + category + "%'";`,
      correct: false,
      explanation: 'Using LIKE makes injection easier, not safer - still concatenating user input.'
    },
    {
      code: `const query = "DELETE FROM posts WHERE user_id = " + userId + " AND UPPER(category) = '" + category.toUpperCase() + "'";`,
      correct: false,
      explanation: 'Case conversion doesn\'t prevent injection - still vulnerable to malicious input.'
    },
    {
      code: `const query = "DELETE FROM posts WHERE user_id = " + userId + " AND category = '" + encodeURIComponent(category) + "'";`,
      correct: false,
      explanation: 'URL encoding is for web requests, not SQL. This doesn\'t prevent database injection.'
    },
    {
      code: `const query = "DELETE FROM posts WHERE user_id = " + userId + " AND category = '" + category.substring(0, 50) + "'";`,
      correct: false,
      explanation: 'Length limits don\'t prevent injection - short malicious payloads can be devastating.'
    },
    {
      code: `const query = "DELETE FROM posts WHERE user_id = " + userId + " AND category = '" + category.trim() + "'";`,
      correct: false,
      explanation: 'Trimming whitespace doesn\'t prevent injection - still concatenating dangerous input.'
    }
  ]
}