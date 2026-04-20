import type { Exercise } from '@/data/exercises'

export const cwe89Delete: Exercise = {
  cweId: 'CWE-89',
  name: 'SQL Injection - Data Deletion',
  language: 'JavaScript',
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
      explanation: `Use ? placeholders - database treats input as data, not code`
    },
    {
      code: `const query = "DELETE FROM posts WHERE user_id = " + parseInt(userId) + " AND category = '" + category + "'";`,
      correct: false,
      explanation: 'parseInt helps userId but category still vulnerable'
    },
    {
      code: `const query = "DELETE FROM posts WHERE user_id = " + userId + " AND category = '" + category.replace(/'/g, "''") + "'";`,
      correct: false,
      explanation: 'Quote escaping is incomplete - UNION attacks still work'
    },
    {
      code: `const query = "DELETE FROM posts WHERE user_id = '" + userId + "' AND category = '" + category + "'";`,
      correct: false,
      explanation: 'Adding quotes doesn\'t help - still concatenating input'
    },
    {
      code: `const query = \`DELETE FROM posts WHERE user_id = \${userId} AND category = '\${category}'\`;`,
      correct: false,
      explanation: 'Template literals are still string concatenation - vulnerable'
    },
    {
      code: `const query = "DELETE FROM posts WHERE user_id = " + userId + " AND category LIKE '" + category + "%'";`,
      correct: false,
      explanation: 'LIKE makes injection easier - still concatenating input'
    },
    {
      code: `const query = "DELETE FROM posts WHERE user_id = " + userId + " AND UPPER(category) = '" + category.toUpperCase() + "'";`,
      correct: false,
      explanation: 'Case conversion doesn\'t prevent injection - still vulnerable'
    },
    {
      code: `const query = "DELETE FROM posts WHERE user_id = " + userId + " AND category = '" + encodeURIComponent(category) + "'";`,
      correct: false,
      explanation: 'URL encoding is for HTTP, not SQL protection'
    },
    {
      code: `const query = "DELETE FROM posts WHERE user_id = " + userId + " AND category = '" + category.substring(0, 50) + "'";`,
      correct: false,
      explanation: 'Length limits don\'t prevent injection - short payloads work'
    },
    {
      code: `const query = "DELETE FROM posts WHERE user_id = " + userId + " AND category = '" + category.trim() + "'";`,
      correct: false,
      explanation: 'Trimming whitespace doesn\'t prevent injection - still concatenating input'
    }
  ]
}