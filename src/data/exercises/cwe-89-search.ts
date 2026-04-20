import type { Exercise } from '@/data/exercises'

export const cwe89Search: Exercise = {
  cweId: 'CWE-89',
  name: 'SQL Injection - Product Search',
  vulnerableFunction: `function searchProducts(searchTerm, sortBy, filterCategory) {
  const baseQuery = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'";
  const categoryFilter = " AND category = '" + filterCategory + "'";
  const orderBy = " ORDER BY " + sortBy;
  const finalQuery = baseQuery + categoryFilter + orderBy;
  return database.query(finalQuery);
}`,
  vulnerableLine: `const baseQuery = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'";
  const categoryFilter = " AND category = '" + filterCategory + "'";
  const orderBy = " ORDER BY " + sortBy;`,
  options: [
    {
      code: `const baseQuery = "SELECT * FROM products WHERE name LIKE ?";
  const categoryFilter = " AND category = ?";
  const orderBy = " ORDER BY " + allowedSortFields[sortBy];`,
      correct: true,
      explanation: 'Correct! This solution demonstrates a hybrid approach for complex queries with multiple injection vectors. The LIKE and WHERE clauses use parameterized queries with placeholders (?), executed as database.query(finalQuery, ["%"+searchTerm+"%", filterCategory]). This handles the data injection points securely by separating SQL structure from user data. However, ORDER BY column names cannot use parameter placeholders because column names must be part of the SQL structure, not data values. The solution uses allowedSortFields[sortBy] which maps user input to a predefined allowlist of valid column names like {"name": "product_name", "price": "price_usd"}. This prevents injection in ORDER BY clauses because the user can only reference pre-approved columns, and the mapping ensures only safe, validated column names are inserted into the SQL. The concatenation approach "+ userId +" and "+ searchTerm +" is dangerous because it treats all user input as SQL code, allowing injection through LIKE patterns, WHERE conditions, or ORDER BY manipulation.'
    },
    {
      code: `const baseQuery = "SELECT * FROM products WHERE name LIKE '%" + searchTerm.replace(/'/g, "\\'") + "%'";
  const categoryFilter = " AND category = '" + filterCategory.replace(/'/g, "\\'") + "'";
  const orderBy = " ORDER BY " + sortBy.replace(/[^a-zA-Z0-9_]/g, '');`,
      correct: false,
      explanation: 'Quote escaping and character filtering are insufficient - many injection techniques still work.'
    },
    {
      code: `const baseQuery = "SELECT * FROM products WHERE UPPER(name) LIKE '%" + searchTerm.toUpperCase() + "%'";
  const categoryFilter = " AND UPPER(category) = '" + filterCategory.toUpperCase() + "'";
  const orderBy = " ORDER BY " + sortBy;`,
      correct: false,
      explanation: 'Case conversion doesn\'t prevent injection - still concatenating user input into SQL.'
    },
    {
      code: `const baseQuery = "SELECT * FROM products WHERE name LIKE '%" + encodeURIComponent(searchTerm) + "%'";
  const categoryFilter = " AND category = '" + encodeURIComponent(filterCategory) + "'";
  const orderBy = " ORDER BY " + encodeURIComponent(sortBy);`,
      correct: false,
      explanation: 'URL encoding is for HTTP, not SQL databases. This doesn\'t prevent SQL injection.'
    },
    {
      code: `const baseQuery = \`SELECT * FROM products WHERE name LIKE '%\${searchTerm}%'\`;
  const categoryFilter = \` AND category = '\${filterCategory}'\`;
  const orderBy = \` ORDER BY \${sortBy}\`;`,
      correct: false,
      explanation: 'Template literals are still string concatenation - equally vulnerable to injection attacks.'
    },
    {
      code: `const baseQuery = "SELECT * FROM products WHERE name LIKE '%" + searchTerm.substring(0, 50) + "%'";
  const categoryFilter = " AND category = '" + filterCategory.substring(0, 20) + "'";
  const orderBy = " ORDER BY " + sortBy.substring(0, 20);`,
      correct: false,
      explanation: 'Length limits don\'t prevent injection - short malicious payloads can be very effective.'
    },
    {
      code: `const baseQuery = "SELECT * FROM products WHERE name LIKE '%" + JSON.stringify(searchTerm) + "%'";
  const categoryFilter = " AND category = '" + JSON.stringify(filterCategory) + "'";
  const orderBy = " ORDER BY " + JSON.stringify(sortBy);`,
      correct: false,
      explanation: 'JSON.stringify may add quotes but doesn\'t prevent all injection forms, especially in ORDER BY.'
    },
    {
      code: `const baseQuery = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'";
  const categoryFilter = " AND category = '" + filterCategory + "'";
  const orderBy = " ORDER BY " + (sortBy === 'price' ? 'price' : 'name');`,
      correct: false,
      explanation: 'Partial validation for ORDER BY doesn\'t fix the vulnerable LIKE and category parameters.'
    },
    {
      code: `const baseQuery = "SELECT * FROM products WHERE name LIKE '%" + searchTerm.trim() + "%'";
  const categoryFilter = " AND category = '" + filterCategory.trim() + "'";
  const orderBy = " ORDER BY " + sortBy.trim();`,
      correct: false,
      explanation: 'Trimming whitespace doesn\'t prevent injection - still concatenating dangerous user input.'
    },
    {
      code: `const baseQuery = "SELECT * FROM products WHERE name LIKE '%" + searchTerm.replace(/[<>]/g, '') + "%'";
  const categoryFilter = " AND category = '" + filterCategory.replace(/[<>]/g, '') + "'";
  const orderBy = " ORDER BY " + sortBy.replace(/[<>]/g, '');`,
      correct: false,
      explanation: 'Removing HTML characters doesn\'t prevent SQL injection - wrong type of filtering.'
    }
  ]
}