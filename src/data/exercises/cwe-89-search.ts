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
      explanation: 'Use ? for data, allowlist for ORDER BY column names'
    },
    {
      code: `const baseQuery = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'";
  const categoryFilter = " AND category = '" + filterCategory.replace(/'/g, "\\'") + "'";
  const orderBy = " ORDER BY " + sortBy;`,
      correct: false,
      explanation: 'Quote escaping and filtering are incomplete - use parameterized queries'
    },
    {
      code: `const baseQuery = "SELECT * FROM products WHERE name LIKE '%" + searchTerm.toUpperCase() + "%'";
  const categoryFilter = " AND category = '" + filterCategory + "'";
  const orderBy = " ORDER BY " + sortBy;`,
      correct: false,
      explanation: 'Case conversion doesn\'t prevent injection - still concatenating input'
    },
    {
      code: `const baseQuery = "SELECT * FROM products WHERE name LIKE '%" + encodeURIComponent(searchTerm) + "%'";
  const categoryFilter = " AND category = '" + filterCategory + "'";
  const orderBy = " ORDER BY " + sortBy;`,
      correct: false,
      explanation: 'URL encoding is for HTTP, not SQL protection'
    },
    {
      code: `const baseQuery = \`SELECT * FROM products WHERE name LIKE '%\${searchTerm}%'\`;
  const categoryFilter = \` AND category = '\${filterCategory}'\`;
  const orderBy = \` ORDER BY \${sortBy}\`;`,
      correct: false,
      explanation: 'Template literals are still string concatenation - vulnerable'
    },
    {
      code: `const baseQuery = "SELECT * FROM products WHERE name LIKE '%" + searchTerm.substring(0, 50) + "%'";
  const categoryFilter = " AND category = '" + filterCategory + "'";
  const orderBy = " ORDER BY " + sortBy;`,
      correct: false,
      explanation: 'Length limits don\'t prevent injection - short payloads work'
    },
    {
      code: `const baseQuery = "SELECT * FROM products WHERE name LIKE '%" + JSON.stringify(searchTerm) + "%'";
  const categoryFilter = " AND category = '" + filterCategory + "'";
  const orderBy = " ORDER BY " + sortBy;`,
      correct: false,
      explanation: 'JSON.stringify doesn\'t prevent all injection forms'
    },
    {
      code: `const baseQuery = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'";
  const categoryFilter = " AND category = '" + filterCategory + "'";
  const orderBy = " ORDER BY " + (sortBy === 'price' ? 'price' : 'name');`,
      correct: false,
      explanation: 'Partial validation doesn\'t fix LIKE and category vulnerabilities'
    },
    {
      code: `const baseQuery = "SELECT * FROM products WHERE name LIKE '%" + searchTerm.trim() + "%'";
  const categoryFilter = " AND category = '" + filterCategory + "'";
  const orderBy = " ORDER BY " + sortBy;`,
      correct: false,
      explanation: 'Trimming whitespace doesn\'t prevent injection - still concatenating input'
    },
    {
      code: `const baseQuery = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'";
  const categoryFilter = " AND category = '" + filterCategory.replace(/[<>]/g, '') + "'";
  const orderBy = " ORDER BY " + sortBy;`,
      correct: false,
      explanation: 'Removing HTML chars doesn\'t prevent SQL injection'
    }
  ]
}