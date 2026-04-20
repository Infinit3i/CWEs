import type { CWEExample } from '@/types/cwe'

export const cweExamples: CWEExample[] = [
  {
    id: 'CWE-89',
    name: 'SQL Injection',
    description: 'The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.',
    category: 'Injection',
    vulnerableCode: {
      language: 'javascript',
      code: `function getUserData(userId) {
  const query = "SELECT * FROM users WHERE id = " + userId;
  return database.query(query);
}

// What happens with malicious input:
getUserData("1 OR 1=1--");
// Executes: SELECT * FROM users WHERE id = 1 OR 1=1--
// Returns ALL users instead of just one!`,
      explanation: 'This code is vulnerable because it directly concatenates user input into the SQL query without any validation or sanitization. An attacker can inject malicious SQL code.'
    },
    secureCode: {
      language: 'javascript',
      code: `function getUserData(userId) {
  const query = "SELECT * FROM users WHERE id = ?";
  return database.query(query, [userId]);
}

// Even with malicious input:
getUserData("1 OR 1=1--");
// The database treats the entire string as a literal ID value
// No SQL injection possible!`,
      explanation: 'This secure version uses parameterized queries (prepared statements) where user input is treated as data, not executable code. The database engine handles escaping automatically.'
    },
    keyDifferences: [
      'Replace: "SELECT * FROM users WHERE id = " + userId',
      'With: "SELECT * FROM users WHERE id = ?" and pass [userId] separately',
      'Replace: Direct string concatenation',
      'With: Parameterized queries that treat input as data'
    ],
    remediationSteps: [
      'Replace string concatenation with parameterized queries/prepared statements',
      'Validate and sanitize all user inputs',
      'Use allowlists for acceptable input values where possible',
      'Implement least privilege principles for database access',
      'Consider using an ORM that handles parameterization automatically'
    ],
    severity: 'Critical',
    owasp: ['OWASP Top 10 2021 - A03: Injection']
  }
]