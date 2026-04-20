import type { Exercise } from '@/data/exercises'

/**
 * CWE-94 Code Injection - Dynamic Query Builder
 * Inspired by MITRE patterns for code generation vulnerabilities
 */
export const cwe94Query: Exercise = {
  cweId: 'CWE-94',
  name: 'Code Injection - Query Builder',

  vulnerableFunction: `function buildDynamicQuery(tableName, filters, orderBy) {
  const queryBuilder = \`
    function query(db) {
      let sql = 'SELECT * FROM \${tableName}';
      if ('\${filters.where}') {
        sql += ' WHERE ' + '\${filters.where}';
      }
      if ('\${orderBy}') {
        sql += ' ORDER BY ' + '\${orderBy}';
      }
      return db.query(sql);
    }
    return query;
  \`;

  return eval('(' + queryBuilder + ')');
}`,

  vulnerableLine: `return eval('(' + queryBuilder + ')');`,

  options: [
    {
      code: `const allowedTables = ['users', 'products', 'orders'];
const allowedColumns = ['id', 'name', 'email', 'created_at'];
if (!allowedTables.includes(tableName)) throw new Error('Invalid table');
if (!allowedColumns.includes(orderBy)) throw new Error('Invalid column');
const whereClause = filters.where ? \` WHERE \${db.escape(filters.where)}\` : '';
const orderClause = orderBy ? \` ORDER BY \${db.escape(orderBy)}\` : '';
return (db) => db.query(\`SELECT * FROM \${tableName}\${whereClause}\${orderClause}\`);`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // Code injection vulnerabilities
    {
      code: `const queryBuilder = \`function query(db) { return db.query('SELECT * FROM \${tableName} WHERE \${filters.where}'); }\`;
return eval('(' + queryBuilder + ')');`,
      correct: false,
      explanation: 'Dynamic code generation with eval() allows injection through any parameter. An attacker can inject filters.where: "1=1\\"); require(\\"child_process\\").exec(\\"rm -rf *\\"); //" to break out and execute system commands.'
    },
    {
      code: `const sanitized = tableName.replace(/[^a-zA-Z0-9_]/g, '');
const queryBuilder = \`function query(db) { return db.query('SELECT * FROM \${sanitized}'); }\`;
return Function(queryBuilder)();`,
      correct: false,
      explanation: 'Character filtering and Function constructor are still vulnerable. If filters.where or orderBy parameters contain JavaScript code, they can be executed when the dynamic function is created.'
    },
    {
      code: `if (tableName.includes('DROP') || tableName.includes('DELETE')) {
  throw new Error('Dangerous keywords blocked');
}
const code = \`(db) => db.query('SELECT * FROM \${tableName}')\`;
return eval(code);`,
      correct: false,
      explanation: 'SQL keyword blacklisting does not prevent JavaScript code injection. Attackers can inject JavaScript commands that do not contain SQL keywords but still execute arbitrary code.'
    },
    {
      code: `const vm = require('vm');
const context = { db: null };
const code = \`function query(db) { return db.query('SELECT * FROM \${tableName}'); }\`;
return vm.runInContext(code, context);`,
      correct: false,
      explanation: 'VM contexts can be escaped and provide limited security. String interpolation with user input can inject JavaScript that breaks out of the sandbox through prototype manipulation or other techniques.'
    },
    {
      code: `const escaped = tableName.replace(/'/g, "\\'").replace(/"/g, '\\"');
const queryBuilder = \`function query(db) { return db.query("SELECT * FROM \${escaped}"); }\`;
return new Function('return ' + queryBuilder)();`,
      correct: false,
      explanation: 'Quote escaping alone is insufficient. JavaScript has many ways to construct malicious code without quotes, such as using template literals, String.fromCharCode(), or accessing constructor properties.'
    },
    {
      code: `if (typeof tableName !== 'string' || tableName.length > 50) {
  throw new Error('Invalid table name');
}
return eval(\`(db) => db.query('SELECT * FROM \${tableName}')\`);`,
      correct: false,
      explanation: 'Type and length validation do not prevent code injection when eval() is used. Short JavaScript payloads can still be very effective for code execution or denial of service.'
    },
    {
      code: `const template = \`SELECT * FROM \${tableName} WHERE \${filters.where}\`;
const queryFunction = new Function('db', 'return db.query(\`' + template + '\`)');
return queryFunction;`,
      correct: false,
      explanation: 'Template literals with user input in Function constructor allow code injection. If filters.where contains \${constructor.constructor("malicious_code")()}, arbitrary code execution is possible.'
    },
    {
      code: `const allowedTables = ['users', 'products'];
if (!allowedTables.includes(tableName)) throw new Error('Invalid table');
const queryCode = \`function(db) { return db.query('SELECT * FROM \${tableName} ORDER BY \${orderBy}'); }\`;
return eval(queryCode);`,
      correct: false,
      explanation: 'Even with table validation, other parameters like orderBy can still be injection vectors. Dynamic code generation with eval() remains vulnerable regardless of partial input validation.'
    },
    {
      code: `const encoded = Buffer.from(tableName).toString('base64');
const decoded = Buffer.from(encoded, 'base64').toString();
const queryBuilder = \`function query(db) { return db.query('SELECT * FROM \${decoded}'); }\`;
return Function('return (' + queryBuilder + ')')();`,
      correct: false,
      explanation: 'Base64 encoding and decoding do not prevent injection - they just transform the data. When the decoded value is used in dynamic code generation, the original injection payload remains intact and executable.'
    }
  ]
}