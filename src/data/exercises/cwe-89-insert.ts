import type { Exercise } from '@/data/exercises'

export const cwe89Insert: Exercise = {
  cweId: 'CWE-89',
  name: 'SQL Injection - Order Creation',
  vulnerableFunction: `function createOrder(customerId, productId, quantity, notes) {
  const orderQuery = "INSERT INTO orders (customer_id, product_id, quantity) VALUES (" + customerId + ", " + productId + ", " + quantity + ")";
  const orderResult = database.query(orderQuery);
  const orderId = orderResult.insertId;

  const notesQuery = "INSERT INTO order_notes (order_id, notes) VALUES (" + orderId + ", '" + notes + "')";
  database.query(notesQuery);
  return { orderId, success: true };
}`,
  vulnerableLine: `const orderQuery = "INSERT INTO orders (customer_id, product_id, quantity) VALUES (" + customerId + ", " + productId + ", " + quantity + ")";
  const notesQuery = "INSERT INTO order_notes (order_id, notes) VALUES (" + orderId + ", '" + notes + "')";`,
  options: [
    {
      code: `const orderQuery = "INSERT INTO orders (customer_id, product_id, quantity) VALUES (?, ?, ?)";
  const notesQuery = "INSERT INTO order_notes (order_id, notes) VALUES (?, ?)";`,
      correct: true,
      explanation: `Correct! This solution uses parameterized queries for both INSERT statements, replacing dangerous string concatenation with secure parameter placeholders. The vulnerable version concatenates values like "+ customerId +" and "+ notes +" directly into the SQL string, which means the database parser treats user input as potential SQL code. With parameterized queries, you execute them as database.query(orderQuery, [customerId, productId, quantity]) and database.query(notesQuery, [orderId, notes]). The database engine handles this by pre-compiling the INSERT command structure, then binding the parameter values through a separate, secure mechanism. This is crucial because even if the notes field contains malicious SQL like "'); DROP TABLE orders; INSERT INTO audit_log VALUES ('hacked", the database treats this entire string as literal text to insert into the notes column. The parameter binding occurs after SQL parsing, so user data cannot influence the command structure or inject additional SQL statements.`
    },
    {
      code: `const orderQuery = "INSERT INTO orders (customer_id, product_id, quantity) VALUES (" + parseInt(customerId) + ", " + parseInt(productId) + ", " + parseInt(quantity) + ")";
  const notesQuery = "INSERT INTO order_notes (order_id, notes) VALUES (" + orderId + ", '" + notes.replace(/'/g, "\\'") + "')";`,
      correct: false,
      explanation: 'parseInt helps with numbers but quote escaping for notes is insufficient protection.'
    },
    {
      code: `const orderQuery = \`INSERT INTO orders (customer_id, product_id, quantity) VALUES (\${customerId}, \${productId}, \${quantity})\`;
  const notesQuery = \`INSERT INTO order_notes (order_id, notes) VALUES (\${orderId}, '\${notes}')\`;`,
      correct: false,
      explanation: 'Template literals are still string concatenation - equally vulnerable to injection attacks.'
    },
    {
      code: `const orderQuery = "INSERT INTO orders (customer_id, product_id, quantity) VALUES ('" + customerId + "', '" + productId + "', '" + quantity + "')";
  const notesQuery = "INSERT INTO order_notes (order_id, notes) VALUES ('" + orderId + "', '" + notes + "')";`,
      correct: false,
      explanation: 'Adding quotes around numbers doesn\'t prevent injection - still concatenating user input.'
    },
    {
      code: `const orderQuery = "INSERT INTO orders (customer_id, product_id, quantity) VALUES (" + customerId + ", " + productId + ", " + quantity + ")";
  const notesQuery = "INSERT INTO order_notes (order_id, notes) VALUES (" + orderId + ", '" + encodeURIComponent(notes) + "')";`,
      correct: false,
      explanation: 'URL encoding is for HTTP, not SQL. The orderQuery is also still vulnerable.'
    },
    {
      code: `const orderQuery = "INSERT INTO orders (customer_id, product_id, quantity) VALUES (" + customerId + ", " + productId + ", " + quantity + ")";
  const notesQuery = "INSERT INTO order_notes (order_id, notes) VALUES (" + orderId + ", " + JSON.stringify(notes) + ")";`,
      correct: false,
      explanation: 'JSON.stringify adds quotes but doesn\'t prevent all injection. OrderQuery remains vulnerable.'
    },
    {
      code: `const orderQuery = "INSERT INTO orders (customer_id, product_id, quantity) VALUES (" + Math.abs(customerId) + ", " + Math.abs(productId) + ", " + Math.abs(quantity) + ")";
  const notesQuery = "INSERT INTO order_notes (order_id, notes) VALUES (" + orderId + ", '" + notes + "')";`,
      correct: false,
      explanation: 'Math.abs doesn\'t prevent injection and notes parameter is still completely vulnerable.'
    },
    {
      code: `const orderQuery = "INSERT INTO orders (customer_id, product_id, quantity) VALUES (" + customerId + ", " + productId + ", " + quantity + ")";
  const notesQuery = "INSERT INTO order_notes (order_id, notes) VALUES (" + orderId + ", '" + notes.substring(0, 200) + "')";`,
      correct: false,
      explanation: 'Length limits don\'t prevent injection. OrderQuery is vulnerable and short payloads can still work.'
    },
    {
      code: `const orderQuery = "INSERT INTO orders (customer_id, product_id, quantity) VALUES (" + customerId.toString() + ", " + productId.toString() + ", " + quantity.toString() + ")";
  const notesQuery = "INSERT INTO order_notes (order_id, notes) VALUES (" + orderId + ", '" + notes.toLowerCase() + "')";`,
      correct: false,
      explanation: 'toString() and toLowerCase() don\'t sanitize input - both queries remain vulnerable.'
    },
    {
      code: `const orderQuery = "INSERT INTO orders (customer_id, product_id, quantity) VALUES (" + customerId + ", " + productId + ", " + quantity + ")";
  const notesQuery = "INSERT INTO order_notes (order_id, notes) VALUES (" + orderId + ", '" + notes.replace(/[<>]/g, '') + "')";`,
      correct: false,
      explanation: 'Removing HTML characters doesn\'t prevent SQL injection - wrong type of filtering for both queries.'
    }
  ]
}