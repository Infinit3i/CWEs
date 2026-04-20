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
      explanation: `Use ? placeholders - database treats input as data, not code`
    },
    {
      code: `const orderQuery = "INSERT INTO orders (customer_id, product_id, quantity) VALUES (" + parseInt(customerId) + ", " + parseInt(productId) + ", " + parseInt(quantity) + ")";
  const notesQuery = "INSERT INTO order_notes (order_id, notes) VALUES (" + orderId + ", '" + notes.replace(/'/g, "\\'") + "')";`,
      correct: false,
      explanation: 'parseInt helps numbers but quote escaping is incomplete'
    },
    {
      code: `const orderQuery = \`INSERT INTO orders (customer_id, product_id, quantity) VALUES (\${customerId}, \${productId}, \${quantity})\`;
  const notesQuery = \`INSERT INTO order_notes (order_id, notes) VALUES (\${orderId}, '\${notes}')\`;`,
      correct: false,
      explanation: 'Template literals are still string concatenation - vulnerable'
    },
    {
      code: `const orderQuery = "INSERT INTO orders (customer_id, product_id, quantity) VALUES ('" + customerId + "', '" + productId + "', '" + quantity + "')";
  const notesQuery = "INSERT INTO order_notes (order_id, notes) VALUES ('" + orderId + "', '" + notes + "')";`,
      correct: false,
      explanation: 'Adding quotes doesn\'t prevent injection - still concatenating input'
    },
    {
      code: `const orderQuery = "INSERT INTO orders (customer_id, product_id, quantity) VALUES (" + customerId + ", " + productId + ", " + quantity + ")";
  const notesQuery = "INSERT INTO order_notes (order_id, notes) VALUES (" + orderId + ", '" + encodeURIComponent(notes) + "')";`,
      correct: false,
      explanation: 'URL encoding is for HTTP, not SQL protection'
    },
    {
      code: `const orderQuery = "INSERT INTO orders (customer_id, product_id, quantity) VALUES (" + customerId + ", " + productId + ", " + quantity + ")";
  const notesQuery = "INSERT INTO order_notes (order_id, notes) VALUES (" + orderId + ", " + JSON.stringify(notes) + ")";`,
      correct: false,
      explanation: 'JSON.stringify doesn\'t prevent all injection forms'
    },
    {
      code: `const orderQuery = "INSERT INTO orders (customer_id, product_id, quantity) VALUES (" + Math.abs(customerId) + ", " + Math.abs(productId) + ", " + Math.abs(quantity) + ")";
  const notesQuery = "INSERT INTO order_notes (order_id, notes) VALUES (" + orderId + ", '" + notes + "')";`,
      correct: false,
      explanation: 'Math.abs doesn\'t prevent injection - notes still vulnerable'
    },
    {
      code: `const orderQuery = "INSERT INTO orders (customer_id, product_id, quantity) VALUES (" + customerId + ", " + productId + ", " + quantity + ")";
  const notesQuery = "INSERT INTO order_notes (order_id, notes) VALUES (" + orderId + ", '" + notes.substring(0, 200) + "')";`,
      correct: false,
      explanation: 'Length limits don\'t prevent injection - short payloads work'
    },
    {
      code: `const orderQuery = "INSERT INTO orders (customer_id, product_id, quantity) VALUES (" + customerId.toString() + ", " + productId.toString() + ", " + quantity.toString() + ")";
  const notesQuery = "INSERT INTO order_notes (order_id, notes) VALUES (" + orderId + ", '" + notes.toLowerCase() + "')";`,
      correct: false,
      explanation: 'toString() and toLowerCase() don\'t sanitize - still vulnerable'
    },
    {
      code: `const orderQuery = "INSERT INTO orders (customer_id, product_id, quantity) VALUES (" + customerId + ", " + productId + ", " + quantity + ")";
  const notesQuery = "INSERT INTO order_notes (order_id, notes) VALUES (" + orderId + ", '" + notes.replace(/[<>]/g, '') + "')";`,
      correct: false,
      explanation: 'Removing HTML chars doesn\'t prevent SQL injection'
    }
  ]
}