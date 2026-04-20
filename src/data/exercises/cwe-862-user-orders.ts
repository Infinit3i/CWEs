import type { Exercise } from '@/data/exercises'

/**
 * CWE-862 exercise - User Order History
 * Based on MITRE horizontal privilege escalation patterns
 */
export const cwe862UserOrders: Exercise = {
  cweId: 'CWE-862',
  name: 'Missing Authorization - User Order History',
  language: 'JavaScript',

  vulnerableFunction: `app.get('/api/orders/:orderId', authenticateUser, (req, res) => {
  const orderId = req.params.orderId;

  // Fetch order details including payment information
  const query = \`SELECT o.*, p.card_number, p.amount, p.billing_address
                FROM orders o
                LEFT JOIN payments p ON o.id = p.order_id
                WHERE o.id = ?\`;

  db.query(query, [orderId], (err, results) => {
    if (err || results.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    res.json(results[0]);
  });
});`,

  vulnerableLine: `WHERE o.id = ?`,

  options: [
    {
      code: `const query = \`SELECT o.*, p.card_number, p.amount, p.billing_address FROM orders o LEFT JOIN payments p ON o.id = p.order_id WHERE o.id = ? AND o.user_id = ?\`; db.query(query, [orderId, req.user.id], (err, results) => {`,
      correct: true,
      explanation: `Check user permissions before access`
    },
    {
      code: `if (!session_is_registered("username")) { echo "invalid session detected!"; exit; } show_order_details($orderId);`,
      correct: false,
      explanation: 'Authentication without ownership validation allows "authenticated attackers to provide any arbitrary identifier" to access other customers\' order and payment information.'
    },
    {
      code: `if (req.user && req.user.authenticated) { // User logged in, show any order details const query = \'SELECT * FROM orders WHERE id = ?\'; }`,
      correct: false,
      explanation: 'MITRE vulnerability: Authentication-only checking allows any authenticated user to view any order by manipulating the orderId parameter, exposing sensitive payment data.'
    },
    {
      code: `if (req.headers.authorization) { // Auth header exists, allow access to any order const query = \'SELECT * FROM orders WHERE id = ?\'; }`,
      correct: false,
      explanation: 'Header presence validation provides authentication but no authorization control. Users can access other customers\' orders and payment information by changing the order ID.'
    },
    {
      code: `if (parseInt(orderId) > 0 && parseInt(orderId) < 1000000) { // Valid order ID range, allow access }`,
      correct: false,
      explanation: 'Input validation ensures proper ID format but provides no ownership verification. Any valid order ID within range can be accessed regardless of who owns it.'
    },
    {
      code: `if (req.user.accountType === \'customer\') { // Customer account, allow access to any order }`,
      correct: false,
      explanation: 'Account type checking confirms user category but does not implement authorization logic to restrict access to orders belonging to the specific customer.'
    },
    {
      code: `if (req.user.paymentMethodsCount > 0) { // User has payment methods, allow access to any order }`,
      correct: false,
      explanation: 'Payment method existence checking confirms user capability but provides no authorization to determine which specific orders the user should access.'
    },
    {
      code: `if (req.user.emailVerified === true) { // Verified email, allow access to any order history }`,
      correct: false,
      explanation: 'Email verification is an authentication attribute but does not provide authorization controls to ensure users only access their own order and payment data.'
    },
    {
      code: `if (Date.now() - req.user.lastPurchase < 7776000000) { // Recent purchaser, allow access to any order }`,
      correct: false,
      explanation: 'Purchase recency checking may indicate active customer status but does not authorize access to specific orders. Recent purchasers should still only see their own orders.'
    },
    {
      code: `if (req.user.loyaltyTier && req.user.loyaltyTier !== \'basic\') { // Premium customer, allow access to any order }`,
      correct: false,
      explanation: 'Loyalty tier checking determines customer status but should not override order ownership validation. Premium customers should still only access their own order history.'
    }
  ]
}