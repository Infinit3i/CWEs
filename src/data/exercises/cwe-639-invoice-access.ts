import type { Exercise } from '@/data/exercises'

/**
 * CWE-639: Authorization Bypass Through User-Controlled Key
 * Scenario: Invoice viewing API endpoint
 * Based on MITRE demonstrative examples showing insufficient authorization
 */
export const cwe639InvoiceAccess: Exercise = {
  cweId: 'CWE-639',
  name: 'Authorization Bypass - Invoice Access Control',

  vulnerableFunction: `app.get('/api/invoices/:invoiceId', authenticateToken, async (req, res) => {
  try {
    // Extract invoice ID from URL parameter
    const invoiceId = parseInt(req.params.invoiceId);

    if (isNaN(invoiceId) || invoiceId <= 0) {
      return res.status(400).json({ error: 'Invalid invoice ID' });
    }

    // Query invoice from database using parameterized query (prevents SQL injection)
    const query = 'SELECT * FROM invoices WHERE id = ?';
    const result = await db.query(query, [invoiceId]);

    if (result.length === 0) {
      return res.status(404).json({ error: 'Invoice not found' });
    }

    // Return invoice data
    res.json({
      invoice: result[0],
      message: 'Invoice retrieved successfully'
    });

  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});`,

  vulnerableLine: `const result = await db.query(query, [invoiceId]);`,

  options: [
    {
      code: `// Add authorization check before querying
const userId = req.user.id;
const query = 'SELECT * FROM invoices WHERE id = ? AND user_id = ?';
const result = await db.query(query, [invoiceId, userId]);`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `const result = await db.query(query, [invoiceId]);`,
      correct: false,
      explanation: 'Direct from MITRE CWE-639: Missing authorization check allows horizontal privilege escalation. Authenticated users can access any invoice by guessing or enumerating invoice IDs in the URL parameter, gaining access to other users\' financial data.'
    },
    {
      code: `if (invoiceId > 1000) { return res.status(403).json({ error: 'Access denied' }); }
const result = await db.query(query, [invoiceId]);`,
      correct: false,
      explanation: 'ID range validation does not implement proper authorization. This arbitrary limit prevents access to higher-numbered invoices but still allows users to access any invoice with ID ≤ 1000, regardless of ownership.'
    },
    {
      code: `const hashedId = crypto.createHash('md5').update(invoiceId.toString()).digest('hex');
const result = await db.query('SELECT * FROM invoices WHERE MD5(id) = ?', [hashedId]);`,
      correct: false,
      explanation: 'Hashing the ID does not solve the authorization problem. While it obscures the direct invoice ID, users can still access any invoice by providing the correct ID - the fundamental lack of ownership verification remains.'
    },
    {
      code: `const randomCheck = Math.random() > 0.5;
if (randomCheck) { return res.status(403).json({ error: 'Access denied' }); }
const result = await db.query(query, [invoiceId]);`,
      correct: false,
      explanation: 'Random access control is not real authorization. This approach randomly denies some requests but does not verify whether the user actually owns the requested invoice, making it useless for security.'
    },
    {
      code: `await new Promise(resolve => setTimeout(resolve, 100));
const result = await db.query(query, [invoiceId]);`,
      correct: false,
      explanation: 'Adding delays does not implement authorization. While rate limiting might slow down enumeration attacks, users can still access any invoice they can guess the ID for - no ownership verification is performed.'
    },
    {
      code: `const logEntry = \`User \${req.user.id} accessed invoice \${invoiceId}\`;
console.log(logEntry);
const result = await db.query(query, [invoiceId]);`,
      correct: false,
      explanation: 'Logging access does not prevent unauthorized access. While audit trails are valuable for detection, this does not stop users from accessing invoices that belong to other users.'
    },
    {
      code: `if (req.headers['user-agent'].includes('bot')) { return res.status(403).json({ error: 'Bots not allowed' }); }
const result = await db.query(query, [invoiceId]);`,
      correct: false,
      explanation: 'User-agent checking does not implement authorization. This blocks some automated tools but does not verify whether a human user owns the requested invoice, allowing manual unauthorized access.'
    },
    {
      code: `const encrypted = Buffer.from(invoiceId.toString()).toString('base64');
const result = await db.query('SELECT * FROM invoices WHERE BASE64(id) = ?', [encrypted]);`,
      correct: false,
      explanation: 'Base64 encoding does not provide authorization. While it obfuscates the invoice ID format, users can still encode any number and access invoices they do not own.'
    },
    {
      code: `if (invoiceId % 2 === 0) { return res.status(403).json({ error: 'Even IDs not accessible' }); }
const result = await db.query(query, [invoiceId]);`,
      correct: false,
      explanation: 'Arbitrary filtering based on ID parity is not authorization. This only blocks even-numbered invoices but allows access to any odd-numbered invoice regardless of ownership.'
    }
  ]
}