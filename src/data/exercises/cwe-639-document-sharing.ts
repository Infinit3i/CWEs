import type { Exercise } from '@/data/exercises'

/**
 * CWE-639: Authorization Bypass Through User-Controlled Key
 * Scenario: Document sharing API with access control bypass
 * Based on MITRE patterns for resource access authorization
 */
export const cwe639DocumentSharing: Exercise = {
  cweId: 'CWE-639',
  name: 'Authorization Bypass - Document Access Control',

  vulnerableFunction: `app.get('/api/documents/:documentId', authenticateUser, async (req, res) => {
  try {
    const documentId = req.params.documentId;

    // Validate document ID is a valid UUID
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(documentId)) {
      return res.status(400).json({ error: 'Invalid document ID format' });
    }

    // Query document metadata and content
    const docQuery = \`
      SELECT d.id, d.title, d.content, d.created_at, d.owner_id,
             u.username as owner_name, d.visibility_level
      FROM documents d
      JOIN users u ON d.owner_id = u.id
      WHERE d.id = ?
    \`;

    const docResult = await db.query(docQuery, [documentId]);

    if (docResult.length === 0) {
      return res.status(404).json({ error: 'Document not found' });
    }

    const document = docResult[0];

    // Check if document is marked as deleted
    if (document.visibility_level === 'deleted') {
      return res.status(404).json({ error: 'Document not found' });
    }

    // Get sharing permissions for this document
    const shareQuery = 'SELECT user_id, permission_level FROM document_shares WHERE document_id = ?';
    const shareResult = await db.query(shareQuery, [documentId]);

    // Return document with sharing info
    res.json({
      document: {
        id: document.id,
        title: document.title,
        content: document.content,
        owner: document.owner_name,
        createdAt: document.created_at,
        sharedWith: shareResult
      }
    });

  } catch (error) {
    res.status(500).json({ error: 'Failed to retrieve document' });
  }
});`,

  vulnerableLine: `const docResult = await db.query(docQuery, [documentId]);`,

  options: [
    {
      code: `const currentUserId = req.user.id;

// First check if user owns the document or has been granted access
const accessQuery = \`
  SELECT d.* FROM documents d
  WHERE d.id = ? AND (
    d.owner_id = ? OR
    d.visibility_level = 'public' OR
    EXISTS (
      SELECT 1 FROM document_shares ds
      WHERE ds.document_id = d.id AND ds.user_id = ?
    )
  )
\`;

const docResult = await db.query(accessQuery, [documentId, currentUserId, currentUserId]);`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `const docResult = await db.query(docQuery, [documentId]);`,
      correct: false,
      explanation: 'Direct from MITRE CWE-639: Missing access control allows users to access any document by guessing or enumerating UUIDs. Despite UUID obscurity, attackers can access confidential documents, trade secrets, or personal information through systematic enumeration or leaked/shared document IDs.'
    },
    {
      code: `const currentTime = new Date().getHours();
if (currentTime < 9 || currentTime > 17) { return res.status(403).json({ error: 'Access denied outside business hours' }); }
const docResult = await db.query(docQuery, [documentId]);`,
      correct: false,
      explanation: 'Time-based access control does not implement document-level authorization. While restricting access to business hours might be a business requirement, this does not verify whether the user has permission to access the specific document.'
    },
    {
      code: `if (documentId.startsWith('admin-')) { return res.status(403).json({ error: 'Admin documents protected' }); }
const docResult = await db.query(docQuery, [documentId]);`,
      correct: false,
      explanation: 'Prefix-based filtering provides minimal protection. While it may block documents with admin prefixes, users can still access any other document by manipulating the UUID parameter, gaining unauthorized access to confidential information.'
    },
    {
      code: `const requestCount = await getRequestCount(req.user.id);
if (requestCount > 100) { return res.status(429).json({ error: 'Too many requests' }); }
const docResult = await db.query(docQuery, [documentId]);`,
      correct: false,
      explanation: 'Rate limiting does not prevent unauthorized document access, only limits the frequency. Users can still access documents they do not own within the rate limit, just at a slower pace.'
    },
    {
      code: `const hashedId = crypto.createHash('sha256').update(documentId + req.user.salt).digest('hex');
const docResult = await db.query('SELECT * FROM documents WHERE SHA256(CONCAT(id, ?)) = ?', [req.user.salt, hashedId]);`,
      correct: false,
      explanation: 'User-specific hashing does not solve the authorization problem. This approach prevents direct UUID access but does not verify legitimate ownership or sharing permissions for the document.'
    },
    {
      code: `const documentAge = Date.now() - Date.parse(document.created_at);
if (documentAge < 86400000) { return res.status(403).json({ error: 'Recent documents protected' }); }
const docResult = await db.query(docQuery, [documentId]);`,
      correct: false,
      explanation: 'Age-based restrictions do not implement proper authorization. This arbitrary rule blocks recent documents but allows access to older documents regardless of ownership or sharing permissions.'
    },
    {
      code: `if (req.user.role !== 'premium') { return res.status(403).json({ error: 'Premium feature' }); }
const docResult = await db.query(docQuery, [documentId]);`,
      correct: false,
      explanation: 'Role-based feature gating does not provide document-level authorization. While this restricts the feature to premium users, any premium user can still access any document by manipulating the document ID.'
    },
    {
      code: `const userTier = await getUserTier(req.user.id);
if (userTier < 3) { return res.status(403).json({ error: 'Insufficient user tier' }); }
const docResult = await db.query(docQuery, [documentId]);`,
      correct: false,
      explanation: 'User tier validation does not implement object-level authorization. While this may be a business requirement, high-tier users can still access any document regardless of ownership or sharing permissions.'
    },
    {
      code: `const encryptedId = encrypt(documentId, process.env.SECRET_KEY);
const decryptedId = decrypt(encryptedId, process.env.SECRET_KEY);
const docResult = await db.query(docQuery, [decryptedId]);`,
      correct: false,
      explanation: 'Encryption/decryption operations do not provide authorization. This encrypts and immediately decrypts the same ID, providing no security benefit while still allowing unauthorized access to any document.'
    }
  ]
}